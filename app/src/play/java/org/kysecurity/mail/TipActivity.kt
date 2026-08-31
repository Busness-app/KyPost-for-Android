package org.kysecurity.mail

import android.content.Intent
import android.graphics.Color
import android.net.Uri
import android.os.Bundle
import android.view.Gravity
import android.view.View
import android.widget.Button
import android.widget.LinearLayout
import android.widget.TextView
import android.widget.Toast
import com.android.billingclient.api.AcknowledgePurchaseParams
import com.android.billingclient.api.BillingClient
import com.android.billingclient.api.BillingClientStateListener
import com.android.billingclient.api.BillingFlowParams
import com.android.billingclient.api.BillingResult
import com.android.billingclient.api.ConsumeParams
import com.android.billingclient.api.PendingPurchasesParams
import com.android.billingclient.api.ProductDetails
import com.android.billingclient.api.Purchase
import com.android.billingclient.api.QueryProductDetailsParams
import com.android.billingclient.api.QueryPurchasesParams
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicBoolean
import org.kysecurity.mail.security.LockedActivity

class TipActivity : LockedActivity() {
    private lateinit var buttonsContainer: LinearLayout
    private lateinit var loadingText: TextView
    @Volatile private var subscriptionActive = false
    @Volatile private var subscriptionPending = false
    @Volatile private var oneTimeTipPending = false

    private val billingClient by lazy {
        BillingClient.newBuilder(this)
            .setListener(::onPurchasesUpdated)
            .enablePendingPurchases(PendingPurchasesParams.newBuilder().enableOneTimeProducts().build())
            .enableAutoServiceReconnection()
            .build()
    }

    override fun onCreateUnlocked(savedInstanceState: Bundle?) {
        setContentView(R.layout.activity_tip)
        setTitle(R.string.tip_title)
        applyTopInsetWithHeader(this, findViewById(R.id.tipContent))
        buttonsContainer = findViewById(R.id.tipButtons)
        loadingText = findViewById(R.id.tipLoading)
        applyTheme()
        connectToBilling()
    }

    override fun onDestroy() {
        if (::buttonsContainer.isInitialized) billingClient.endConnection()
        super.onDestroy()
    }

    private fun applyTheme() {
        applyThemeToActivity(this)
        applyKyPostTopBar(this, getString(R.string.tip_title))
        val ink = Color.parseColor(getStoredThemePalette(this).ink)
        findViewById<TextView>(R.id.tipIntro).setTextColor(ink)
        loadingText.setTextColor(ink)
        applySectionEyebrowLabel(this, findViewById(R.id.tipOptionsLabel))
    }

    private fun connectToBilling() {
        billingClient.startConnection(object : BillingClientStateListener {
            override fun onBillingSetupFinished(result: BillingResult) {
                if (result.responseCode == BillingClient.BillingResponseCode.OK) {
                    queryExistingPurchases(::queryProducts)
                } else {
                    showUnavailable()
                }
            }

            override fun onBillingServiceDisconnected() = Unit
        })
    }

    private fun queryExistingPurchases(onComplete: () -> Unit) {
        val finished = AtomicInteger(0)
        val failed = AtomicBoolean(false)
        listOf(BillingClient.ProductType.INAPP, BillingClient.ProductType.SUBS).forEach { type ->
            val params = QueryPurchasesParams.newBuilder().setProductType(type).build()
            billingClient.queryPurchasesAsync(params) { result, purchases ->
                if (result.responseCode == BillingClient.BillingResponseCode.OK) {
                    purchases.forEach(::processPurchase)
                } else {
                    failed.set(true)
                }
                if (finished.incrementAndGet() == 2) {
                    if (failed.get()) showUnavailable() else onComplete()
                }
            }
        }
    }

    private fun queryProducts() {
        val inAppParams = productQuery(listOf(TIP_PRODUCT_ID), BillingClient.ProductType.INAPP)
        val subParams = productQuery(TIP_SUBSCRIPTION_PRODUCT_IDS.toList(), BillingClient.ProductType.SUBS)
        var inAppDetails: List<ProductDetails> = emptyList()
        var subDetails: List<ProductDetails> = emptyList()
        val finished = AtomicInteger(0)

        fun renderIfDone() {
            if (finished.incrementAndGet() == 2) renderProducts(inAppDetails, subDetails)
        }
        billingClient.queryProductDetailsAsync(inAppParams) { result, details ->
            if (result.responseCode == BillingClient.BillingResponseCode.OK) inAppDetails = details.productDetailsList
            renderIfDone()
        }
        billingClient.queryProductDetailsAsync(subParams) { result, details ->
            if (result.responseCode == BillingClient.BillingResponseCode.OK) subDetails = details.productDetailsList
            renderIfDone()
        }
    }

    private fun productQuery(productIds: List<String>, productType: String): QueryProductDetailsParams =
        QueryProductDetailsParams.newBuilder()
            .setProductList(
                productIds.map { id ->
                    QueryProductDetailsParams.Product.newBuilder()
                        .setProductId(id)
                        .setProductType(productType)
                        .build()
                },
            )
            .build()

    private fun renderProducts(inApp: List<ProductDetails>, subscriptions: List<ProductDetails>) {
        runOnUiThread {
            if (!screenIsAlive()) return@runOnUiThread
            loadingText.visibility = View.GONE
            buttonsContainer.removeAllViews()
            if (!oneTimeTipPending) inApp.forEach(::addOneTimeTipButton)
            if (oneTimeTipPending || subscriptionPending) addStatusText(R.string.tip_pending)
            if (subscriptionActive) {
                addStatusText(R.string.tip_subscription_active)
                addManageSubscriptionButton()
            } else if (!subscriptionPending) {
                subscriptions.forEach(::addSubscriptionButtons)
            }
            if (buttonsContainer.childCount == 0) showUnavailable()
        }
    }

    private fun addOneTimeTipButton(details: ProductDetails) {
        val offer = details.oneTimePurchaseOfferDetailsList?.firstOrNull() ?: return
        val offerToken = offer.offerToken ?: return
        createAndAddButton(details, offerToken, getString(R.string.tip_button, offer.formattedPrice))
    }

    private fun addSubscriptionButtons(details: ProductDetails) {
        details.subscriptionOfferDetails.orEmpty().forEach { offer ->
            val recurringPrice = recurringTipPrice(
                offer.pricingPhases.pricingPhaseList.map { it.formattedPrice },
            ) ?: return@forEach
            val planName = when (offer.basePlanId) {
                "take5" -> getString(R.string.tip_plan_take_five)
                "nonetherichar" -> getString(R.string.tip_plan_none_the_richer)
                else -> details.name
            }
            createAndAddButton(
                details,
                offer.offerToken,
                "$planName ${getString(R.string.tip_button_monthly, recurringPrice)}",
            )
        }
    }

    private fun createAndAddButton(details: ProductDetails, offerToken: String, label: String) {
        val button = Button(this).apply {
            text = label
            setOnClickListener { launchBillingFlow(details, offerToken) }
        }
        applyPrimaryButtonTheme(this, button)
        buttonsContainer.addViewSpaced(button, bottomDp = 12)
    }

    private fun launchBillingFlow(details: ProductDetails, offerToken: String) {
        val product = BillingFlowParams.ProductDetailsParams.newBuilder()
            .setProductDetails(details)
            .setOfferToken(offerToken)
            .build()
        val result = billingClient.launchBillingFlow(
            this,
            BillingFlowParams.newBuilder().setProductDetailsParamsList(listOf(product)).build(),
        )
        if (result.responseCode != BillingClient.BillingResponseCode.OK &&
            result.responseCode != BillingClient.BillingResponseCode.USER_CANCELED
        ) showToast(R.string.tip_unavailable, Toast.LENGTH_LONG)
    }

    private fun onPurchasesUpdated(result: BillingResult, purchases: List<Purchase>?) {
        when (result.responseCode) {
            BillingClient.BillingResponseCode.OK -> {
                val updated = purchases.orEmpty()
                updated.forEach(::processPurchase)
                if (updated.any { purchase -> purchase.products.any { it in TIP_SUBSCRIPTION_PRODUCT_IDS } }) {
                    queryProducts()
                }
            }
            BillingClient.BillingResponseCode.USER_CANCELED -> Unit
            else -> showToast(R.string.tip_unavailable, Toast.LENGTH_LONG)
        }
    }

    private fun processPurchase(purchase: Purchase) {
        when (
            tipPurchaseAction(
                products = purchase.products,
                purchased = purchase.purchaseState == Purchase.PurchaseState.PURCHASED,
                pending = purchase.purchaseState == Purchase.PurchaseState.PENDING,
                acknowledged = purchase.isAcknowledged,
            )
        ) {
            TipPurchaseAction.IGNORE -> Unit
            TipPurchaseAction.PENDING -> {
                oneTimeTipPending = TIP_PRODUCT_ID in purchase.products
                subscriptionPending = purchase.products.any { it in TIP_SUBSCRIPTION_PRODUCT_IDS }
                showToast(R.string.tip_pending, Toast.LENGTH_SHORT)
            }
            TipPurchaseAction.CONSUME -> consume(purchase.purchaseToken)
            TipPurchaseAction.ACKNOWLEDGE -> {
                subscriptionActive = true
                acknowledge(purchase.purchaseToken)
            }
            TipPurchaseAction.ACTIVE -> subscriptionActive = true
        }
    }

    private fun consume(token: String) {
        billingClient.consumeAsync(ConsumeParams.newBuilder().setPurchaseToken(token).build()) { result, _ ->
            if (result.responseCode == BillingClient.BillingResponseCode.OK) {
                showToast(R.string.tip_thanks, Toast.LENGTH_LONG)
            }
        }
    }

    private fun acknowledge(token: String) {
        val params = AcknowledgePurchaseParams.newBuilder().setPurchaseToken(token).build()
        billingClient.acknowledgePurchase(params) { result ->
            if (result.responseCode == BillingClient.BillingResponseCode.OK) {
                showToast(R.string.tip_thanks, Toast.LENGTH_LONG)
            }
        }
    }

    private fun addStatusText(textRes: Int) {
        buttonsContainer.addView(TextView(this).apply {
            setText(textRes)
            gravity = Gravity.CENTER
            setTextColor(Color.parseColor(getStoredThemePalette(this@TipActivity).ink))
        })
    }

    private fun addManageSubscriptionButton() {
        val button = Button(this).apply {
            setText(R.string.tip_subscription_manage)
            setOnClickListener {
                val url = Uri.parse("https://play.google.com/store/account/subscriptions").buildUpon()
                    .appendQueryParameter("sku", TIP_SUBSCRIPTION_PRODUCT_IDS.first())
                    .appendQueryParameter("package", packageName)
                    .build()
                runCatching { startActivity(Intent(Intent.ACTION_VIEW, url)) }
                    .onFailure { showToast(R.string.tip_unavailable, Toast.LENGTH_LONG) }
            }
        }
        applyGhostButtonTheme(this, button)
        buttonsContainer.addViewSpaced(button, topDp = 12)
    }

    private fun showUnavailable() = runOnUiThread {
        if (!screenIsAlive()) return@runOnUiThread
        loadingText.visibility = View.GONE
        buttonsContainer.removeAllViews()
        addStatusText(R.string.tip_unavailable)
    }

    private fun showToast(message: Int, length: Int) = runOnUiThread {
        if (screenIsAlive()) Toast.makeText(this, message, length).show()
    }

    private fun screenIsAlive(): Boolean = !isFinishing && !isDestroyed && ::buttonsContainer.isInitialized
}
