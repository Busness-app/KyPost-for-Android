package org.kysecurity.mail

import android.os.Bundle
import android.widget.Button
import android.widget.TextView
import android.widget.Toast
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
import org.kysecurity.mail.security.LockedActivity

class TipActivity : LockedActivity() {
    private lateinit var tipButton: Button
    private var productDetails: ProductDetails? = null
    private val billingClient by lazy {
        BillingClient.newBuilder(this)
            .setListener(::onPurchasesUpdated)
            .enablePendingPurchases(
                PendingPurchasesParams.newBuilder().enableOneTimeProducts().build(),
            )
            .enableAutoServiceReconnection()
            .build()
    }

    override fun onCreateUnlocked(savedInstanceState: Bundle?) {
        setContentView(R.layout.activity_tip)
        setTitle(R.string.tip_title)
        applyTopInsetWithHeader(this, findViewById(R.id.tipContent))
        tipButton = findViewById(R.id.tipButton)
        tipButton.setOnClickListener { productDetails?.let(::launchBillingFlow) }
        applyTheme()
        connectToBilling()
    }

    override fun onDestroy() {
        if (::tipButton.isInitialized) billingClient.endConnection()
        super.onDestroy()
    }

    private fun applyTheme() {
        applyThemeToActivity(this)
        applyKyPostTopBar(this, getString(R.string.tip_title))
        applyPrimaryButtonTheme(this, tipButton)
        findViewById<TextView>(R.id.tipIntro).setTextColor(
            android.graphics.Color.parseColor(getStoredThemePalette(this).ink),
        )
    }

    private fun connectToBilling() {
        billingClient.startConnection(object : BillingClientStateListener {
            override fun onBillingSetupFinished(result: BillingResult) {
                if (result.responseCode == BillingClient.BillingResponseCode.OK) {
                    queryExistingPurchases()
                    queryTip()
                } else {
                    showUnavailable()
                }
            }

            override fun onBillingServiceDisconnected() = Unit
        })
    }

    private fun queryTip() {
        val product = QueryProductDetailsParams.Product.newBuilder()
            .setProductId(TIP_PRODUCT_ID)
            .setProductType(BillingClient.ProductType.INAPP)
            .build()
        val params = QueryProductDetailsParams.newBuilder().setProductList(listOf(product)).build()
        billingClient.queryProductDetailsAsync(params) { result, detailsResult ->
            if (result.responseCode != BillingClient.BillingResponseCode.OK) {
                showUnavailable()
                return@queryProductDetailsAsync
            }
            val details = detailsResult.productDetailsList.firstOrNull() ?: run {
                showUnavailable()
                return@queryProductDetailsAsync
            }
            val offer = details.oneTimePurchaseOfferDetailsList?.firstOrNull() ?: run {
                showUnavailable()
                return@queryProductDetailsAsync
            }
            productDetails = details
            tipButton.text = getString(R.string.tip_button, offer.formattedPrice)
            tipButton.isEnabled = true
        }
    }

    private fun launchBillingFlow(details: ProductDetails) {
        val offerToken = details.oneTimePurchaseOfferDetailsList?.firstOrNull()?.offerToken ?: return
        val productParams = BillingFlowParams.ProductDetailsParams.newBuilder()
            .setProductDetails(details)
            .setOfferToken(offerToken)
            .build()
        billingClient.launchBillingFlow(
            this,
            BillingFlowParams.newBuilder().setProductDetailsParamsList(listOf(productParams)).build(),
        )
    }

    private fun onPurchasesUpdated(result: BillingResult, purchases: List<Purchase>?) {
        when (result.responseCode) {
            BillingClient.BillingResponseCode.OK -> purchases.orEmpty().forEach(::processPurchase)
            BillingClient.BillingResponseCode.USER_CANCELED -> Unit
            else -> showUnavailable()
        }
    }

    private fun queryExistingPurchases() {
        val params = QueryPurchasesParams.newBuilder()
            .setProductType(BillingClient.ProductType.INAPP)
            .build()
        billingClient.queryPurchasesAsync(params) { result, purchases ->
            if (result.responseCode == BillingClient.BillingResponseCode.OK) {
                purchases.forEach(::processPurchase)
            }
        }
    }

    private fun processPurchase(purchase: Purchase) {
        if (TIP_PRODUCT_ID !in purchase.products) return
        if (purchase.purchaseState == Purchase.PurchaseState.PENDING) {
            Toast.makeText(this, R.string.tip_pending, Toast.LENGTH_SHORT).show()
            return
        }
        if (purchase.purchaseState != Purchase.PurchaseState.PURCHASED) return
        val params = ConsumeParams.newBuilder().setPurchaseToken(purchase.purchaseToken).build()
        billingClient.consumeAsync(params) { result, _ ->
            if (result.responseCode == BillingClient.BillingResponseCode.OK) {
                Toast.makeText(this, R.string.tip_thanks, Toast.LENGTH_LONG).show()
            }
        }
    }

    private fun showUnavailable() {
        tipButton.isEnabled = false
        tipButton.setText(R.string.tip_unavailable)
    }

    companion object {
        internal const val TIP_PRODUCT_ID = "tip"
    }
}
