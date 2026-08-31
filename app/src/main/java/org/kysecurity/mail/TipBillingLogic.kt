package org.kysecurity.mail

internal enum class TipPurchaseAction {
    IGNORE,
    PENDING,
    CONSUME,
    ACKNOWLEDGE,
    ACTIVE,
}

internal fun tipPurchaseAction(
    products: List<String>,
    purchased: Boolean,
    pending: Boolean,
    acknowledged: Boolean,
): TipPurchaseAction = when {
    products.none { it == TIP_PRODUCT_ID || it in TIP_SUBSCRIPTION_PRODUCT_IDS } -> TipPurchaseAction.IGNORE
    pending -> TipPurchaseAction.PENDING
    !purchased -> TipPurchaseAction.IGNORE
    TIP_PRODUCT_ID in products -> TipPurchaseAction.CONSUME
    !acknowledged -> TipPurchaseAction.ACKNOWLEDGE
    else -> TipPurchaseAction.ACTIVE
}

internal const val TIP_PRODUCT_ID = "1offtips"
internal val TIP_SUBSCRIPTION_PRODUCT_IDS = setOf("monthlycoffee")

/** The final phase is the price that continues after any trial or introductory phase. */
internal fun recurringTipPrice(pricingPhases: List<String>): String? = pricingPhases.lastOrNull()
