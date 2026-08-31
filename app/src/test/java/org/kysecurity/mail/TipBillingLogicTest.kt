package org.kysecurity.mail

import org.junit.Test
import kotlin.test.assertEquals

class TipBillingLogicTest {
    @Test fun oneTimeTipsAreConsumed() = assertEquals(
        TipPurchaseAction.CONSUME,
        tipPurchaseAction(listOf(TIP_PRODUCT_ID), purchased = true, pending = false, acknowledged = false),
    )

    @Test fun subscriptionsAreAcknowledgedButNeverConsumed() = assertEquals(
        TipPurchaseAction.ACKNOWLEDGE,
        tipPurchaseAction(
            TIP_SUBSCRIPTION_PRODUCT_IDS.toList(),
            purchased = true,
            pending = false,
            acknowledged = false,
        ),
    )

    @Test fun acknowledgedSubscriptionIsActive() = assertEquals(
        TipPurchaseAction.ACTIVE,
        tipPurchaseAction(
            TIP_SUBSCRIPTION_PRODUCT_IDS.toList(),
            purchased = true,
            pending = false,
            acknowledged = true,
        ),
    )

    @Test fun pendingAndUnrelatedPurchasesStayDistinct() {
        assertEquals(
            TipPurchaseAction.PENDING,
            tipPurchaseAction(listOf(TIP_PRODUCT_ID), purchased = false, pending = true, acknowledged = false),
        )
        assertEquals(
            TipPurchaseAction.IGNORE,
            tipPurchaseAction(listOf("something-else"), purchased = true, pending = false, acknowledged = false),
        )
    }

    @Test fun recurringPriceComesAfterAnyIntroductoryPhase() {
        assertEquals("\$5.00", recurringTipPrice(listOf("Free", "\$2.00", "\$5.00")))
    }
}
