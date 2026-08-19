plugins {
    alias(libs.plugins.android.application) apply false
    id("org.jetbrains.kotlin.plugin.serialization") version "2.2.20" apply false
    id("com.google.gms.google-services") version "4.4.4" apply false
    alias(libs.plugins.ksp) apply false
}