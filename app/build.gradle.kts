import java.util.Properties

plugins {
    alias(libs.plugins.android.application)
    id("org.jetbrains.kotlin.plugin.serialization")
    id("com.google.gms.google-services")
    alias(libs.plugins.ksp)
}

/** Only fail the build on a missing keystore when a release variant is actually being assembled —
 *  a debug build has no business tripping over release signing configuration. */
val isBuildingRelease = gradle.startParameter.taskNames.any { it.contains("Release", ignoreCase = true) }

val keystorePropertiesFile = rootProject.file("keystore.properties")
val keystoreProperties = Properties().apply {
    if (keystorePropertiesFile.exists()) {
        keystorePropertiesFile.inputStream().use { load(it) }
    }
}

android {
    namespace = "com.urlxl.mail"
    compileSdk {
        version = release(36) {
            minorApiLevel = 1
        }
    }

    defaultConfig {
        applicationId = "com.urlxl.mail"
        minSdk = 31
        targetSdk = 36
        versionCode = 1
        versionName = "1.0"

        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
    }

    signingConfigs {
        if (keystorePropertiesFile.exists()) {
            create("release") {
                storeFile = file(keystoreProperties["storeFile"] as String)
                storePassword = keystoreProperties["storePassword"] as String
                keyAlias = keystoreProperties["keyAlias"] as String
                keyPassword = keystoreProperties["keyPassword"] as String
            }
        }
    }

    buildTypes {
        release {
            // R8 was disabled outright, shipping a security-sensitive binary with every class,
            // method and field name intact and no shrinking. Rules live in proguard-rules.pro.
            optimization {
                enable = true
            }
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro",
            )
            if (keystorePropertiesFile.exists()) {
                signingConfig = signingConfigs.getByName("release")
            } else if (isBuildingRelease) {
                // Previously this branch was simply absent, so a missing keystore.properties made
                // the release build fall through to the debug signing key — silently, with a
                // green build. An APK signed with the public debug key must never be produced by
                // accident.
                throw GradleException(
                    "keystore.properties is missing: a release build must not fall back to the debug signing key.",
                )
            }
        }
    }
    buildFeatures {
        buildConfig = true
    }
    testOptions {
        unitTests {
            // `android.util.Log` throws "not mocked" by default, which forces production code that
            // JVM tests exercise to choose between logging and being testable. AppLockManager hit
            // exactly that: it is deliberately Context-free so it can be unit-tested against a fake
            // AppLockState, and it now has to report two security-relevant events (an unevaluable
            // PIN verifier, and a credential-key derivation that failed on an otherwise correct
            // unlock). Silently dropping those is not an acceptable price for a stub's behaviour.
            isReturnDefaultValues = true
        }
    }
    packaging {
        resources {
            excludes += "META-INF/NOTICE.md"
            excludes += "META-INF/LICENSE.md"
        }
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_11
        targetCompatibility = JavaVersion.VERSION_11
    }
    sourceSets {
        // Room's MigrationTestHelper (used by the androidTest MigrationTest) reads exported
        // schema JSON from assets at runtime.
        getByName("androidTest").assets.srcDirs("$projectDir/schemas")
    }

}

configurations.all {
    // androidx.security.crypto (used by SecurePairingStore) and the UnifiedPush connector
    // both pull in Google's tink crypto library — the former via tink-android, the latter
    // via plain tink. Both jars ship identical com.google.crypto.tink.* classes, so having
    // both on the classpath is a duplicate-class build failure, not a real version conflict;
    // excluding the plain jar and keeping tink-android (already required by security.crypto)
    // is the fix the connector's own docs recommend.
    exclude(group = "com.google.crypto.tink", module = "tink")
}

dependencies {
    implementation("androidx.activity:activity-ktx:1.10.1")
    implementation("androidx.lifecycle:lifecycle-runtime-ktx:2.9.4")
    implementation("androidx.lifecycle:lifecycle-viewmodel-ktx:2.9.4")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.10.2")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-play-services:1.10.2")
    implementation("androidx.datastore:datastore-preferences:1.1.7")
    implementation(libs.androidx.security.crypto)
    implementation(libs.androidx.biometric)
    implementation(libs.androidx.work.runtime.ktx)
    implementation(libs.androidx.lifecycle.process)
    implementation("com.squareup.okhttp3:okhttp:5.2.1")
    implementation("org.jetbrains.kotlinx:kotlinx-serialization-json:1.9.0")
    implementation(platform("com.google.firebase:firebase-bom:34.2.0"))
    implementation("com.google.firebase:firebase-messaging")
    implementation("org.unifiedpush.android:connector:3.3.3")
    implementation("com.google.android.gms:play-services-code-scanner:16.1.0")
    // QR *generation* for the "My QR Code" screen — play-services-code-scanner above only scans.
    implementation("com.google.zxing:core:3.5.3")
    implementation("com.github.infomaniak:android-rich-html-editor:1.1.0")
    // Sanitizes sender HTML before it is quoted into the compose editor, which is a JavaScript
    // enabled WebView with a bound @JavascriptInterface. Parser-backed rather than hand-rolled on
    // purpose: an allowlist applied to a real DOM is the only form that survives mXSS and
    // malformed-markup tricks, and it is what the comparable clients (K-9, FairEmail) use.
    implementation(libs.jsoup)

    implementation(libs.androidx.appcompat)
    implementation(libs.androidx.core.ktx)
    implementation(libs.material)
    implementation(libs.androidx.recyclerview)
    implementation(libs.androidx.cardview)
    implementation(libs.angus.mail)
    implementation(libs.bouncycastle.bcpg)
    implementation(libs.androidx.room.runtime)
    implementation(libs.androidx.room.ktx)
    ksp(libs.androidx.room.compiler)

    testImplementation(libs.junit)
    testImplementation(kotlin("test-junit"))
    androidTestImplementation(libs.androidx.espresso.core)
    androidTestImplementation(libs.androidx.junit)
    androidTestImplementation(libs.androidx.room.runtime)
    androidTestImplementation(libs.androidx.room.testing)
}

ksp {
    arg("room.schemaLocation", "$projectDir/schemas")
}