import java.util.Properties

plugins {
    alias(libs.plugins.android.application)
    id("org.jetbrains.kotlin.plugin.serialization")
    id("com.google.gms.google-services")
    alias(libs.plugins.ksp)
}

// Environment first, so keystore.properties can hold only a path and an alias.
val keystorePropertiesFile = rootProject.file("keystore.properties")
val keystoreProperties = Properties().apply {
    if (keystorePropertiesFile.exists()) {
        keystorePropertiesFile.inputStream().use { load(it) }
    }
}

// providers.environmentVariable, never System.getenv: the latter reads the daemon's stale env.
fun signingValue(env: String, property: String): String? =
    providers.environmentVariable(env).orNull ?: keystoreProperties[property] as String?

val SECRET_PROPERTY_KEYS = listOf("storePassword", "keyPassword")

val keystoreFileHoldsSecrets = SECRET_PROPERTY_KEYS.any {
    !(keystoreProperties[it] as String?).isNullOrBlank()
}

if (keystoreFileHoldsSecrets) {
    logger.warn(
        "\n" +
            "WARNING: keystore.properties holds a signing password in cleartext.\n" +
            "         Move it to KYPOST_STORE_PASSWORD / KYPOST_KEY_PASSWORD and blank the fields.\n" +
            "         Rotate first — anything that has read the working tree has read the password.\n" +
            "         See keystore.properties.example. CI fails on this; see .github/workflows/ci.yml.\n",
    )
}

// A task rather than a configuration-time failure, so a developer mid-migration can still build.
tasks.register("checkSigningSecretsAreNotInTheTree") {
    group = "verification"
    description = "Fails if keystore.properties holds a signing password."
    val holdsSecrets = keystoreFileHoldsSecrets
    val path = keystorePropertiesFile.path
    doLast {
        if (holdsSecrets) {
            throw GradleException(
                "$path holds a signing password in cleartext. Move it to KYPOST_STORE_PASSWORD / " +
                    "KYPOST_KEY_PASSWORD, blank the fields in the file, and rotate the keystore " +
                    "passwords — see keystore.properties.example.",
            )
        }
    }
}

val signingMaterial: Map<String, String>? = run {
    val store = signingValue("KYPOST_KEYSTORE", "storeFile")
    val storePassword = signingValue("KYPOST_STORE_PASSWORD", "storePassword")
    val alias = signingValue("KYPOST_KEY_ALIAS", "keyAlias")
    val keyPassword = signingValue("KYPOST_KEY_PASSWORD", "keyPassword")
    if (store != null && storePassword != null && alias != null && keyPassword != null) {
        mapOf("storeFile" to store, "storePassword" to storePassword, "keyAlias" to alias, "keyPassword" to keyPassword)
    } else {
        null
    }
}

android {
    namespace = "org.kysecurity.mail"
    compileSdk {
        version = release(36) {
            minorApiLevel = 1
        }
    }

    defaultConfig {
        applicationId = "org.kysecurity.mail"
        minSdk = 31
        targetSdk = 36
        versionCode = 8
        versionName = "0.3.2"

        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"

        // FLAG_SECURE is unconditional unless this is overridden, and only the debug type below
        // can override it. See security/SecureWindow.kt for why the escape hatch exists at all.
        buildConfigField("boolean", "ALLOW_SCREENSHOTS", "false")
    }

    signingConfigs {
        signingMaterial?.let { material ->
            create("release") {
                storeFile = file(material.getValue("storeFile"))
                storePassword = material.getValue("storePassword")
                keyAlias = material.getValue("keyAlias")
                keyPassword = material.getValue("keyPassword")
            }
        }
    }

    // Explicit fatal list rather than warningsAsErrors, which would need a 383-entry baseline.
    lint {
        abortOnError = true
        fatal += listOf(
            // Attack surface reachable by other apps on the device.
            "ExportedActivity",
            "ExportedService",
            "ExportedReceiver",
            "ExportedContentProvider",
            "GrantAllUris",
            "UnsafeIntentLaunch",
            // The mail renderer's posture. See EmailDetailActivity's WebView settings.
            "SetJavaScriptEnabled",
            // Transport.
            "TrustAllX509TrustManager",
            "InsecureBaseConfiguration",
            "CustomX509TrustManager",
            "BadHostnameVerifier",
            // At rest.
            "AllowBackup",
            "WorldReadableFiles",
            "WorldWriteableFiles",
            "HardcodedDebugMode",
        )
        disable += listOf(
            // `commit()` over `apply()` is deliberate and load-bearing throughout the security
            // package: an async flush that has not landed when the process dies is an unlimited-
            // guess bypass for the failed-attempt counter. See AppLockStore's KDoc.
            "ApplySharedPref",
        )
    }

    buildTypes {
        debug {
            // Screenshot capture, opt-in per invocation: `./gradlew :app:assembleDebug
            // -PallowScreenshots=true`. Read at configuration time so the value is a plain Boolean
            // by the time the configuration cache serializes this block.
            val allowScreenshots = project.findProperty("allowScreenshots") == "true"
            buildConfigField("boolean", "ALLOW_SCREENSHOTS", allowScreenshots.toString())
        }
        release {
            // Rules live in proguard-rules.pro, and ci.yml asserts that R8 actually renamed most of
            // the app — a keep rule that over-matches does not fail a build, it silently ships an
            // unobfuscated binary on a green run.
            optimization {
                enable = true
            }
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro",
            )
            if (signingMaterial != null) {
                signingConfig = signingConfigs.getByName("release")
            }
            // The missing-signing-material check is NOT here — see the task guard below.
        }
    }

    buildFeatures {
        buildConfig = true
    }
    testOptions {
        unitTests {
            // On so `android.util.Log` does not throw; the cost is that every other android.* call
            // silently returns a default, so src/test-reachable code must avoid them (SourceRulesTest).
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

// Gate on the tasks that emit a signable artifact, never on gradle.startParameter.taskNames.
// `packageRelease` (APK) and `signReleaseBundle` (AAB), matched exactly. A prefix match on
// "package…Release" also catches `packageReleaseResources`, a resource-merge step in the *compile*
// chain, which would fail release compilation rather than only artifact production.
tasks.matching { it.name == "packageRelease" || it.name == "signReleaseBundle" }.configureEach {
    // Resolved at configuration time and captured below as a plain Boolean. Referencing
    // `keystorePropertiesFile` from inside doFirst instead makes the action hold a reference to the
    // build script, which the configuration cache cannot serialize.
    val signingMaterialPresent = signingMaterial != null
    doFirst {
        if (!signingMaterialPresent) {
            throw GradleException(
                "No signing material: a release variant cannot be signed. Set KYPOST_KEYSTORE, " +
                    "KYPOST_STORE_PASSWORD, KYPOST_KEY_ALIAS and KYPOST_KEY_PASSWORD (see " +
                    "keystore.properties.example), or build only the debug variant.",
            )
        }
    }
}


dependencies {
    implementation(libs.androidx.activity.ktx)
    implementation(libs.androidx.lifecycle.runtime.ktx)
    implementation(libs.androidx.lifecycle.viewmodel.ktx)
    implementation(libs.kotlinx.coroutines.android)
    implementation(libs.kotlinx.coroutines.play.services)
    implementation(libs.androidx.datastore.preferences)
    implementation(libs.androidx.security.crypto)
    implementation(libs.androidx.biometric)
    implementation(libs.androidx.work.runtime.ktx)
    implementation(libs.androidx.lifecycle.process)
    implementation(libs.okhttp)
    implementation(libs.kotlinx.serialization.json)
    implementation(platform(libs.firebase.bom))
    implementation(libs.firebase.messaging)
    implementation(libs.unifiedpush.connector) {
        // tink and tink-android both ship com.google.crypto.tink.*; never configurations.all.
        exclude(group = "com.google.crypto.tink", module = "tink")
    }
    implementation(libs.play.services.code.scanner)
    // QR *generation* for the "My QR Code" screen — play-services-code-scanner above only scans.
    implementation(libs.zxing.core)
    implementation(libs.rich.html.editor)
    // Sanitizes sender HTML before it is quoted into the JavaScript-enabled compose WebView.
    implementation(libs.jsoup)

    implementation(libs.androidx.appcompat)
    implementation(libs.androidx.core.ktx)
    implementation(libs.material)
    implementation(libs.androidx.recyclerview)
    implementation(libs.androidx.cardview)
    implementation(libs.androidx.swiperefreshlayout)
    implementation(libs.angus.mail)
    implementation(libs.bouncycastle.bcpg)
    implementation(libs.androidx.room.runtime)
    implementation(libs.androidx.room.ktx)
    // Encryption at rest for kypost_mail.db: message bodies, contacts and PGP key material.
    implementation(libs.sqlcipher.android)
    ksp(libs.androidx.room.compiler)
    implementation(libs.androidx.window)
    implementation(libs.androidx.startup.runtime)

    testImplementation(libs.junit)
    testImplementation(kotlin("test-junit"))
    androidTestImplementation(libs.androidx.espresso.core)
    androidTestImplementation(libs.androidx.junit)
    androidTestImplementation(libs.androidx.test.core)
    androidTestImplementation(libs.androidx.room.runtime)
    androidTestImplementation(libs.androidx.room.testing)
    // Test-only, and the same shape as room-testing above. Without it a WorkManager test would have
    // to enqueue against the real scheduler, which would actually run the worker — a real network
    // call carrying this device's credential, from a test.
    androidTestImplementation(libs.androidx.work.testing)
}

ksp {
    arg("room.schemaLocation", "$projectDir/schemas")
}

