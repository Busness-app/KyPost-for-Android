import java.util.Properties

plugins {
    alias(libs.plugins.android.application)
    id("org.jetbrains.kotlin.plugin.serialization")
    id("com.google.gms.google-services")
    alias(libs.plugins.ksp)
}

/**
 * Signing material, environment first.
 *
 * `keystore.properties` held the production store and key passwords in cleartext in the source
 * tree. `.gitignore` is not a control for that: it stops one specific accident and does nothing
 * about a tarball, an rsync, a backup daemon, a Docker `COPY .`, a build container, or anything
 * else running as the developer's user. The environment is read first so the file can be reduced
 * to non-secret fields (or deleted entirely) without changing how the build is invoked.
 *
 * See keystore.properties.example.
 */
val keystorePropertiesFile = rootProject.file("keystore.properties")
val keystoreProperties = Properties().apply {
    if (keystorePropertiesFile.exists()) {
        keystorePropertiesFile.inputStream().use { load(it) }
    }
}

/**
 * `providers.environmentVariable`, not `System.getenv`. The latter reads the *daemon's* environment,
 * which is fixed when the daemon starts and is not declared as a configuration-cache input — so a
 * warm daemon silently produces an unsigned release from a shell that exported the variables.
 */
fun signingValue(env: String, property: String): String? =
    providers.environmentVariable(env).orNull ?: keystoreProperties[property] as String?

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

    /**
     * Lint findings that matter here fail the build.
     *
     * CI ran `./gradlew ... lint` and then went green over whatever the report said, which makes the
     * task a report generator rather than a check.
     *
     * `warningsAsErrors = true` was the obvious lever and is the wrong one: it produces a
     * 383-entry baseline file, none of it security-relevant (152 `UseKtx`, 35 `Typos`, 31
     * `UnusedResources`), and a suppression file that large is indistinguishable from not running
     * the check. Escalating the specific checks this app's threat model depends on gives the same
     * gate with real signal and no baseline.
     */
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
            // R8 was disabled outright, shipping a security-sensitive binary with every class,
            // method and field name intact and no shrinking. Rules live in proguard-rules.pro.
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
            // `android.util.Log` throws "not mocked" by default, which forces production code that
            // JVM tests exercise to choose between logging and being testable. AppLockManager hit
            // exactly that: it is deliberately Context-free so it can be unit-tested against a fake
            // AppLockState, and it has to report two security-relevant events (an unevaluable PIN
            // verifier, and a credential-key derivation that failed on an otherwise correct unlock).
            //
            // THE COST, STATED PLAINLY: every other android.* call in JVM-tested production code
            // also returns a default instead of working. `android.util.Base64` returns null;
            // `org.json` returns nothing. That is not hypothetical — DeviceEnvelope's KDoc records a
            // suite that passed against a `= null` body because of it.
            //
            // The rule that follows: production code reachable from src/test must not call android.*
            // for anything but logging. Use java.util.Base64 and kotlinx.serialization, as
            // DeviceEnvelope and Sec1Point do. Code that genuinely needs the framework belongs in
            // src/androidTest, which is where AppLockStoreTest and the Keystore suites already live.
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

/**
 * Fails the build when a **release variant** is configured without signing material.
 *
 * Gated on the variant, not on the command line. The previous guard tested
 * `gradle.startParameter.taskNames.any { it.contains("Release") }`, which is a property of how the
 * build was invoked rather than of what it builds, and it was wrong in both directions:
 * `./gradlew :app:assemble` runs `minifyReleaseWithR8` → `packageRelease` → `assembleRelease`
 * without the token "Release" ever appearing in taskNames, so the guard never fired and the build
 * emitted `app-release-unsigned.apk` on a green run; while `--configuration releaseRuntimeClasspath`
 * contains "release" and aborted a read-only dependency query.
 *
 * The comment that guard carried was also wrong about the failure mode: AGP does not fall back to
 * the debug keystore when no signingConfig is assigned — `apksigner verify` on the artifact it
 * produced reports `DOES NOT VERIFY / Missing META-INF/MANIFEST.MF`, i.e. unsigned.
 */
// Exactly the tasks that emit a signable artifact — `packageRelease` (APK) and `signReleaseBundle`
// (AAB). Matching `startsWith("package") && contains("Release")` also caught
// `packageReleaseResources`, which is a resource-merge step in the *compile* chain, so it failed
// release compilation and dependency-metadata generation rather than only artifact production.
tasks.matching { it.name == "packageRelease" || it.name == "signReleaseBundle" }.configureEach {
    // Resolved here, at configuration time, and captured by the action below as a plain Boolean.
    // Referencing `keystorePropertiesFile` from inside doFirst instead makes the action hold a
    // reference to the build script itself, which the configuration cache cannot serialize —
    // every release build then failed a second time with "cannot serialize Gradle script object
    // references" and discarded its cache entry.
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
    implementation(libs.unifiedpush.connector)
    implementation(libs.play.services.code.scanner)
    // QR *generation* for the "My QR Code" screen — play-services-code-scanner above only scans.
    implementation(libs.zxing.core)
    implementation(libs.rich.html.editor)
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
    implementation(libs.androidx.swiperefreshlayout)
    implementation(libs.angus.mail)
    implementation(libs.bouncycastle.bcpg)
    implementation(libs.androidx.room.runtime)
    implementation(libs.androidx.room.ktx)
    // Encryption at rest for kypost_mail.db, which holds every cached message body, the contact
    // book and PGP key material. It was a plain SQLite file: readable by anyone with the device
    // and root, or with an unlocked bootloader, whatever the app lock said. See
    // security/DatabaseKey.kt.
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

