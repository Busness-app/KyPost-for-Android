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
 * The environment wins so that `keystore.properties` can hold only non-secret fields — a path and
 * an alias — without changing how the build is invoked. `.gitignore` does not make a password in
 * the working tree safe: it stops one specific accident and does nothing about a tarball, an
 * rsync, a backup daemon, a Docker `COPY .`, or anything else running as the developer's user.
 *
 * `checkSigningSecretsAreNotInTheTree` below is what enforces it. See keystore.properties.example.
 */
val keystorePropertiesFile = rootProject.file("keystore.properties")
val keystoreProperties = Properties().apply {
    if (keystorePropertiesFile.exists()) {
        keystorePropertiesFile.inputStream().use { load(it) }
    }
}

/**
 * `providers.environmentVariable`, **never** `System.getenv`. The latter reads the *daemon's*
 * environment, which is fixed when the daemon starts and is not a declared configuration-cache
 * input, so a warm daemon silently produces an unsigned release from a shell that exported the
 * variables.
 */
fun signingValue(env: String, property: String): String? =
    providers.environmentVariable(env).orNull ?: keystoreProperties[property] as String?

/**
 * The two `keystore.properties` fields that must never hold a value.
 *
 * `storeFile` and `keyAlias` are paths and names, not secrets, and keeping them in the file is the
 * point of reading the environment first. These two are passwords.
 */
val SECRET_PROPERTY_KEYS = listOf("storePassword", "keyPassword")

/**
 * Whether the file currently holds a password.
 *
 * The environment-first read above was added so this file could be reduced to non-secret fields —
 * and then nothing checked whether it had been, so it sat there with the production store and key
 * passwords in it while the comment above explained at length why that was unacceptable. A
 * mitigation nobody is told they have not adopted is a mitigation nobody adopts.
 */
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

/**
 * Fails the build when the file holds a password, on demand rather than always.
 *
 * A task, not a hard failure at configuration time: a developer mid-migration must still be able to
 * build, and turning "you have not migrated yet" into "you cannot build" would get the check
 * deleted rather than the password moved. CI runs this task, so the repo cannot regress; locally it
 * is the warning above.
 */
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

    /**
     * Lint findings that matter here fail the build.
     *
     * An explicit `fatal` list rather than `warningsAsErrors = true`. That lever needs a 383-entry
     * baseline file to be usable here, none of it security-relevant, and a suppression file that
     * large is indistinguishable from not running the check. Escalating the specific checks this
     * app's threat model depends on gives the same gate with real signal and no baseline.
     *
     * Add to this list when a new check guards something in `SECURITY.md`; do not add a baseline.
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
            // OFF, so an unmocked android.* call throws instead of quietly returning a default.
            //
            // It was on, for one reason: `android.util.Log` otherwise throws "not mocked", which
            // would force Context-free production code (AppLockManager, DeviceEnvelope,
            // EnrollmentCeremony) to choose between recording a security-relevant event and being
            // unit-testable. The price was paid by every OTHER android.* call in JVM-tested code,
            // silently — `android.util.Base64` returned null, `org.json` returned nothing — so a
            // suite could go green over a body that did nothing. That is not hypothetical:
            // DeviceEnvelope's KDoc records its tests passing vacuously, with `= null` as the whole
            // function body leaving the suite green.
            //
            // src/test/java/android/util/Log.java buys the logging back on its own. It shadows the
            // stub with a real implementation, so the one API this flag existed for keeps working
            // while everything else now fails loudly. Flipping it cost ten test failures, all of
            // them that same Log class and none of them anything else — which is the measurement
            // that says the rule below was already being followed.
            //
            // THE RULE, now enforced by the runtime rather than by convention: production code
            // reachable from src/test must not call android.* for anything but logging. Use
            // java.util.Base64 and kotlinx.serialization, as DeviceEnvelope and Sec1Point do. Code
            // that genuinely needs the framework belongs in src/androidTest. `SourceRulesTest`
            // keeps the two historically silent APIs named explicitly.
            isReturnDefaultValues = false
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
 * Gate on the *tasks that emit a signable artifact*, never on `gradle.startParameter.taskNames`.
 * Task names describe how the build was invoked rather than what it builds, and they are wrong in
 * both directions: `./gradlew :app:assemble` reaches `packageRelease` without the token "Release"
 * ever appearing, while `--configuration releaseRuntimeClasspath` contains "release" and is a
 * read-only query that must not abort.
 *
 * Without a signingConfig AGP does not fall back to the debug keystore — it emits an artifact that
 * `apksigner verify` rejects outright, so nothing downstream catches this for us.
 */
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
        // androidx.security.crypto and this connector both pull in Google's tink — the former via
        // tink-android, the latter via plain tink. Both jars ship the same com.google.crypto.tink.*
        // classes, so both on the classpath is a duplicate-class build failure. Keeping
        // tink-android is what the connector's own docs recommend.
        //
        // **Scoped to this dependency, never `configurations.all`.** A global exclusion of a crypto
        // artifact means a future version where the two jars stop being interchangeable surfaces as
        // NoClassDefFoundError in the push path at runtime, on a subset of devices, after a routine
        // bump — instead of a resolution failure at build time. The global form was also, silently,
        // excluding tink from AGP's own instrumented-test runner, whose seven artifacts are now
        // recorded in gradle/verification-metadata.xml rather than hidden.
        exclude(group = "com.google.crypto.tink", module = "tink")
    }
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

