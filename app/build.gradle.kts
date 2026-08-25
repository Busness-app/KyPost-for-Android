import com.android.build.api.artifact.SingleArtifact
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
    providers.environmentVariable(env).orNull
        ?: providers.gradleProperty(env).orNull
        ?: providers.gradleProperty(property).orNull
        ?: keystoreProperties[property] as String?

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
        versionCode = 10
        versionName = "0.3.3"

        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"

        // FLAG_SECURE is unconditional unless this is overridden, and only the debug type below
        // can override it. See security/SecureWindow.kt for why the escape hatch exists at all.
        buildConfigField("boolean", "ALLOW_SCREENSHOTS", "false")

        // res/xml cannot read ${applicationId} the way the manifest can, so the account type is
        // injected as a string resource instead. It MUST track applicationId: AccountManager keys
        // account types globally across the device and binds each to a signing key, so two flavors
        // claiming one type means only the first-installed one has a working authenticator.
        // DeviceContactAccount derives the same value from BuildConfig; DeviceContactAccountTest
        // and AccountTypeMatchesManifestTest pin the two halves together.
        resValue("string", "contact_account_type", "org.kysecurity.mail.contacts")

        // The sideloaded APK carries arm only. x86/x86_64 are ~10 MB of libsqlcipher.so that
        // serve emulators and a handful of Chromebooks, not phones. Deliberately a flag rather
        // than an unconditional filter: bundleRelease must run WITHOUT it so the Play bundle
        // keeps every ABI and Chromebooks still get served. See .github/workflows/release.yml.
        if (providers.gradleProperty("kypostArmOnlyApk").isPresent) {
            ndk {
                abiFilters.clear()
                abiFilters += listOf("armeabi-v7a", "arm64-v8a")
            }
        }
    }

    // Android identifies an app by applicationId AND signature, and the three channels sign with
    // three different keys: Play re-signs under Play App Signing, the GitHub APK carries the upload
    // key, F-Droid signs with its own. One applicationId across all three means a user who
    // installed from one cannot update from another without uninstalling, which destroys local
    // data. Distinct ids dissolve that: each is a separate app, and they install side by side.
    flavorDimensions += "channel"
    productFlavors {
        // FIRST on purpose: AGP builds the default variant from the first flavor, and `./gradlew
        // lint` analyses only the default variant. play must be the one that gets analysed.
        create("play") {
            dimension = "channel"
            // No suffix. This id is in the closed test; changing it breaks every tester's update.
            resValue("string", "contact_account_type", "org.kysecurity.mail.contacts")
        }
        create("github") {
            dimension = "channel"
            applicationIdSuffix = ".github"
            resValue("string", "contact_account_type", "org.kysecurity.mail.github.contacts")
        }
        create("fdroid") {
            dimension = "channel"
            applicationIdSuffix = ".fdroid"
            resValue("string", "contact_account_type", "org.kysecurity.mail.fdroid.contacts")
        }
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
            // A fatal entry naming a check lint cannot resolve is a warning about itself, not a
            // gate. "ExportedActivity" sat in this list and was one; this is what would have said so.
            "UnknownIssueId",
            // Attack surface reachable by other apps on the device. Exported *activities* have no
            // lint check at all — see checkExportedComponents below, which gates them.
            "ExportedService",
            "ExportedReceiver",
            "ExportedContentProvider",
            "ExportedPreferenceActivity",
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
            // Form semantics, at zero as of this list. Fatal because the pile they were in is how
            // an email client ends up shipping controls TalkBack cannot name: 62 of these sat as
            // warnings under 156 KTX suggestions, which is the same as not reporting them.
            "Autofill",
            "ContentDescription",
            "HardcodedText",
            "LabelFor",
            "SetTextI18n",
            "TextFields",
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
        // Required for the resValue("string", "contact_account_type", …) call above.
        resValues = true
    }
    testOptions {
        unitTests {
            // OFF: unmocked android.* throws. src/test/java/android/util/Log.java restores logging.
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

// Gate on the tasks that emit a signable artifact, never on gradle.startParameter.taskNames.
// `packageRelease` (APK) and `signReleaseBundle` (AAB), matched exactly. A prefix match on
// "package…Release" also catches `packageReleaseResources`, a resource-merge step in the *compile*
// chain, which would fail release compilation rather than only artifact production.
tasks.matching { it.name == "packageRelease" || it.name == "signReleaseBundle" }.configureEach {
    // The secrets check runs HERE, not only in CI. On a developer machine keystore.properties is
    // gitignored, so no CI job can see it — which made "CI fails on this" true and useless: a
    // password could sit in the working tree indefinitely behind nothing but a build warning.
    // Gated on release packaging rather than preBuild so the debug loop is unaffected and the
    // refusal lands at the moment the password is actually about to be used.
    dependsOn("checkSigningSecretsAreNotInTheTree")
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

/** Every component the merged manifest is allowed to export, and why. Lint has no check for an
 *  exported activity, and no lint check reads the *merged* manifest at all — where a dependency
 *  bump can add an exported component this project's own manifest never mentions. */
val allowedExportedComponents = setOf(
    // The launcher.
    "org.kysecurity.mail.MainActivity",
    // The kypost://native-pair forwarder; deliberately thin. See PushPairingLinkActivity.
    "org.kysecurity.mail.push.PushPairingLinkActivity",
    // Third-party, and reachable only by a caller holding the platform permission each declares.
    "androidx.work.impl.background.systemjob.SystemJobService",
    "androidx.work.impl.diagnostics.DiagnosticsReceiver",
    "androidx.profileinstaller.ProfileInstallReceiver",
    "com.google.firebase.iid.FirebaseInstanceIdReceiver",
    // UnifiedPush's distributor-facing surface: the route a distributor delivers a push through.
    "org.unifiedpush.android.connector.internal.MessagingReceiverImpl",
    "org.unifiedpush.android.connector.internal.RaiseToForegroundService",
)

/** Classes this app identifies by NAME at runtime, where R8 renaming one is silent: the comparison
 *  still compiles, still runs, and simply never matches again.
 *
 *  `EncryptedPrefs.isProtobufParseFailure` is the reason this gate exists. It decides whether an
 *  unreadable encrypted store is repaired or the app refuses to open it, by comparing
 *  `javaClass.simpleName` against a literal. Obfuscated, the literal could not match, so only the
 *  debug build could ever heal a store — and its unit test could not see that, because the test
 *  declares a stand-in class of its own with the same name. */
val runtimeMatchedClassNames = setOf(
    "com.google.crypto.tink.shaded.protobuf.InvalidProtocolBufferException",
    // Named as strings in jakarta.mail's META-INF/mailcap and loaded by MailcapCommandMap, so no
    // bytecode references them and R8 deleted all five. Without them jakarta.activation falls back
    // to DataSourceDataContentHandler, whose getContent() answers an InputStream rather than a
    // String or a MimeMultipart — so PgpMimeReader found neither an html nor a plain part and
    // every decrypted message in a release build ended as "could not be read once decrypted".
    // MimeContentHandlersTest keeps this list level with what mailcap actually declares.
    "org.eclipse.angus.mail.handlers.text_plain",
    "org.eclipse.angus.mail.handlers.text_html",
    "org.eclipse.angus.mail.handlers.text_xml",
    "org.eclipse.angus.mail.handlers.multipart_mixed",
    "org.eclipse.angus.mail.handlers.message_rfc822",
)

androidComponents.onVariants { variant ->
    val mergedManifest = variant.artifacts.get(SingleArtifact.MERGED_MANIFEST)
    val allowed = allowedExportedComponents
    val gate = tasks.register("checkExportedComponents${variant.name.replaceFirstChar { it.uppercase() }}") {
        description = "Fails if the merged manifest exports a component outside the allowlist."
        inputs.file(mergedManifest).withPropertyName("mergedManifest")
        // No project references inside: this action has to survive configuration-cache serialization.
        doLast {
            val android = "http://schemas.android.com/apk/res/android"
            val root = javax.xml.parsers.DocumentBuilderFactory.newInstance()
                .apply { isNamespaceAware = true }
                .newDocumentBuilder()
                .parse(mergedManifest.get().asFile)
                .documentElement
            val exported = listOf("activity", "activity-alias", "service", "receiver", "provider")
                .flatMap { tag ->
                    val nodes = root.getElementsByTagName(tag)
                    (0 until nodes.length).map { nodes.item(it) as org.w3c.dom.Element }
                }
                .filter { it.getAttributeNS(android, "exported") == "true" }
                .map { it.getAttributeNS(android, "name") }
                .toSortedSet()
            val unexpected = exported - allowed
            if (unexpected.isNotEmpty()) {
                throw GradleException(
                    "The merged manifest exports components that are not on the allowlist: " +
                        "$unexpected. Every exported component is attack surface reachable by any " +
                        "other app on the device. Set android:exported=\"false\", or add it to " +
                        "allowedExportedComponents in app/build.gradle.kts with the reason it is safe.",
                )
            }
            // A stale entry is a gate that has quietly stopped covering anything.
            val vanished = allowed - exported
            if (vanished.isNotEmpty()) {
                throw GradleException(
                    "allowedExportedComponents lists components the merged manifest no longer " +
                        "exports: $vanished. Remove them.",
                )
            }
        }
    }
    val variantName = variant.name.replaceFirstChar { it.uppercase() }

    // Reads the mapping R8 actually emitted, not the rules we asked for: a -keep rule that matches
    // nothing — because the library moved the class — is written exactly like one that works.
    val mappingFile = variant.artifacts.get(SingleArtifact.OBFUSCATION_MAPPING_FILE)
    val names = runtimeMatchedClassNames
    val nameGate = tasks.register("checkRuntimeMatchedClassNames$variantName") {
        description = "Fails if R8 renamed a class this app matches by name at runtime."
        inputs.file(mappingFile).withPropertyName("mappingFile").optional(true)
        doLast {
            // Absent on an unminified variant, where there is nothing to rename.
            val file = mappingFile.orNull?.asFile?.takeIf { it.exists() } ?: return@doLast
            // Class lines are unindented and end in ':'; member lines are indented.
            val renamedTo = file.readLines()
                .filter { it.isNotEmpty() && !it[0].isWhitespace() && it.endsWith(":") && " -> " in it }
                .associate { line ->
                    val parts = line.removeSuffix(":").split(" -> ")
                    parts[0] to parts[1]
                }
            val broken = names.mapNotNull { name ->
                when (val to = renamedTo[name]) {
                    null -> "$name is absent from the mapping — R8 shrank it away, or the library " +
                        "moved it. Either way nothing can load it by that name at runtime"
                    name -> null
                    else -> "$name was renamed to '$to', so a runtime match on its simple name " +
                        "silently never fires"
                }
            }
            if (broken.isNotEmpty()) {
                throw GradleException(
                    "R8 broke a class name this app compares at runtime:\n" +
                        broken.joinToString("\n") { "  - $it" } +
                        "\nAdd a -keepnames rule in proguard-rules.pro, or stop matching on the " +
                        "name. See runtimeMatchedClassNames in app/build.gradle.kts.",
                )
            }
        }
    }

    // Every task that can emit an installable artifact. NOT `check`: CI does not run it, so
    // hanging this gate there alone would have been the same nothing the lint entry was.
    listOf("assemble$variantName", "bundle$variantName").forEach { producer ->
        tasks.matching { it.name == producer }.configureEach { dependsOn(gate, nameGate) }
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

