# R8 rules for the release build.
#
# Most of what this app depends on ships its own consumer rules (Room, OkHttp, AndroidX,
# Firebase), so this file only covers what R8 cannot infer from bytecode alone: reflection-driven
# serialization, and the classes the platform instantiates by name from the manifest.

# --- kotlinx.serialization -----------------------------------------------------------------
# Serializers are generated as nested classes and looked up reflectively; without these the
# relay DTOs deserialize to nothing and every network response reads as "malformed".
-keepattributes *Annotation*, InnerClasses
-dontnote kotlinx.serialization.**
-keepclassmembers class **$$serializer { *** descriptor; }
# The `-if @Serializable` rule below is the whole of what serialization needs, and it is precise:
# it keeps the companion and serializer of the annotated classes only.
#
# There used to be a blanket `-keepclasseswithmembers class org.kysecurity.mail.** { public static
# ** Companion; }` above it. That matches every class in this app with a companion object — which,
# in idiomatic Kotlin, is most of them — so it kept their names and undid a large part of the
# obfuscation this file exists to get.
#
# That regression is now caught by CI rather than by a reader remembering to look: the
# `R8 actually obfuscated the app` step in .github/workflows/ci.yml fails the release-build job if
# more than 30% of app classes keep their original name in
# `app/build/outputs/mapping/release/mapping.txt`. It was 22% when that step landed.
-if @kotlinx.serialization.Serializable class org.kysecurity.mail.**
-keepclassmembers class <1> {
    static <1>$Companion Companion;
    public static **$* *;
    kotlinx.serialization.KSerializer serializer(...);
}
-keep,includedescriptorclasses class org.kysecurity.mail.**$$serializer { *; }

# --- Manifest-declared components ----------------------------------------------------------
# Instantiated by class name by the framework, so R8 sees no reference to them. Only the class name
# and the no-arg constructor need to survive: `{ *; }` additionally kept every private field and
# method of five security-relevant classes, which is exactly what enabling R8 was meant to stop.
# Overridden framework methods are kept by the Android default rules, not by these.
-keep class org.kysecurity.mail.KyPostApp { <init>(); }
-keep class org.kysecurity.mail.security.EphemeralAttachmentProvider { <init>(); }
-keep class org.kysecurity.mail.push.KyPostFirebaseMessagingService { <init>(); }
-keep class org.kysecurity.mail.push.KyPostUnifiedPushService { <init>(); }
-keep class org.kysecurity.mail.contacts.device.KyPostContactAuthenticatorService { <init>(); }

# Referenced only by name from AndroidManifest metadata, so R8 cannot see the reference and would
# strip it — leaving splits silently dead in release while they work in debug.
-keep class org.kysecurity.mail.ui.SplitInitializer { <init>(); }

# WorkManager instantiates workers reflectively via their (Context, WorkerParameters) constructor.
-keep class * extends androidx.work.ListenableWorker {
    public <init>(android.content.Context, androidx.work.WorkerParameters);
}

# --- Diagnostics ---------------------------------------------------------------------------
# Keep line numbers so a release crash report is readable, but rename the source file so the
# original paths are not embedded in the APK.
-keepattributes SourceFile,LineNumberTable
-renamesourcefileattribute SourceFile
