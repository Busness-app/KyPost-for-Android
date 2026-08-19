# R8 rules for the release build: only what R8 cannot infer, reflection and manifest-named classes.

# kotlinx.serialization
# Serializers are generated as nested classes and looked up reflectively; without these the
# relay DTOs deserialize to nothing and every network response reads as "malformed".
-keepattributes *Annotation*, InnerClasses
-dontnote kotlinx.serialization.**
-keepclassmembers class **$$serializer { *** descriptor; }
-if @kotlinx.serialization.Serializable class org.kysecurity.mail.**
-keepclassmembers class <1> {
    static <1>$Companion Companion;
    public static **$* *;
    kotlinx.serialization.KSerializer serializer(...);
}
-keep,includedescriptorclasses class org.kysecurity.mail.**$$serializer { *; }

# Manifest-declared components
# Instantiated by name by the framework; only the class name and no-arg constructor must survive.
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

# Diagnostics
# Keep line numbers so a release crash report is readable, but rename the source file so the
# original paths are not embedded in the APK.
-keepattributes SourceFile,LineNumberTable
-renamesourcefileattribute SourceFile
