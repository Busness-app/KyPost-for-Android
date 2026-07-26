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
-keepclasseswithmembers class com.urlxl.mail.** {
    public static ** Companion;
}
-if @kotlinx.serialization.Serializable class com.urlxl.mail.**
-keepclassmembers class <1> {
    static <1>$Companion Companion;
    public static **$* *;
    kotlinx.serialization.KSerializer serializer(...);
}
-keep,includedescriptorclasses class com.urlxl.mail.**$$serializer { *; }

# --- Manifest-declared components ----------------------------------------------------------
# Instantiated by class name by the framework, so R8 sees no reference to them.
-keep class com.urlxl.mail.KyPostApp { *; }
-keep class com.urlxl.mail.security.EphemeralAttachmentProvider { *; }
-keep class com.urlxl.mail.push.KyPostFirebaseMessagingService { *; }
-keep class com.urlxl.mail.push.KyPostUnifiedPushService { *; }
-keep class com.urlxl.mail.contacts.device.KyPostContactAuthenticatorService { *; }

# WorkManager instantiates workers reflectively via their (Context, WorkerParameters) constructor.
-keep class * extends androidx.work.ListenableWorker {
    public <init>(android.content.Context, androidx.work.WorkerParameters);
}

# --- Diagnostics ---------------------------------------------------------------------------
# Keep line numbers so a release crash report is readable, but rename the source file so the
# original paths are not embedded in the APK.
-keepattributes SourceFile,LineNumberTable
-renamesourcefileattribute SourceFile
