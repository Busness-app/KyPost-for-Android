package android.util;

/**
 * A real {@code android.util.Log} for JVM unit tests, shadowing the stub in the mockable
 * android.jar.
 *
 * <p>This exists so {@code testOptions.unitTests.isReturnDefaultValues} can be <b>false</b>. With
 * it true, every unmocked {@code android.*} call in JVM-tested production code returned a default
 * <i>silently</i> — {@code android.util.Base64} returned null, {@code org.json} returned nothing —
 * so a suite could go green over a body that did nothing. {@code DeviceEnvelope}'s KDoc records
 * exactly that happening: its tests all passed vacuously, and replacing the whole function with
 * {@code = null} left the suite green.
 *
 * <p>The setting was true for one reason: logging. Production code with no {@code Context}
 * (AppLockManager, DeviceEnvelope, EnrollmentCeremony) has to be able to record a
 * security-relevant event without that making it untestable. Flipping the flag and shadowing this
 * one class gets both — every other stubbed API now throws loudly, which is the correct signal
 * given the project's own rule that JVM-tested production code must not call {@code android.*} for
 * anything but logging.
 *
 * <p>Writes to stderr rather than discarding, so a test that logs an error is visible in the
 * report instead of silent.
 */
public final class Log {
    public static final int VERBOSE = 2;
    public static final int DEBUG = 3;
    public static final int INFO = 4;
    public static final int WARN = 5;
    public static final int ERROR = 6;
    public static final int ASSERT = 7;

    private Log() {}

    public static int v(String tag, String msg) { return print("V", tag, msg, null); }
    public static int v(String tag, String msg, Throwable tr) { return print("V", tag, msg, tr); }
    public static int d(String tag, String msg) { return print("D", tag, msg, null); }
    public static int d(String tag, String msg, Throwable tr) { return print("D", tag, msg, tr); }
    public static int i(String tag, String msg) { return print("I", tag, msg, null); }
    public static int i(String tag, String msg, Throwable tr) { return print("I", tag, msg, tr); }
    public static int w(String tag, String msg) { return print("W", tag, msg, null); }
    public static int w(String tag, String msg, Throwable tr) { return print("W", tag, msg, tr); }
    public static int w(String tag, Throwable tr) { return print("W", tag, null, tr); }
    public static int e(String tag, String msg) { return print("E", tag, msg, null); }
    public static int e(String tag, String msg, Throwable tr) { return print("E", tag, msg, tr); }
    public static int wtf(String tag, String msg) { return print("A", tag, msg, null); }
    public static int wtf(String tag, String msg, Throwable tr) { return print("A", tag, msg, tr); }
    public static int wtf(String tag, Throwable tr) { return print("A", tag, null, tr); }

    public static boolean isLoggable(String tag, int level) { return true; }

    public static String getStackTraceString(Throwable tr) {
        if (tr == null) return "";
        java.io.StringWriter sw = new java.io.StringWriter();
        tr.printStackTrace(new java.io.PrintWriter(sw));
        return sw.toString();
    }

    public static int println(int priority, String tag, String msg) {
        return print(String.valueOf(priority), tag, msg, null);
    }

    private static int print(String level, String tag, String msg, Throwable tr) {
        String line = level + "/" + tag + ": " + (msg == null ? "" : msg);
        System.err.println(line);
        if (tr != null) tr.printStackTrace(System.err);
        return line.length();
    }
}
