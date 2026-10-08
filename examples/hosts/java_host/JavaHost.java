// Host-loaded DLL: the Java case, and the one that is *different*.
//
// `System.load` calls `JNI_OnLoad`, which starts the chain on a worker thread
// and returns `JNI_VERSION_1_6` at once. The JVM therefore owns the process
// lifetime: a `main` that returns right after `System.load` kills the chain
// before the payload runs. The latch below is the fix the design documents
// (`docs/design/dll-output.md` section 4.3); the parked Phase E extension is
// `AttachCurrentThread` from the worker, after which the JVM waits on its own.
//
// The DLL must match the JVM's bitness (`System.load` is in-process).
//
// Build and run (this host had no JDK, so the Java row of the host matrix in
// `docs/measurements.md` was never measured):
//
//   javac -d examples/hosts/java_host examples/hosts/java_host/JavaHost.java
//   java -cp examples/hosts/java_host JavaHost dist/dll-shellcode.dll 10000
//
// The DLL from `examples/plans/dll.yaml` opens a modal dialog instead of
// returning a code, so it works here too (with the dialog visible from
// `java.exe`).
public final class JavaHost {

    public static void main(String[] args) throws Exception {
        String dll = args.length > 0 ? args[0] : "dist/dll-shellcode.dll";
        long keepAliveMs = args.length > 1 ? Long.parseLong(args[1]) : 10_000L;

        // Absolute path: `System.load` does not take a relative path.
        String absolute = new java.io.File(dll).getAbsolutePath();
        System.out.println("[*] System.load(" + absolute + ")");
        System.load(absolute);
        System.out.println("[*] JNI_OnLoad returned; the chain runs on a worker thread");

        // The latch. A native thread created by Rust is invisible to the JVM's
        // exit decision, so without this the process could exit mid-chain.
        Thread.sleep(keepAliveMs);
        System.out.println("[*] done");
    }
}
