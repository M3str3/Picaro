// A JVM host for a host-loaded DLL (`build.output.kind: dll`), Java 7 source
// compatible so it runs on a JRE 7.
//
//   javac -d . LoadDll.java
//   java -cp . LoadDll C:\path\to\full-evasion.dll
//
// `System.load` maps the DLL with the OS loader — so `DllMain(DLL_PROCESS_ATTACH)`
// runs — and then calls `JNI_OnLoad`, which starts the chain on a worker thread
// and returns at once. This loader therefore keeps the JVM alive for the whole
// process lifetime: see the latch at the end. It writes nothing to disk.
//
// `System.load` is in-process, so the DLL's bitness must match this JVM's; the
// loader prints `sun.arch.data.model` before loading so a mismatch is obvious
// instead of a bare `UnsatisfiedLinkError`.
//
// Payload arguments are not passed here: Picaro bakes them into the plan
// (`build.payloads.<name>.args`, with `args_mode: override` for a DLL host).
import java.io.File;
import java.util.concurrent.CountDownLatch;

public final class LoadDll {

    public static void main(String[] args) {
        if (args.length < 1) {
            System.err.println("usage: java -cp . LoadDll <path.dll>");
            System.exit(1);
        }

        String bits = System.getProperty("sun.arch.data.model");
        File dll = new File(args[0]).getAbsoluteFile();
        if (!dll.isFile()) {
            System.err.println("[loader] not a file: " + dll);
            System.exit(1);
        }

        System.out.println("[loader] jvm    : "
                + System.getProperty("java.version") + " (" + bits + "-bit)");
        System.out.println("[loader] dll    : " + dll);
        System.out.println("[loader] loading DLL...");

        try {
            System.load(dll.getAbsolutePath());
        } catch (UnsatisfiedLinkError e) {
            System.err.println("[loader] load failed: " + e.getMessage());
            System.err.println("[loader] check the DLL bitness matches this JVM ("
                    + bits + "-bit) and that its JNI_OnLoad returned a valid version");
            System.exit(2);
        }

        System.out.println("[loader] DLL loaded; the DLL's worker runs on its own");
        System.out.println("[loader] Ctrl+C to stop");

        // Keep the JVM alive for as long as the DLL needs — indefinitely, if the
        // payload is long-lived.
        //
        // Why this matters: a native thread spawned by Rust is invisible to the
        // JVM's exit decision. The JVM shuts down when no *non-daemon Java* thread
        // remains, and on shutdown it calls ExitProcess, which tears down every
        // native thread too. So if `main` returned, the JVM would kill the DLL's
        // worker with it. `main` must therefore never return: the latch is never
        // counted down, so `main` blocks here for the process lifetime. (A bounded
        // keep-alive such as `Thread.sleep(ms)` would NOT do — after `ms` the JVM
        // would exit and take a long-lived payload with it.)
        CountDownLatch keepAlive = new CountDownLatch(1);
        while (true) {
            try {
                keepAlive.await();
                return; // nothing counts it down; unreachable in practice
            } catch (InterruptedException ignored) {
                // Swallow the interrupt and keep waiting: stay alive.
            }
        }
    }
}
