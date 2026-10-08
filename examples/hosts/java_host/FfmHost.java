// Loads a packed DLL from the JVM and calls its export, using the FFM API
// (`java.lang.foreign`), which is standard since JDK 22 (preview in 21, where
// it needs `--enable-preview`). No JNI wrapper, no JNA, no native code.
//
// This is the counterpart of `JavaHost.java`: that one only proves the
// `JNI_OnLoad` path (`System.load` starts the chain and returns at once), while
// this one calls `Run` and reads the chain's return code.
//
// `SymbolLookup.libraryLookup` maps the DLL with the OS loader, so `DllMain`
// runs; `JNI_OnLoad` does NOT (only the JVM's own loader calls it), which is
// why `entry: export:<name>` is the right entry for this host and `auto`'s
// `JNI_OnLoad` would sit unused.
//
// NOT run on this repository's measurement host (no JDK installed).
//
// Build and run:
//   javac -d examples/hosts/java_host examples/hosts/java_host/FfmHost.java
//   java -cp examples/hosts/java_host FfmHost dist/dll-shellcode.dll Run

import java.lang.foreign.Arena;
import java.lang.foreign.FunctionDescriptor;
import java.lang.foreign.Linker;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.SymbolLookup;
import java.lang.foreign.ValueLayout;
import java.lang.invoke.MethodHandle;
import java.nio.file.Path;

public final class FfmHost {

    public static void main(String[] args) throws Throwable {
        String dll = args.length > 0 ? args[0] : "dist/dll-shellcode.dll";
        String export = args.length > 1 ? args[1] : "Run";
        Path path = Path.of(dll).toAbsolutePath();

        System.out.println("[*] loading " + path + " (export " + export + ")");

        // Arena.global() keeps the library mapped for the process's lifetime.
        SymbolLookup lookup = SymbolLookup.libraryLookup(path, Arena.global());
        Linker linker = Linker.nativeLinker();

        // The plain export has the rundll32 shape: four arguments, ignored.
        FunctionDescriptor descriptor = FunctionDescriptor.of(
                ValueLayout.JAVA_INT,   // int return
                ValueLayout.ADDRESS,    // hwnd
                ValueLayout.ADDRESS,    // hinst
                ValueLayout.ADDRESS,    // cmdline
                ValueLayout.JAVA_INT);  // show

        MethodHandle run = linker.downcallHandle(
                lookup.find(export).orElseThrow(() -> new NoSuchMethodException(export)),
                descriptor);

        int code = (int) run.invokeExact(
                MemorySegment.NULL, MemorySegment.NULL, MemorySegment.NULL, 0);
        System.out.println("[+] " + export + "() -> " + code);
    }
}
