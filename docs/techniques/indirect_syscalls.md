# Indirect Syscalls (Hell's Gate)

- Title: Indirect Syscalls (Hell's Gate)
- ATT&CK: T1106 (Native API)
- YAML key: `build.stub.syscalls.mode = indirect`
- Introduced in: phase 6a

## What it does

Sustituye las llamadas a APIs Win32 sospechosas por syscalls NT con el SSN
resuelto en runtime vía Hell's Gate. El `syscall` se ejecuta a través de un
gadget `syscall; ret` dentro de ntdll, de modo que la instrucción `syscall`
siempre "origina" en ntdll (no en código privado del stub), se evitan los hooks
en userland de ntdll y el IAT del stub deja de contener los imports
sospechosos.

No es una técnica de pipeline: es una configuración del loader
(`build.stub.syscalls`), porque cambia cómo el stub habla con el kernel, no
cómo se ejecuta el payload.

## YAML example

```yaml
build:
  stub:
    syscalls:
      mode: indirect      # none | indirect
      resolver: hells_gate  # hells_gate (tartarus_gate vendrá en 6b)
```

Sin el bloque, los defaults son `mode: none`, `resolver: hells_gate`.

```yaml
# examples/configs/test-syscalls.yaml (resumen)
build:
  stub:
    syscalls:
      mode: indirect
      resolver: hells_gate
runtime:
  - technique: process_hollowing
    params:
      target: "C:\\Windows\\System32\\svchost.exe"
```

## How it works

1. **Contrato de fragments.** Los fragments de técnica siempre llaman a los
   helpers `nt_*` (`nt_alloc_vm`, `nt_write_vm`, `nt_read_vm`,
   `nt_resume_thread`, `nt_unmap_view`). El stub template provee el bloque
   `$SYSCALLS_BLOCK$` con DOS implementaciones de cada helper:
   - `mode: none`: llamada directa a la API Win32 (`VirtualAllocEx`,
     `WriteProcessMemory`, `ReadProcessMemory`, `ResumeThread`; el unmap se
     resuelve dinámicamente vía `GetProcAddress` como antes).
   - `mode: indirect`: syscall a través del gadget de ntdll.

   El fragment no sabe qué modo está activo: el código es idéntico en ambos.

2. **Resolución de SSN (Hell's Gate).** `init_syscalls()` se ejecuta una vez,
   antes de las técnicas. Para cada función Nt* requerida por las técnicas del
   build (la unión de `TechniqueDef::syscalls`, deduplicada):
   - se obtiene su dirección en ntdll con `GetProcAddress` (el nombre va
     ofuscado con `StringsConfig`, reconstruido en runtime);
   - se leen los primeros 8 bytes del stub;
   - se verifica el prólogo canónico `4C 8B D1 B8 ?? ?? ?? ??`
     (`mov r10, rcx; mov eax, <SSN>`) y se extrae el SSN de los bytes 4..8.
   - Si el prólogo no coincide (hook de EDR), `resolve_ssns` devuelve
     `PatternMismatch` con un mensaje claro; Tartarus Gate (fase 6b) lo
     manejará. Si `GetProcAddress` falla, `FunctionNotFound`.

   Solo se resuelven las funciones necesarias: si una técnica no está en el
   pipeline, sus SSNs no se resuelven (menos tiempo y menos strings).

3. **Gadget `syscall; ret`.** Se camina la tabla de secciones de la imagen PE
   de ntdll en memoria para localizar `.text`, y se escanea en busca del
   primer `0F 05 C3`. Su dirección se guarda como el gadget.

4. **Trampoline ASM (`nt_invoke`).** En Rust estable se usa
   `core::arch::global_asm!` con una función exportada. La firma Rust es:

   ```rust
   extern "system" {
       fn nt_invoke(
           arg1: usize, arg2: usize, arg3: usize, arg4: usize,
           arg5: usize, arg6: usize, ssn: u32, gadget: usize,
       ) -> i32; // NTSTATUS
   }
   ```

   Los argumentos 1-4 llegan en rcx/rdx/r8/r9; los 5-8 en el stack del caller
   (`[rsp+40]` a `[rsp+64]` tras el return address y el shadow space de 32
   bytes). El `syscall` espera: `r10` = arg1, `eax` = SSN, args 1-4 en los
   mismos registros, args 5-6 en `[rsp+8]`/`[rsp+16]` (con `rsp` apuntando al
   return address). El trampoline recoloca el frame y hace `jmp r11` al
   gadget; el `ret` del gadget devuelve directamente al caller Rust.

   ```asm
   nt_invoke:
       mov r10, rcx        ; r10 = arg1
       mov rax, [rsp + 40] ; rax = arg5
       mov [rsp + 8], rax  ; el syscall lee arg5 de [rsp+8]
       mov rax, [rsp + 48] ; rax = arg6
       mov [rsp + 16], rax ; el syscall lee arg6 de [rsp+16]
       mov eax, [rsp + 56] ; eax = SSN
       mov r11, [rsp + 64] ; r11 = gadget (syscall; ret)
       jmp r11
   ```

   Verificado en `x86_64-pc-windows-msvc` (rustc 1.90) y con
   `-C target-feature=+crt-static`; el ensamblador integrado de LLVM acepta
   `.intel_syntax noprefix` en ambos targets Windows.

5. **Helpers.** Cada helper envuelve `nt_invoke` con la firma de la función NT:

   - `nt_alloc_vm(process, &base, zero_bits, &size, alloc_type, protect)`
   - `nt_write_vm(process, base, buf, size, &written)`
   - `nt_read_vm(process, base, buf, size, &read)`
   - `nt_resume_thread(thread, &previous_count)`
   - `nt_unmap_view(process, base)`

   Todos devuelven `NTSTATUS` (`i32`); los fragments tratan `< 0` como error.

## What it evades

- Hooks en ntdll de userland (EDR): el SSN se lee de la propia ntdll y la
  llamada entra al kernel sin pasar por el stub exportado hookeado.
- Análisis estático del IAT: `VirtualAllocEx`, `WriteProcessMemory`,
  `ReadProcessMemory` y `ResumeThread` desaparecen del import table; la string
  `NtUnmapViewOfSection` ya no aparece en el binario (medido).

## What detects it

- Kernel callbacks (PsSetCreateProcessNotifyRoutine, ObRegisterCallbacks) y
  ETW-TI: la syscall es indistinguible de una llamada legítima de ntdll.
- Verificación del origen de la instrucción `syscall` (syscall-origin check):
  con indirectas la instrucción ya apunta a ntdll, que es exactamente lo que
  este método soluciona frente a las syscalls directas.
- Inspección de stack / stack-spoofing detectors (el call stack no muestra
  ntdll): pendiente de una fase futura.
- Anomalías de SSN (firmas por SSN cambiados entre builds de Windows).

## Measurements

Ver `docs/measurements/phase6a_iat_reduction.md`: antes/después del IAT con
`batesian audit`, tamaños y confirmación de que las strings Nt* no aparecen
en el binario.

## Implementation notes

- **Por qué indirectas > directas.** Una syscall directa (`syscall` en código
  propio) se detecta con el syscall-origin check (la instrucción debe residir
  en un módulo firmado por Microsoft). Saltando a un gadget `syscall; ret`
  dentro de ntdll, la instrucción origina en ntdll y ese check se supera.
- **Qué pasa si ntdll está hookeada.** El prólogo ya no es
  `mov r10, rcx; mov eax, <SSN>` y Hell's Gate no puede leer el SSN: el stub
  falla con `PatternMismatch` (mensaje claro). Tartarus Gate (fase 6b) hará
  el fallback recorriendo la sección `.text` de ntdll byte a byte buscando
  los prólogos por patrón completo (incluyendo SSN vecinos).
- El renderizado es programático (`src/engine/syscalls.rs`): el bloque se
  ensambla a partir de `TechniqueDef::syscalls` (unión de requerimientos del
  pipeline), así que una técnica nueva solo declara sus funciones Nt* y sus
  helpers se emiten si (y solo si) es necesaria.
- Los nombres Nt* nunca llegan al binario: se reconstruyen en runtime vía
  `StringsConfig` (igual que `patch_amsi`). El guardrail
  `no_sensitive_literals_in_generated_stubs` cubre estas strings.
- Las referencias de `code_examples/RustRedOps` (MIT/Apache) resuelven SSNs
  por API-hashing en vez de `GetProcAddress`; esa mejora (eliminar del
  binario incluso los nombres ofuscados) queda como dirección futura.

## References

- Hell's Gate (am0nsec, RtlMateusz — VX Underground):
  https://vxug.fakedoma.in/papers/VXUG/Exclusive/HellsGate.pdf
- Tartarus' Gate (trickster0):
  https://github.com/trickster0/TartarusGate
- Direct syscalls: a journey from high to low (Dylan Tran, Outflank):
  https://outflank.nl/blog/2020/12/26/direct-syscalls-in-beacon-object-files/
- Direct syscalls vs indirect syscalls (Outflank):
  https://www.outflank.nl/blog/2023/12/13/direct-syscalls-vs-indirect-syscalls/
- Syscall detection / instrumentation callbacks (n4r1b):
  https://github.com/Deputation/instrumentation_callbacks
- Reference implementations in this repo:
  `code_examples/RustRedOps/Syscalls`,
  `code_examples/RustRedOps/Hells-Halos-Tartarus-Gate`,
  `code_examples/OffensiveRust/asm_syscall` (patrón de trampoline).
