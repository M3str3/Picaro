# T3 — Cerrar limitaciones ya documentadas
- Hollowing completo: provisioning de loader/TLS según el plan de docs/techniques/process_hollowing.md (dejar inicializar el loader, cargar DLLs en el target, ejecutar callbacks TLS). Es el mayor valor funcional pendiente.
- Fase 6b Tartarus Gate (resolver: tartarus_gate) y migrar reflective_loading, patch_amsi, patch_etw, anti_debug a los helpers nt_*.
- API hashing para resolver SSNs sin depender de GetProcAddress ni de nombres (dirección ya anotada en el doc de syscalls).
-
# T4 — Nuevas técnicas / formatos (el registro hace que salgan baratas)
- Formatos de payload: build.payload.format: pe|shellcode|dll (y args para shellcode/DLL).
- Técnicas nuevas aprovechando el modelo Preparation/Execution: early_bird (APC, T1055.012 — esquiva elegantemente el problema del loader no inicializado), process_doppelganging/transacted_hollowing (T1055.013), ppid_spoofing (T1134.004), module_stomping (T1055), unhook_ntdll (preparación), stack_spoofing (cierra el hueco que el propio doc de syscalls reconoce).
- bouncer: on_fail: decoy y checks MAC/IP ya en el roadmap.


# T5 — Ingeniería y robustez
- Fuzzing de src/engine/pe.rs y del parser de config (entrada no confiable).
- cargo deny/cargo audit en CI (hay ureq/inquire/serde_yml; serde_yml está sin mantener — valorar serde_yaml/serde_norway).
- Enforcement de Capability y builds reproducibles (--seed/clave determinista para tests, hoy la key aleatoria lo impide).
UX: cerrar los huecos del wizard (strings.key, stub.path, args_mode: override, regiones de sleep_obfuscation), batesian config validate <file> y --json en techniques.
