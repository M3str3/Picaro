// Custom stub that takes a value from a build argument instead of embedding it.
//
// A `name=value` CLI argument becomes `$ARG_<name>$` at build time, so nothing
// derived from it lands in the artifact:
//
//   picaro build <plan.yaml> key=<hex>
//
// This stub only illustrates the substitution; it ignores the technique blocks,
// so the packer prints a warning (the declared techniques will have no effect).

fn main() {
    let key: String = $ARG_key$;
    println!("configured key length: {}", key.len());
}
