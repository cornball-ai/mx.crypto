// Forwards R's package init to the Rust-defined registration function.
// R substitutes '_' for '.' in package names when forming init symbols,
// so the package "mx.crypto" looks for R_init_mx_crypto.

void R_init_mx_crypto_rust(void *dll);
void R_init_mx_crypto(void *dll) { R_init_mx_crypto_rust(dll); }
