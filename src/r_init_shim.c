// Forwards R's package init to the Rust-defined registration function.
// R substitutes '_' for '.' in package names when forming init symbols,
// so the package "mx.encrypt" looks for R_init_mx_encrypt.

void R_init_mx_encrypt_rust(void *dll);
void R_init_mx_encrypt(void *dll) { R_init_mx_encrypt_rust(dll); }
