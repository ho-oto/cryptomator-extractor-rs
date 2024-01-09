mod vault;

use anyhow::Result;
use rpassword;
use std::path::Path;

fn main() -> Result<()> {
    let vault_root = Path::new(env!("CARGO_MANIFEST_DIR")).join("sample_vault");
    let vault_tgt_root = Path::new(env!("CARGO_MANIFEST_DIR")).join("sample_vault_tgt");
    let passphrase = rpassword::prompt_password("Your passphrase: ")?;
    vault::Vault::new(&vault_root, &passphrase)?.decrypt_dir_from_root(&vault_tgt_root)
}
