mod vault;

use anyhow::Result;
use std::path::Path;

fn main() -> Result<()> {
    let m = clap::Command::new("cryptomator-extractor")
        .arg(clap::Arg::new("vault").index(1).required(true))
        .arg(clap::Arg::new("target").index(2).required(true))
        .get_matches();
    let vault_root = Path::new(m.get_one::<String>("vault").unwrap());
    let vault_tgt_root = Path::new(m.get_one::<String>("target").unwrap());
    let passphrase = rpassword::prompt_password("Your passphrase: ")?;
    vault::Vault::new(&vault_root, &passphrase)?.decrypt_dir_from_root(&vault_tgt_root)
}
