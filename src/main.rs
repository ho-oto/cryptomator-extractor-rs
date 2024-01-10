mod vault;

use anyhow::Result;
use std::path::Path;

fn main() -> Result<()> {
    let m = clap::Command::new("cryptomator-extractor")
        .author("Hayate Nakano, nakanodesu@gmail.com")
        .version(env!("CARGO_PKG_VERSION"))
        .about("decryption tool for Cryptomator vault")
        .arg(
            clap::Arg::new("vault")
                .help("Path of the Cryptomator vault where 'vault.cryptomator' exists")
                .index(1)
                .required(true),
        )
        .arg(
            clap::Arg::new("target")
                .help("Path of the decryption target path")
                .index(2)
                .required(true),
        )
        .get_matches();
    let vault_root = Path::new(m.get_one::<String>("vault").unwrap());
    let vault_tgt_root = Path::new(m.get_one::<String>("target").unwrap());
    let passphrase = rpassword::prompt_password("Your passphrase: ")?;
    vault::Vault::new(&vault_root, &passphrase)?.decrypt(&vault_tgt_root)
}
