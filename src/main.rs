mod vault;

use anyhow::Result;
use std::path::Path;

fn main() -> Result<()> {
    let m = clap::Command::new("cryptomator-extractor")
        .author("Hayate Nakano, nakanodesu@gmail.com")
        .version(env!("CARGO_PKG_VERSION"))
        .about("simple decryption tool of Cryptomator vault")
        .arg(
            clap::Arg::new("vault")
                .help("Root of the Cryptomator vault (where 'vault.cryptomator' exists)")
                .index(1)
                .required(true),
        )
        .arg(
            clap::Arg::new("target")
                .help("Root of the decryption target")
                .index(2)
                .required(true),
        )
        .get_matches();
    let vault = Path::new(m.get_one::<String>("vault").unwrap());
    let target = Path::new(m.get_one::<String>("target").unwrap());
    let passphrase = rpassword::prompt_password("Your passphrase: ")?;
    vault::Vault::new(vault, &passphrase)?.decrypt(target)
}
