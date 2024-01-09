use aes::Aes256;
use aes_gcm::{
    aead::{AeadInPlace, KeyInit},
    Aes256Gcm,
};
use aes_kw::Kek;
use aes_siv::siv::Siv;
use cmac::Cmac;
use jsonwebtoken;
use scrypt;
use sha1::{Digest, Sha1};

use base32;
use base64::{engine::general_purpose, Engine as _};
use byteorder::{BigEndian, ByteOrder};
use serde::Deserialize;
use serde_json;
use serde_with::{base64::Base64, serde_as};

use anyhow::{bail, ensure, Context, Result};

use std::io::BufReader;
use std::iter;
use std::path::{Path, PathBuf};
use std::{fs, io::Write};
use std::{fs::File, io::Read};

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Claims {
    format: i64,
    cipher_combo: String,
}

#[serde_as]
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct MasterKey {
    #[serde_as(as = "Base64")]
    scrypt_salt: Vec<u8>,
    scrypt_cost_param: u64,
    scrypt_block_size: u32,
    #[serde_as(as = "Base64")]
    primary_master_key: Vec<u8>,
    #[serde_as(as = "Base64")]
    hmac_master_key: Vec<u8>,
}

type Aes256Siv = Siv<Aes256, Cmac<Aes256>>;

fn get_vault_meta(vault_root_path: &Path, user_passphrase: &str) -> Result<(Aes256Gcm, Aes256Siv)> {
    use jsonwebtoken::{decode, DecodingKey, Validation};

    let vault_jwt = fs::read_to_string(vault_root_path.join("vault.cryptomator"))?;
    let mut buf = [0; 32];

    let mut valid = Validation::new(jsonwebtoken::Algorithm::HS256);
    valid.set_required_spec_claims(&["kid", "alg", "typ"]);
    valid.insecure_disable_signature_validation();
    let claims = decode::<Claims>(
        &vault_jwt,
        &jsonwebtoken::DecodingKey::from_secret(b""),
        &valid,
    )?;

    ensure!(
        claims.claims.format == 8 && claims.claims.cipher_combo == "SIV_GCM",
        "unsupported vault format"
    );
    let kid = claims.header.kid.context("kid is required")?;
    let master_key_file_name = kid
        .strip_prefix("masterkeyfile:")
        .context("unsupported kid format")?;

    let master_key: MasterKey = serde_json::from_reader(BufReader::new(File::open(
        vault_root_path.join(master_key_file_name),
    )?))?;
    ensure!(
        master_key.scrypt_cost_param.is_power_of_two(),
        "scrypt_cost_param is not power of two"
    );
    scrypt::scrypt(
        user_passphrase.as_bytes(),
        &master_key.scrypt_salt,
        &scrypt::Params::new(
            master_key.scrypt_cost_param.ilog2().try_into()?,
            master_key.scrypt_block_size,
            1,
            32,
        )?,
        &mut buf,
    )?;
    let kek = Kek::try_from(buf)?;

    let primary_master = match kek.unwrap(&master_key.primary_master_key, &mut buf) {
        Ok(_) => buf,
        Err(_) => bail!("failed to unwrap master key"),
    };
    let mac_master = match kek.unwrap(&master_key.hmac_master_key, &mut buf) {
        Ok(_) => buf,
        Err(_) => bail!("failed to unwrap MAC key"),
    };

    let mut valid = Validation::new(claims.header.alg);
    valid.set_required_spec_claims(&["kid", "alg", "typ"]);
    decode::<Claims>(
        &vault_jwt,
        &DecodingKey::from_secret(&[primary_master, mac_master].concat()),
        &valid,
    )?;

    Ok((
        Aes256Gcm::new(primary_master[..].into()),
        Siv::new([mac_master, primary_master].concat()[..64].into()),
    ))
}

fn dir_id_to_vault_path(
    vault_root_path: &Path,
    dir_id: &str,
    cipher: &mut Aes256Siv,
) -> Result<PathBuf> {
    let mut dir_id: Vec<_> = dir_id.as_bytes().to_vec();
    if let Err(_) = cipher.encrypt_in_place(iter::empty::<&[u8]>(), &mut dir_id) {
        bail!("failed to encrypt dir id");
    }
    let mut hasher = Sha1::new();
    hasher.update(dir_id);
    let result = hasher.finalize();
    let dir_name = base32::encode(base32::Alphabet::RFC4648 { padding: false }, &result);
    let (parent, child) = dir_name.split_at(2);
    Ok(vault_root_path.join("d").join(parent).join(child))
}

fn decrypt_file_name(
    encrypted_file_path: &Path,
    parent_dir_id: &str,
    parent_tgt_dir_path: &Path,
    cipher: &mut Aes256Siv,
) -> Result<PathBuf> {
    ensure!(
        parent_tgt_dir_path.is_dir(),
        "parent_tgt_dir_path should be dir"
    );
    let mut file_name = general_purpose::URL_SAFE.decode(
        &encrypted_file_path
            .file_name()
            .context("not a file")?
            .to_str()
            .context("invalid OsStr")?
            .strip_suffix(".c9r")
            .context("not .c9r file")?,
    )?;
    let (siv_tag, file_name_body) = file_name.split_at_mut(16);
    let mut file_name_body: Vec<u8> = file_name_body.into();
    cipher
        .decrypt_in_place_detached(
            [parent_dir_id.as_bytes()],
            &mut file_name_body,
            siv_tag[..16].into(),
        )
        .unwrap();
    Ok(parent_tgt_dir_path.join(&String::from_utf8(file_name_body)?))
}

fn decrypt_file_body(encrypted_file_path: &Path, cipher: &Aes256Gcm) -> Result<Vec<u8>> {
    let mut file = File::open(encrypted_file_path)?;
    let mut header_nonce = [0; 12];
    let mut header_payload = [0; 40];
    let mut header_tag = [0; 16];
    file.read_exact(&mut header_nonce)?;
    file.read_exact(&mut header_payload)?;
    file.read_exact(&mut header_tag)?;
    if let Err(_) = cipher.decrypt_in_place_detached(
        (&header_nonce).into(),
        b"",
        &mut header_payload,
        (&header_tag).into(),
    ) {
        bail!("failed to decrypt header");
    }
    ensure!(
        header_payload[..8] == [0xFF; 8],
        "header payload should start with 0xFFFFFFFFFFFFFFFF"
    );
    let cipher = Aes256Gcm::new(header_payload[8..].into());
    let mut clear_text: Vec<u8> = vec![];
    let mut buf = [0; 12 + (1024 * 32) + 16];
    let mut chunk_num = 0;
    let mut chunk_add_buf = [0; 20];
    chunk_add_buf[8..].copy_from_slice(&header_nonce);
    while let Ok(n) = file.read(&mut buf) {
        if n == 0 {
            break;
        }
        ensure!(n > 12 + 16, "invalid chunk size");
        BigEndian::write_u64(&mut chunk_add_buf[..8], chunk_num);
        let (chunk_nonce, rest) = buf.split_at_mut(12);
        let (body, tag) = rest.split_at_mut(n - 12 - 16);
        cipher
            .decrypt_in_place_detached(
                chunk_nonce[..12].into(),
                &chunk_add_buf,
                body,
                tag[..16].into(),
            )
            .unwrap();
        clear_text.extend_from_slice(body);
        chunk_num += 1;
    }
    Ok(clear_text)
}

fn main() -> Result<()> {
    let vault_root = Path::new(env!("CARGO_MANIFEST_DIR")).join("sample_vault");
    let vault_tgt_root = Path::new(env!("CARGO_MANIFEST_DIR")); //.join("sample_vault_tgt");
    let (cipher_header, mut cipher_name) = get_vault_meta(&vault_root, "password")?;
    let vault_path_of_root = dir_id_to_vault_path(&vault_root, "", &mut cipher_name)?;
    for entry in vault_path_of_root.read_dir()? {
        if let Ok(entry) = entry {
            if entry.path().is_file() && entry.file_name() != "dirid.c9r" {
                println!("{:?}", entry.file_name());
                let tgt_file_name =
                    decrypt_file_name(&entry.path(), "", vault_tgt_root, &mut cipher_name)?;
                File::create(tgt_file_name)?
                    .write_all(&decrypt_file_body(&entry.path(), &cipher_header)?)?;
            }
            if entry.path().is_dir() {
                for entry in entry.path().read_dir()? {
                    if let Ok(entry) = entry {
                        if entry.file_name() == "dir.c9r" {
                            let mut buf = String::new();
                            File::open(entry.path())?.read_to_string(&mut buf)?;
                            println!(
                                "{:?}",
                                dir_id_to_vault_path(&vault_root, &buf, &mut cipher_name)
                            );
                        }
                    }
                }
            }
        }
    }
    Ok(())
}
