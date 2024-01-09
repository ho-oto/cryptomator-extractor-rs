use aes_gcm::{
    aead::{AeadInPlace, Key, KeyInit},
    aes::Aes256,
    Aes256Gcm,
};
use aes_kw::Kek;
use aes_siv::siv::Siv;
use cmac::Cmac;
use scrypt;
use sha1::{Digest, Sha1};

use base32;
use base64::{engine::general_purpose, Engine as _};
use byteorder::{BigEndian, ByteOrder};

use jsonwebtoken;
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

struct Vault {
    aes_gcm_cipher: Aes256Gcm,
    // aes_siv::Aes256SivAead dose not have method to decrypt without nonce.
    // So we construct aes_siv::siv::Siv with key each time for aes-siv decryption.
    aes_siv_key: Key<Aes256Siv>,
    vault_root_path: PathBuf,
}

impl Vault {
    pub fn new(vault_root_path: &Path, user_passphrase: &str) -> Result<Self> {
        let vault_jwt = fs::read_to_string(vault_root_path.join("vault.cryptomator"))?;
        let mut buf = [0; 32];
        // decode jwt without verification
        let mut valid = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::HS256);
        valid.set_required_spec_claims(&["kid", "alg", "typ"]);
        valid.insecure_disable_signature_validation();
        let jwt_decoded = jsonwebtoken::decode::<Claims>(
            &vault_jwt,
            &jsonwebtoken::DecodingKey::from_secret(b""),
            &valid,
        )?;
        ensure!(
            jwt_decoded.claims.format == 8 && jwt_decoded.claims.cipher_combo == "SIV_GCM",
            "unsupported vault format"
        );
        let kid = jwt_decoded.header.kid.context("kid is required")?;
        let master_key_file_name = kid
            .strip_prefix("masterkeyfile:")
            .context("unsupported kid format")?;
        // read master-key file
        let master_key: MasterKey = serde_json::from_reader(BufReader::new(File::open(
            vault_root_path.join(master_key_file_name),
        )?))?;
        ensure!(
            master_key.scrypt_cost_param.is_power_of_two(),
            "scrypt_cost_param is not power of two"
        );
        // unwrap secrets
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
        // validate jwt
        let mut valid = jsonwebtoken::Validation::new(jwt_decoded.header.alg);
        valid.set_required_spec_claims(&["kid", "alg", "typ"]);
        jsonwebtoken::decode::<Claims>(
            &vault_jwt,
            &jsonwebtoken::DecodingKey::from_secret(&[primary_master, mac_master].concat()),
            &valid,
        )
        .context("failed to verify vault.cryptomator")?;
        // construct cipher
        let mut aes_siv_key = [0; 64];
        aes_siv_key[..32].copy_from_slice(&mac_master);
        aes_siv_key[32..].copy_from_slice(&primary_master);
        Ok(Self {
            aes_gcm_cipher: Aes256Gcm::new(primary_master[..].into()),
            aes_siv_key: aes_siv_key.into(),
            vault_root_path: vault_root_path.to_owned(),
        })
    }

    fn path_in_vault(&self, dir_id: &str) -> Result<PathBuf> {
        let mut dir_id: Vec<_> = dir_id.as_bytes().to_vec();
        if let Err(_) =
            Aes256Siv::new(&self.aes_siv_key).encrypt_in_place(iter::empty::<&[u8]>(), &mut dir_id)
        {
            bail!("failed to encrypt dir id");
        }
        let mut hasher = Sha1::new();
        hasher.update(dir_id);
        let result = hasher.finalize();
        let dir_name = base32::encode(base32::Alphabet::RFC4648 { padding: false }, &result);
        let (parent, child) = dir_name.split_at(2);
        Ok(self.vault_root_path.join("d").join(parent).join(child))
    }

    fn decrypt_file_path(
        &self,
        encrypted_file_name: &str,
        parent_dir_id: &str,
        parent_dir_path_in_tgt: &Path,
    ) -> Result<PathBuf> {
        ensure!(
            parent_dir_path_in_tgt.is_dir(),
            "parent_tgt_dir_path should be dir"
        );
        let mut file_name = general_purpose::URL_SAFE.decode(
            encrypted_file_name
                .strip_suffix(".c9r")
                .context("not .c9r file")?,
        )?;
        let (siv_tag, file_name_body) = file_name.split_at_mut(16);
        let mut file_name_body: Vec<u8> = file_name_body.into();
        if let Err(_) = Aes256Siv::new(&self.aes_siv_key).decrypt_in_place_detached(
            [parent_dir_id.as_bytes()],
            &mut file_name_body,
            siv_tag[..16].into(),
        ) {
            bail!("failed to decrypt file name")
        }
        Ok(parent_dir_path_in_tgt.join(&String::from_utf8(file_name_body)?))
    }

    fn decrypt_file_content(&self, encrypted_file_path: &Path) -> Result<Vec<u8>> {
        let mut file = File::open(encrypted_file_path)?;
        let mut header_nonce = [0; 12];
        let mut header_payload = [0; 40];
        let mut header_tag = [0; 16];
        file.read_exact(&mut header_nonce)?;
        file.read_exact(&mut header_payload)?;
        file.read_exact(&mut header_tag)?;
        if let Err(_) = self.aes_gcm_cipher.decrypt_in_place_detached(
            (&header_nonce).into(),
            b"",
            &mut header_payload,
            (&header_tag).into(),
        ) {
            bail!("failed to decrypt file header");
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
            if let Err(_) = cipher.decrypt_in_place_detached(
                chunk_nonce[..12].into(),
                &chunk_add_buf,
                body,
                tag[..16].into(),
            ) {
                bail!("failed to decrypt file chunk")
            }
            clear_text.extend_from_slice(body);
            chunk_num += 1;
        }
        Ok(clear_text)
    }

    fn decrypt_dir(&self, parent_dir_id: &str, parent_dir_path_in_tgt: &Path) -> Result<()> {
        enum Node {
            File { name: String, content_path: PathBuf },
            Dir { name: String, id: String },
        }

        fs::create_dir_all(&parent_dir_path_in_tgt)?;
        let vault_path = self.path_in_vault(parent_dir_id)?;

        for entry in vault_path.read_dir()? {
            if let Ok(entry) = entry {
                let path = entry.path();
                if path.is_file() && entry.file_name() == "dirid.c9r" {
                    continue;
                }
                let node = if path.is_file() {
                    Node::File {
                        name: entry
                            .path()
                            .file_name()
                            .context("not a file")?
                            .to_str()
                            .context("invalid OsStr")?
                            .to_owned(),
                        content_path: path.to_owned(),
                    }
                } else if path.is_dir() {
                    let name = if path.join("name.c9s").is_file() {
                        let mut name = String::new();
                        File::open(&path.join("name.c9s"))?.read_to_string(&mut name)?;
                        name
                    } else {
                        entry
                            .file_name()
                            .to_str()
                            .context("invalid OsStr")?
                            .to_owned()
                    };
                    if path.join("dir.c9r").is_file() {
                        let mut id = String::new();
                        File::open(&path.join("dir.c9r"))?.read_to_string(&mut id)?;
                        Node::Dir { name, id }
                    } else if path.join("contents.c9r").is_file() {
                        Node::File {
                            name,
                            content_path: path.join("contents.c9r"),
                        }
                    } else {
                        bail!("unsupported Node type (may be symlink)")
                    }
                } else {
                    bail!("failed to open entry")
                };
                match node {
                    Node::File { name, content_path } => {
                        let tgt_file_name =
                            self.decrypt_file_path(&name, parent_dir_id, parent_dir_path_in_tgt)?;
                        File::create(tgt_file_name)?
                            .write_all(&self.decrypt_file_content(&content_path)?)?;
                    }
                    Node::Dir { name, id } => {
                        let parent_tgt_dir_path =
                            self.decrypt_file_path(&name, parent_dir_id, parent_dir_path_in_tgt)?;
                        fs::create_dir_all(&parent_tgt_dir_path)?;
                        self.decrypt_dir(&id, &parent_tgt_dir_path)?
                    }
                }
            }
        }
        Ok(())
    }

    pub fn decrypt_dir_from_root(&self, parent_dir_path_in_tgt: &Path) -> Result<()> {
        self.decrypt_dir("", parent_dir_path_in_tgt)
    }
}

fn main() -> Result<()> {
    let vault_root = Path::new(env!("CARGO_MANIFEST_DIR")).join("sample_vault");
    let vault_tgt_root = Path::new(env!("CARGO_MANIFEST_DIR")).join("sample_vault_tgt");
    Vault::new(&vault_root, "password")?.decrypt_dir_from_root(&vault_tgt_root)
}
