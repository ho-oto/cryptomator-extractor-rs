// RustCrypto
use aead::{AeadInPlace as _, Key, KeyInit as _};
use aes::Aes256;
use aes_gcm::Aes256Gcm;
use aes_kw::Kek;
use aes_siv::siv::Siv;
use cmac::Cmac;
use digest::{core_api::CoreWrapper, Digest as _};
use sha1::Sha1Core;

use anyhow::{bail, ensure, Context as _, Result};
use byteorder::{BigEndian, ByteOrder as _};
use data_encoding::{BASE32, BASE64, BASE64URL};
use jsonwebtoken::{decode as jwt_decode, Algorithm::HS256, DecodingKey, Validation};
use serde::Deserialize;
use url::Url;

use std::fs;
use std::fs::File;
use std::io::{Read, Write};
use std::iter;
use std::path::{Path, PathBuf};

type Aes256Siv = Siv<Aes256, Cmac<Aes256>>;

pub struct Vault {
    aes_gcm_cipher: Aes256Gcm,
    // aes_siv::Aes256SivAead dose not have method to decrypt without nonce.
    // So we construct aes_siv::siv::Siv with key each time for aes-siv decryption.
    aes_siv_key: Key<Aes256Siv>,
    root_of_vault: PathBuf,
}

impl Vault {
    pub fn new(root_of_vault: &Path, passphrase: &str) -> Result<Self> {
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase")]
        struct Claims {
            format: i64,
            cipher_combo: String,
        }

        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase")]
        struct MasterKey {
            scrypt_salt: String,
            scrypt_cost_param: u64,
            scrypt_block_size: u32,
            primary_master_key: String,
            hmac_master_key: String,
        }

        let vault_jwt = fs::read_to_string(root_of_vault.join("vault.cryptomator"))
            .context("failed to open vault.cryptomator")?;
        let mut buf = [0; 32];

        // decode jwt without verification
        let key = DecodingKey::from_secret(b"");
        let mut valid = Validation::new(HS256);
        valid.set_required_spec_claims(&["kid", "alg", "typ"]);
        valid.insecure_disable_signature_validation();
        let jwt = jwt_decode::<Claims>(&vault_jwt, &key, &valid).context("failed to decode JWT")?;
        let kid = Url::parse(&jwt.header.kid.context("kid is required")?)?;
        ensure!(
            kid.scheme() == "masterkeyfile"
                && jwt.claims.format == 8
                && jwt.claims.cipher_combo == "SIV_GCM",
            "unsupported vault format"
        );

        // read master-key file
        let master_key = serde_json::from_str::<MasterKey>(
            &fs::read_to_string(root_of_vault.join(kid.path()))
                .context("failed to open masterkeyfile")?,
        )
        .context("unsupported masterkeyfile format")?;
        ensure!(
            master_key.scrypt_cost_param.is_power_of_two(),
            "scrypt_cost_param is not power of two"
        );

        // unwrap secrets
        scrypt::scrypt(
            passphrase.as_bytes(),
            &BASE64.decode(master_key.scrypt_salt.as_bytes())?,
            &scrypt::Params::new(
                master_key.scrypt_cost_param.ilog2().try_into()?,
                master_key.scrypt_block_size,
                1,
                32,
            )?,
            &mut buf,
        )?;
        let kek = Kek::try_from(buf)?;
        let primary_master = match kek.unwrap(
            &BASE64.decode(master_key.primary_master_key.as_bytes())?,
            &mut buf,
        ) {
            Ok(()) => buf,
            Err(_) => bail!("failed to unwrap master key"),
        };
        let mac_master = match kek.unwrap(
            &BASE64.decode(master_key.hmac_master_key.as_bytes())?,
            &mut buf,
        ) {
            Ok(()) => buf,
            Err(_) => bail!("failed to unwrap MAC key"),
        };

        // validate jwt
        let key = DecodingKey::from_secret(&[primary_master, mac_master].concat());
        let mut valid = Validation::new(HS256);
        valid.set_required_spec_claims(&["kid", "alg", "typ"]);
        jwt_decode::<Claims>(&vault_jwt, &key, &valid)
            .context("failed to verify signature of vault.cryptomator")?;

        // construct cipher
        let mut aes_siv_key = [0; 64];
        aes_siv_key[..32].copy_from_slice(&mac_master);
        aes_siv_key[32..].copy_from_slice(&primary_master);
        Ok(Self {
            aes_gcm_cipher: Aes256Gcm::new(primary_master[..].into()),
            aes_siv_key: aes_siv_key.into(),
            root_of_vault: root_of_vault.to_owned(),
        })
    }

    fn path_in_vault(&self, dir_id: &str) -> Result<PathBuf> {
        let mut id = dir_id.as_bytes().to_vec();
        if let Err(_) =
            Aes256Siv::new(&self.aes_siv_key).encrypt_in_place(iter::empty::<&[u8]>(), &mut id)
        {
            bail!("failed to encrypt dir_id: {}", dir_id);
        };
        let mut hasher = CoreWrapper::from_core(Sha1Core::default());
        hasher.update(id);
        let result = hasher.finalize();
        let dir_id_hash = BASE32.encode(&result);
        let (parent, child) = dir_id_hash.split_at(2);
        Ok(self.root_of_vault.join("d").join(parent).join(child))
    }

    fn path_in_tgt(
        &self,
        encrypted_name: &str,
        parent_dir_id: &str,
        parent_in_tgt: &Path,
    ) -> Result<PathBuf> {
        ensure!(parent_in_tgt.is_dir(), "parent_in_tgt should be dir");
        let mut file_name = BASE64URL.decode(
            encrypted_name
                .strip_suffix(".c9r")
                .context("not .c9r file")?
                .as_bytes(),
        )?;
        let (siv_tag, file_name_body) = file_name.split_at_mut(16);
        let mut file_name_body = file_name_body.to_vec();
        if let Err(_) = Aes256Siv::new(&self.aes_siv_key).decrypt_in_place_detached(
            [parent_dir_id.as_bytes()],
            &mut file_name_body,
            siv_tag[..16].into(),
        ) {
            bail!("failed to decrypt file name: {}", encrypted_name)
        }
        Ok(parent_in_tgt.join(&String::from_utf8(file_name_body)?))
    }

    fn plaintext(&self, encrypted_file: &Path) -> Result<Vec<u8>> {
        let mut file = File::open(encrypted_file)?;
        let mut header_nonce = [0; 12];
        let mut header_payload = [0; 40];
        let mut header_tag = [0; 16];
        file.read_exact(&mut header_nonce)
            .with_context(|| format!("failed to read header nonce: {:?}", encrypted_file))?;
        file.read_exact(&mut header_payload)
            .with_context(|| format!("failed to read header payload: {:?}", encrypted_file))?;
        file.read_exact(&mut header_tag)
            .with_context(|| format!("failed to read header tag: {:?}", encrypted_file))?;
        if let Err(_) = self.aes_gcm_cipher.decrypt_in_place_detached(
            (&header_nonce).into(),
            b"",
            &mut header_payload,
            (&header_tag).into(),
        ) {
            bail!("failed to decrypt file header: {:?}", encrypted_file);
        }
        ensure!(
            header_payload[..8] == [0xFF; 8],
            "header payload should start with 0xFF_FF_FF_FF_FF_FF_FF_FF: {:?}",
            encrypted_file
        );
        let cipher = Aes256Gcm::new(header_payload[8..].into());
        let mut buf = [0; 12 + (1024 * 32) + 16];
        let mut chunk_num = 0;
        let mut chunk_aad_buf = [0; 20];
        chunk_aad_buf[8..].copy_from_slice(&header_nonce);
        let mut output = Vec::<u8>::new();
        while let Ok(n) = file.read(&mut buf) {
            if n == 0 {
                break;
            }
            ensure!(
                n > 12 + 16,
                "size of chunk {} in {:?} is invalid",
                chunk_num,
                encrypted_file
            );
            BigEndian::write_u64(&mut chunk_aad_buf[..8], chunk_num);
            let (chunk_nonce, rest) = buf.split_at_mut(12);
            let (body, tag) = rest.split_at_mut(n - 12 - 16);
            match cipher.decrypt_in_place_detached(
                chunk_nonce[..12].into(),
                &chunk_aad_buf,
                body,
                tag[..16].into(),
            ) {
                Ok(()) => output.extend_from_slice(body),
                Err(_) => bail!(
                    "failed to decrypt file chunk {} in {:?}",
                    chunk_num,
                    encrypted_file
                ),
            }
            chunk_num += 1;
        }
        Ok(output)
    }

    fn decrypt_dir(&self, parent_dir_id: &str, parent_in_tgt: &Path) -> Result<()> {
        enum Node {
            Dir { dir_id: String },
            File { contents_path: PathBuf },
        }

        fs::create_dir_all(&parent_in_tgt)?;
        let vault_path = self.path_in_vault(parent_dir_id)?;

        for entry in vault_path.read_dir()? {
            if let Ok(entry) = entry {
                let path = entry.path();
                let mut name = path
                    .file_name()
                    .context("failed to get file name")?
                    .to_str()
                    .context("invalid OsStr")?
                    .to_owned();

                if name == "dirid.c9r" {
                    continue;
                }

                let node = if path.is_file() {
                    Node::File {
                        contents_path: path,
                    }
                } else if path.is_dir() {
                    if path.join("name.c9s").is_file() {
                        name = fs::read_to_string(&path.join("name.c9s"))?
                    };

                    if path.join("dir.c9r").is_file() {
                        Node::Dir {
                            dir_id: fs::read_to_string(&path.join("dir.c9r"))?,
                        }
                    } else if path.join("contents.c9r").is_file() {
                        Node::File {
                            contents_path: path.join("contents.c9r"),
                        }
                    } else {
                        bail!("symbolic link is unsupported")
                    }
                } else {
                    bail!("failed to open entry: {:?}", path)
                };

                let path = self.path_in_tgt(&name, parent_dir_id, parent_in_tgt)?;
                match node {
                    Node::Dir { dir_id } => self.decrypt_dir(&dir_id, &path)?,
                    Node::File { contents_path } => {
                        File::create(path)?.write_all(&self.plaintext(&contents_path)?)?
                    }
                }
            }
        }
        Ok(())
    }

    pub fn decrypt(&self, root_of_tgt: &Path) -> Result<()> {
        self.decrypt_dir("", root_of_tgt)
    }
}
