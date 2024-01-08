use aes::Aes256;
use aes_gcm::{
    aead::{AeadInPlace, KeyInit},
    Aes256Gcm,
};
use aes_kw::Kek;
use aes_siv::siv::Siv;
use anyhow::{ensure, Result};
use base64::{engine::general_purpose, Engine as _};
use byteorder::{BigEndian, ByteOrder};
use cmac::Cmac;
use jsonwebtoken;
use scrypt;
use serde::Deserialize;
use serde_json;
use serde_with::{base64::Base64, serde_as};
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

/* cSpell:disable */

static VAULT_JWT: &str = "eyJraWQiOiJtYXN0ZXJrZXlmaWxlOm1hc3RlcmtleS5jcnlwdG9tYXRvciIsImFsZyI6IkhTMjU2IiwidHlwIjoiSldUIn0.eyJqdGkiOiJjNzE0YWU2NS05NDg5LTRhYTgtOTEwOS1kNDE4YjNhOTI5MTkiLCJmb3JtYXQiOjgsImNpcGhlckNvbWJvIjoiU0lWX0dDTSIsInNob3J0ZW5pbmdUaHJlc2hvbGQiOjIyMH0.ALuy5lni8Rb4WPnpDY9UHcz2G8JJuKtYOZiQCr73jVU";

static MASTERKEY_JSON: &str = r#"{
    "version": 999,
    "scryptSalt": "sD/IDv8nhmI=",
    "scryptCostParam": 32768,
    "scryptBlockSize": 8,
    "primaryMasterKey": "LUE8YEKFtVxQU6tvRusExl95n0pd1hozskQ5bYvd7qGVgzUr6tgfkg==",
    "hmacMasterKey": "3M2PucnR9aDJmrIugyv6sG0aSR1NFkK4KRpaPRCUUbUhCCKl9OgITQ==",
    "versionMac": "oxU6jFXKslN/nolJox7gRMlhOpnlKgU01dJQ3dhi05s="
}"#;

static USER_PASSWORD: &[u8] = b"password";

/* cSpell:ensable */

fn main() -> Result<()> {
    let mut valid = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::HS256);
    valid.set_required_spec_claims(&["kid", "alg", "typ"]);
    valid.insecure_disable_signature_validation();
    let claims = jsonwebtoken::decode::<Claims>(
        &VAULT_JWT,
        &jsonwebtoken::DecodingKey::from_secret(b""),
        &valid,
    )?;
    ensure!(
        claims.claims.cipher_combo == "SIV_GCM",
        "unsupported cipher_combo"
    );
    ensure!(claims.claims.format == 8, "unsupported vault format");

    let masterkey: MasterKey = serde_json::from_str(MASTERKEY_JSON)?;

    let mut buf = [0; 32];
    scrypt::scrypt(
        USER_PASSWORD,
        &masterkey.scrypt_salt,
        &scrypt::Params::new(
            (63 - masterkey.scrypt_cost_param.leading_zeros()).try_into()?,
            masterkey.scrypt_block_size,
            1,
            32,
        )?,
        &mut buf,
    )?;
    let kek = Kek::try_from(buf)?;

    let mut buf = [0; 32];
    kek.unwrap(&masterkey.primary_master_key, &mut buf).unwrap();
    let primary_master = buf;
    kek.unwrap(&masterkey.hmac_master_key, &mut buf).unwrap();
    let mac_master = buf;

    let mut valid = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::HS256);
    valid.required_spec_claims.remove("exp");
    valid.set_required_spec_claims(&["kid", "alg", "typ"]);
    jsonwebtoken::decode::<Claims>(
        &VAULT_JWT,
        &jsonwebtoken::DecodingKey::from_secret(&[primary_master, mac_master].concat()),
        &valid,
    )
    .unwrap();

    // file header decrypt
    let cipher = Aes256Gcm::new((&primary_master).into());

    let mut file = File::open("/Users/hnakano/cryptomator-rs/test/d/2K/723QQ6QB7BXDSTL4RSAGGVO6FLRVNB/_Z61vxqh9srCKQxEHS6hM7OFPZnfPNAwOfDCRtaUS9td3lymVbHGJ_N2oBPE.c9r")?;

    let mut header_nonce = [0; 12];
    let mut header_payload = [0; 40];
    let mut header_tag = [0; 16];
    file.read_exact(&mut header_nonce)?;
    file.read_exact(&mut header_payload)?;
    file.read_exact(&mut header_tag)?;
    cipher
        .decrypt_in_place_detached(
            (&header_nonce).into(),
            b"",
            &mut header_payload,
            (&header_tag).into(),
        )
        .unwrap();
    ensure!(header_payload[..8] == [u8::MAX; 8], "aaa");
    let content_key: [u8; 32] = header_payload[8..].try_into()?;

    // file body decrypt
    let cipher = Aes256Gcm::new((&content_key).into());
    let mut buf = [0; 12 + 32 * 1024 + 16];
    let mut chunk_num = 0;

    let mut chunk_add_buf = [0; 20];
    let mut chunk_nonce_buf = [0; 12];
    let mut chunk_tag_buf = [0; 16];

    chunk_add_buf[8..20].copy_from_slice(&header_nonce);

    while let Ok(n) = file.read(&mut buf) {
        if n == 0 {
            break;
        }
        ensure!(n > 12 + 16, "bbb");
        BigEndian::write_u64(&mut chunk_add_buf[0..8], chunk_num);
        chunk_nonce_buf.copy_from_slice(&buf[0..12]);
        chunk_tag_buf.copy_from_slice(&buf[(n - 16)..n]);
        cipher
            .decrypt_in_place_detached(
                (&chunk_nonce_buf).into(),
                &chunk_add_buf,
                &mut buf[12..(n - 16)],
                (&chunk_tag_buf).into(),
            )
            .unwrap();
        chunk_num += 1;
    }

    // file name decrypt
    let mut file_name = general_purpose::URL_SAFE_NO_PAD
        .decode("_Z61vxqh9srCKQxEHS6hM7OFPZnfPNAwOfDCRtaUS9td3lymVbHGJ_N2oBPE")?;
    let (siv_tag, file_name_body) = file_name.split_at_mut(16);
    let mut file_name_body: Vec<u8> = file_name_body.into();

    let mut cipher = Siv::<Aes256, Cmac<Aes256>>::new(
        (&<[u8; 64]>::try_from([mac_master, primary_master].concat()).unwrap()).into(),
    );
    let parent_dir_id = b"";
    cipher
        .decrypt_in_place_detached(
            [parent_dir_id],
            &mut file_name_body,
            (&<[u8; 16]>::try_from(siv_tag)?).into(),
        )
        .unwrap();
    println!("{:#?}", String::from_utf8(file_name_body));
    Ok(())
}
