# cryptomator-extractor-rs

## Note

This tool is a hobby program that I created to understand the encryption mechanism
of [Cryptomator](https://cryptomator.org/) and is NOT related to the
official Cryptomator project.

## Overview

`cryptomator-extractor` is a Rust-based tool designed for decrypting Cryptomator vaults.
Unlike the original Cryptomator, this tool does not provide a virtual file system.
Instead, it simply generates decrypted contents at the specified target path.

The decryption process is in accordance with the specifications of Cryptomator's Vault,
as outlined in the [official documentation](https://docs.cryptomator.org/en/latest/security/architecture/).

At this stage, it does not support symbolic links.

## Usage

Specify the root path of the vault, which is the directory where the vault.cryptomator file resides,
and then define the target path for decryption.
The decrypted contents of the vault will be generated inside the specified target directory.

```bash
cryptomator-extractor /path/to/vault target/path
```
