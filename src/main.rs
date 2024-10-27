use clap::Parser;
use clio::Input;
use std::str::FromStr;
use twofas_backup_decryptor::{EncryptedServices, Vault};

/// A program for decrypting 2FAS backups
#[derive(Parser, Debug)]
struct Arguments {
    /// File to decrypt
    #[clap(value_parser)]
    file: Input,
}

fn main() -> anyhow::Result<()> {
    let arguments = Arguments::parse();
    let Ok(vault) = serde_json::from_reader::<_, Vault>(arguments.file) else {
        anyhow::bail!("Invalid file format for backup");
    };
    let Ok(services) = EncryptedServices::from_str(&vault.services_encrypted) else {
        anyhow::bail!("Invalid format for encrypted services data")
    };
    let password = rpassword::prompt_password("Password: ")?;
    println!("{}", services.decrypt(&password)?);
    Ok(())
}
