use std::{
    fs,
    io::{self, Read, Write},
    path::PathBuf,
};

use chrono::{DateTime, Utc};
use clap::{Parser, Subcommand, ValueEnum};
use credvault_core::{
    BundleFormat, BundleOptions, CredVault, CredentialFilter, CredentialType, Result,
};
use secrecy::SecretString;

#[derive(Debug, Parser)]
#[command(
    name = "credvault",
    version,
    about = "Safe MVP foundation for scoped credential bundle workflows"
)]
struct Cli {
    #[arg(long = "fixture-dir", global = true)]
    fixture_dir: Option<PathBuf>,
    #[arg(long = "chrome-csv", global = true)]
    chrome_csv: Vec<PathBuf>,
    #[arg(long = "bitwarden-json", global = true)]
    bitwarden_json: Vec<PathBuf>,
    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
    Scan,
    List {
        #[arg(long = "source")]
        sources: Vec<String>,
        #[arg(long = "domain")]
        domains: Vec<String>,
        #[arg(long = "search")]
        search: Option<String>,
        #[arg(long = "type")]
        types: Vec<CredentialTypeArg>,
        #[arg(long)]
        json: bool,
    },
    Export {
        #[arg(long = "id")]
        ids: Vec<String>,
        #[arg(long = "domain")]
        domains: Vec<String>,
        #[arg(long = "search")]
        search: Option<String>,
        #[arg(long = "source")]
        sources: Vec<String>,
        #[arg(long = "type")]
        types: Vec<CredentialTypeArg>,
        #[arg(long, value_enum)]
        format: BundleFormatArg,
        #[arg(long)]
        output: Option<PathBuf>,
        #[arg(long, default_value = "CredVault Bundle")]
        label: String,
        #[arg(long)]
        expires: Option<String>,
        #[arg(long)]
        password: Option<String>,
        #[arg(long)]
        password_stdin: bool,
    },
    Read {
        bundle: PathBuf,
        #[arg(long)]
        password: Option<String>,
        #[arg(long)]
        password_stdin: bool,
    },
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum CredentialTypeArg {
    Password,
    Cookie,
    ApiKey,
    Certificate,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum BundleFormatArg {
    Credvault,
    Csv,
    Env,
    AgentConfig,
}

fn main() {
    let cli = Cli::parse();
    if let Err(error) = run(cli) {
        eprintln!("error: {error}");
        std::process::exit(1);
    }
}

fn run(cli: Cli) -> Result<()> {
    let vault = if matches!(cli.command, Commands::Read { .. }) {
        None
    } else {
        Some(build_vault(&cli)?)
    };

    match cli.command {
        Commands::Scan => {
            let vault = vault.as_ref().expect("vault required for scan");
            let sources = vault.discover_sources();
            println!("Sources found:");
            for source in sources {
                let count = source
                    .credential_count
                    .map(|value| value.to_string())
                    .unwrap_or_else(|| "?".to_string());
                println!(
                    "  - {:<24} {:<32} {} credentials",
                    source.id, source.name, count
                );
            }
        }
        Commands::List {
            sources,
            domains,
            search,
            types,
            json,
        } => {
            let vault = vault.as_ref().expect("vault required for list");
            let filter = build_filter(domains, sources.clone(), types, search, None);
            let source_filter = if sources.is_empty() {
                None
            } else {
                Some(sources.as_slice())
            };
            let index = vault.list_credentials(source_filter, Some(&filter))?;

            if json {
                println!("{}", serde_json::to_string_pretty(&index)?);
                return Ok(());
            }

            println!(
                "{:<38} {:<24} {:<18} {}",
                "ID", "DOMAIN", "USERNAME", "SOURCE"
            );
            for entry in index.entries {
                println!(
                    "{:<38} {:<24} {:<18} {}",
                    entry.id,
                    entry.domain,
                    entry.username.unwrap_or_else(|| "-".to_string()),
                    entry.source_id
                );
            }
        }
        Commands::Export {
            ids,
            domains,
            search,
            sources,
            types,
            format,
            output,
            label,
            expires,
            password,
            password_stdin,
        } => {
            let vault = vault.as_ref().expect("vault required for export");
            let mut entry_ids = ids;
            if entry_ids.is_empty() {
                let filter = build_filter(domains, sources.clone(), types, search, None);
                let source_filter = if sources.is_empty() {
                    None
                } else {
                    Some(sources.as_slice())
                };
                let index = vault.list_credentials(source_filter, Some(&filter))?;
                entry_ids = index.entries.into_iter().map(|entry| entry.id).collect();
            }

            let credentials = vault.extract_credentials(&entry_ids)?;
            let bundle_options = BundleOptions {
                format: format.into(),
                password: resolve_password(format, password, password_stdin)?,
                label,
                expires: parse_expiry(expires.as_deref())?,
                include_metadata: true,
            };
            let artifact = vault.create_bundle(&credentials, &bundle_options)?;

            if let Some(output_path) = output {
                fs::write(&output_path, &artifact.bytes)?;
                println!(
                    "Exported {} credentials to {}",
                    credentials.len(),
                    output_path.display()
                );
            } else {
                io::stdout().write_all(&artifact.bytes)?;
            }
        }
        Commands::Read {
            bundle,
            password,
            password_stdin,
        } => {
            let data = fs::read(bundle)?;
            let password = resolve_password(BundleFormatArg::Credvault, password, password_stdin)?
                .expect("credvault read requires password");
            let contents = credvault_core::read_bundle(&data, &password)?;

            println!(
                "Bundle: \"{}\" (created {}, expires {})",
                contents.label,
                contents.created.to_rfc3339(),
                contents
                    .expires
                    .map(|value| value.to_rfc3339())
                    .unwrap_or_else(|| "never".to_string())
            );
            for credential in contents.credentials {
                println!(
                    "  - {:<24} {:<18} {}",
                    credential.entry.domain,
                    credential.entry.username.unwrap_or_else(|| "-".to_string()),
                    credential.entry.id
                );
            }
        }
    }

    Ok(())
}

fn build_vault(cli: &Cli) -> Result<CredVault> {
    let mut builder = CredVault::builder();

    if let Some(fixture_dir) = &cli.fixture_dir {
        builder = builder.with_fixture_dir(fixture_dir)?;
    }

    for path in &cli.chrome_csv {
        builder = builder.with_chrome_csv_export(path)?;
    }

    for path in &cli.bitwarden_json {
        builder = builder.with_bitwarden_json_export(path)?;
    }

    builder.build()
}

fn build_filter(
    domains: Vec<String>,
    sources: Vec<String>,
    types: Vec<CredentialTypeArg>,
    search: Option<String>,
    min_last_used: Option<DateTime<Utc>>,
) -> CredentialFilter {
    CredentialFilter {
        domains: (!domains.is_empty()).then_some(domains),
        sources: (!sources.is_empty()).then_some(sources),
        types: (!types.is_empty()).then_some(types.into_iter().map(Into::into).collect()),
        search,
        min_last_used,
    }
}

fn resolve_password(
    format: BundleFormatArg,
    password: Option<String>,
    password_stdin: bool,
) -> Result<Option<SecretString>> {
    if !matches!(format, BundleFormatArg::Credvault) {
        return Ok(password.map(into_secret));
    }

    if let Some(password) = password {
        return Ok(Some(into_secret(password)));
    }

    if password_stdin {
        let mut buffer = String::new();
        io::stdin().read_to_string(&mut buffer)?;
        return Ok(Some(into_secret(buffer.trim().to_string())));
    }

    print!("Enter bundle password: ");
    io::stdout().flush()?;
    let mut buffer = String::new();
    io::stdin().read_line(&mut buffer)?;
    let password = buffer.trim().to_string();
    if password.is_empty() {
        return Err(credvault_core::CredVaultError::MissingBundlePassword);
    }
    Ok(Some(into_secret(password)))
}

fn parse_expiry(expires: Option<&str>) -> Result<Option<DateTime<Utc>>> {
    expires
        .map(|value| {
            DateTime::parse_from_rfc3339(value)
                .map(|timestamp| timestamp.with_timezone(&Utc))
                .map_err(|error| credvault_core::CredVaultError::Serialization(error.to_string()))
        })
        .transpose()
}

fn into_secret(value: String) -> SecretString {
    SecretString::new(value.into_boxed_str())
}

impl From<CredentialTypeArg> for CredentialType {
    fn from(value: CredentialTypeArg) -> Self {
        match value {
            CredentialTypeArg::Password => CredentialType::Password,
            CredentialTypeArg::Cookie => CredentialType::Cookie,
            CredentialTypeArg::ApiKey => CredentialType::ApiKey,
            CredentialTypeArg::Certificate => CredentialType::Certificate,
        }
    }
}

impl From<BundleFormatArg> for BundleFormat {
    fn from(value: BundleFormatArg) -> Self {
        match value {
            BundleFormatArg::Credvault => BundleFormat::CredVault,
            BundleFormatArg::Csv => BundleFormat::Csv,
            BundleFormatArg::Env => BundleFormat::Env,
            BundleFormatArg::AgentConfig => BundleFormat::AgentConfig,
        }
    }
}
