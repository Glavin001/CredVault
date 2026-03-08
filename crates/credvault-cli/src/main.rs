use clap::{Parser, Subcommand};
use comfy_table::{presets::UTF8_FULL, Table};
use credvault_core::{BundleFormat, BundleOptions, CredentialFilter, CredentialType};
use secrecy::SecretString;
use std::path::PathBuf;

#[derive(Parser)]
#[command(
    name = "credvault",
    about = "Selective credential extraction & provisioning tool",
    version,
    long_about = "CredVault discovers credential stores on your machine, lets you select a subset,\nand packages them into an encrypted, portable bundle."
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Scan the system for credential sources (browsers, keychains, password managers)
    Scan,

    /// List credentials from all or specific sources
    List {
        /// Filter by source ID (comma-separated)
        #[arg(long)]
        source: Option<String>,

        /// Filter by domain (comma-separated, supports wildcards like *.aws.amazon.com)
        #[arg(long)]
        domain: Option<String>,

        /// Search across domain, username, and label
        #[arg(long)]
        search: Option<String>,

        /// Filter by credential type: password, cookie, api-key
        #[arg(long, name = "type")]
        cred_type: Option<String>,
    },

    /// Export selected credentials to a bundle
    Export {
        /// Credential IDs to export (comma-separated)
        #[arg(long)]
        ids: Option<String>,

        /// Export all credentials matching domain filter (comma-separated)
        #[arg(long)]
        domain: Option<String>,

        /// Export format: credvault, csv, env, agent-config
        #[arg(long, default_value = "credvault")]
        format: String,

        /// Output file path
        #[arg(short, long)]
        output: PathBuf,

        /// Bundle label
        #[arg(long, default_value = "CredVault Bundle")]
        label: String,

        /// Bundle expiry (e.g., "30d", "24h", "2026-04-01")
        #[arg(long)]
        expires: Option<String>,

        /// Read password from stdin (for non-interactive use)
        #[arg(long)]
        password_stdin: bool,
    },

    /// Read and display contents of a CredVault bundle
    Read {
        /// Path to the .credvault bundle file
        path: PathBuf,

        /// Read password from stdin
        #[arg(long)]
        password_stdin: bool,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive("credvault=info".parse().unwrap()),
        )
        .with_target(false)
        .init();

    let cli = Cli::parse();

    match cli.command {
        Commands::Scan => cmd_scan().await?,
        Commands::List {
            source,
            domain,
            search,
            cred_type,
        } => cmd_list(source, domain, search, cred_type).await?,
        Commands::Export {
            ids,
            domain,
            format,
            output,
            label,
            expires,
            password_stdin,
        } => {
            cmd_export(ids, domain, format, output, label, expires, password_stdin).await?;
        }
        Commands::Read {
            path,
            password_stdin,
        } => cmd_read(path, password_stdin)?,
    }

    Ok(())
}

async fn cmd_scan() -> anyhow::Result<()> {
    eprintln!("Scanning for credential sources...\n");

    let sources = credvault_core::discover_sources().await?;

    if sources.is_empty() {
        eprintln!("No credential sources found on this machine.");
        return Ok(());
    }

    println!("Sources found:");
    let mut table = Table::new();
    table
        .load_preset(UTF8_FULL)
        .set_header(vec!["Status", "ID", "Name", "Credentials"]);

    for source in &sources {
        let status = match source.status {
            credvault_core::SourceStatus::Accessible => "✓",
            credvault_core::SourceStatus::Locked => "🔒",
            credvault_core::SourceStatus::RequiresAuth => "🔑",
            credvault_core::SourceStatus::NotFound => "✗",
        };

        table.add_row(vec![
            status.to_string(),
            source.id.clone(),
            source.name.clone(),
            source
                .credential_count
                .map_or("?".to_string(), |c| c.to_string()),
        ]);
    }

    println!("{table}");

    let total: u32 = sources.iter().filter_map(|s| s.credential_count).sum();
    println!(
        "\n  {} sources, ~{} credentials (some may be duplicates)",
        sources.len(),
        total
    );

    Ok(())
}

async fn cmd_list(
    source: Option<String>,
    domain: Option<String>,
    search: Option<String>,
    cred_type: Option<String>,
) -> anyhow::Result<()> {
    let source_ids: Option<Vec<String>> =
        source.map(|s| s.split(',').map(|s| s.trim().to_string()).collect());

    let filter = CredentialFilter {
        domains: domain.map(|d| d.split(',').map(|s| s.trim().to_string()).collect()),
        sources: source_ids,
        types: cred_type.map(|t| {
            t.split(',')
                .filter_map(|s| match s.trim().to_lowercase().as_str() {
                    "password" => Some(CredentialType::Password),
                    "cookie" => Some(CredentialType::Cookie),
                    "api-key" | "apikey" => Some(CredentialType::ApiKey),
                    "certificate" | "cert" => Some(CredentialType::Certificate),
                    "session" | "session-token" => Some(CredentialType::SessionToken),
                    _ => None,
                })
                .collect()
        }),
        search,
    };

    let index = credvault_core::list_credentials(
        None,
        Some(&filter),
    )
    .await?;

    if index.entries.is_empty() {
        eprintln!("No credentials found matching your filters.");
        return Ok(());
    }

    let mut table = Table::new();
    table
        .load_preset(UTF8_FULL)
        .set_header(vec!["ID", "Domain", "Username", "Source"]);

    for entry in &index.entries {
        table.add_row(vec![
            entry.id.clone(),
            entry.domain.clone(),
            entry.username.clone().unwrap_or_default(),
            entry.source_id.clone(),
        ]);
    }

    println!("{table}");
    println!("\n  {} credentials found", index.entries.len());

    if !index.duplicates.is_empty() {
        println!(
            "  {} duplicate groups detected",
            index.duplicates.len()
        );
        for dup in &index.duplicates {
            println!(
                "    ↳ {}{}: {:?}",
                dup.domain,
                dup.username
                    .as_ref()
                    .map_or(String::new(), |u| format!(" ({u})")),
                dup.entry_ids
            );
        }
    }

    Ok(())
}

async fn cmd_export(
    ids: Option<String>,
    domain: Option<String>,
    format_str: String,
    output: PathBuf,
    label: String,
    expires: Option<String>,
    password_stdin: bool,
) -> anyhow::Result<()> {
    let format: BundleFormat = format_str
        .parse()
        .map_err(|e: String| anyhow::anyhow!(e))?;

    // Get the password for the bundle
    let password = if format == BundleFormat::CredVault {
        if password_stdin {
            let mut pw = String::new();
            std::io::Read::read_to_string(&mut std::io::stdin(), &mut pw)?;
            SecretString::from(pw.trim().to_string())
        } else {
            let pw = dialoguer::Password::new()
                .with_prompt("Enter bundle password")
                .with_confirmation("Confirm password", "Passwords don't match")
                .interact()?;
            SecretString::from(pw)
        }
    } else {
        // Non-encrypted formats don't need a password
        if format == BundleFormat::Csv {
            eprintln!("⚠ WARNING: CSV format is plaintext. Passwords will not be encrypted.");
        }
        SecretString::from(String::new())
    };

    // Determine which credentials to export
    let credentials = if let Some(ref ids_str) = ids {
        let entry_ids: Vec<&str> = ids_str.split(',').map(|s| s.trim()).collect();
        credvault_core::extract_credentials(&entry_ids).await?
    } else if domain.is_some() {
        // List + filter by domain, then extract all matches
        let filter = CredentialFilter {
            domains: domain.map(|d| d.split(',').map(|s| s.trim().to_string()).collect()),
            ..Default::default()
        };
        let index = credvault_core::list_credentials(None, Some(&filter)).await?;
        let entry_ids: Vec<&str> = index.entries.iter().map(|e| e.id.as_str()).collect();
        if entry_ids.is_empty() {
            anyhow::bail!("No credentials found matching domain filter");
        }
        credvault_core::extract_credentials(&entry_ids).await?
    } else {
        anyhow::bail!("Specify --ids or --domain to select credentials for export");
    };

    // Parse expiry
    let expires = expires
        .map(|e| parse_expiry(&e))
        .transpose()?;

    let options = BundleOptions {
        format,
        password,
        label: label.clone(),
        expires,
        include_metadata: true,
    };

    let bundle_data = credvault_core::create_bundle(&credentials, &options)?;
    std::fs::write(&output, &bundle_data)?;

    eprintln!(
        "✓ Exported {} credentials to {}",
        credentials.len(),
        output.display()
    );
    if let Some(exp) = options.expires {
        eprintln!("  Expires: {}", exp.to_rfc3339());
    }

    Ok(())
}

fn cmd_read(path: PathBuf, password_stdin: bool) -> anyhow::Result<()> {
    let data = std::fs::read(&path)?;

    let password = if password_stdin {
        let mut pw = String::new();
        std::io::Read::read_to_string(&mut std::io::stdin(), &mut pw)?;
        SecretString::from(pw.trim().to_string())
    } else {
        let pw = dialoguer::Password::new()
            .with_prompt("Enter bundle password")
            .interact()?;
        SecretString::from(pw)
    };

    let contents = credvault_core::read_bundle(&data, &password)?;

    println!("Bundle: \"{}\" (ID: {})", contents.label, contents.bundle_id);
    println!("  Created: {}", contents.created.to_rfc3339());
    if let Some(exp) = contents.expires {
        println!("  Expires: {}", exp.to_rfc3339());
    }
    println!();

    let mut table = Table::new();
    table
        .load_preset(UTF8_FULL)
        .set_header(vec!["#", "Domain", "Username", "Type"]);

    for (i, cred) in contents.credentials.iter().enumerate() {
        table.add_row(vec![
            (i + 1).to_string(),
            cred.domain.clone(),
            cred.username.clone().unwrap_or_default(),
            format!("{:?}", cred.credential_type),
        ]);
    }

    println!("{table}");
    println!("\n  {} credentials in bundle", contents.credentials.len());

    Ok(())
}

fn parse_expiry(s: &str) -> anyhow::Result<chrono::DateTime<chrono::Utc>> {
    use chrono::{Duration, Utc};

    // Try duration format: "30d", "24h"
    if let Some(days) = s.strip_suffix('d') {
        let d: i64 = days.parse()?;
        return Ok(Utc::now() + Duration::days(d));
    }
    if let Some(hours) = s.strip_suffix('h') {
        let h: i64 = hours.parse()?;
        return Ok(Utc::now() + Duration::hours(h));
    }

    // Try ISO 8601 / RFC 3339
    if let Ok(dt) = chrono::DateTime::parse_from_rfc3339(s) {
        return Ok(dt.with_timezone(&Utc));
    }

    // Try date-only format
    if let Ok(date) = chrono::NaiveDate::parse_from_str(s, "%Y-%m-%d") {
        let dt = date
            .and_hms_opt(23, 59, 59)
            .unwrap()
            .and_utc();
        return Ok(dt);
    }

    anyhow::bail!("Could not parse expiry: '{s}'. Use formats like '30d', '24h', '2026-04-01', or RFC 3339.")
}
