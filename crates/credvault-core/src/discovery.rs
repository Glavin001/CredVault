//! Source discovery — scan the system for all available credential stores.

use crate::adapter::{self, SourceAdapter};
use crate::types::CredentialSource;
use crate::Result;

/// Scan the system for all available credential sources.
pub async fn scan_sources() -> Result<Vec<CredentialSource>> {
    let adapters = adapter::get_adapters();
    let mut sources = Vec::new();

    for adapter in &adapters {
        match adapter.detect() {
            Ok(detected) => {
                for d in detected {
                    tracing::info!("Found source: {} ({})", d.source.name, d.source.id);
                    sources.push(d.source);
                }
            }
            Err(e) => {
                tracing::warn!("Failed to detect source: {e}");
            }
        }
    }

    Ok(sources)
}

/// Scan using a specific set of adapters (for testing).
pub fn scan_with_adapters(adapters: &[Box<dyn SourceAdapter>]) -> Result<Vec<CredentialSource>> {
    let mut sources = Vec::new();

    for adapter in adapters {
        match adapter.detect() {
            Ok(detected) => {
                for d in detected {
                    sources.push(d.source);
                }
            }
            Err(e) => {
                tracing::warn!("Failed to detect source: {e}");
            }
        }
    }

    Ok(sources)
}
