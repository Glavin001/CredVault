use std::sync::Arc;

use crate::{
    error::Result,
    types::{Credential, CredentialEntry, CredentialSource},
};

pub mod fixture;

pub trait SourceAdapter: Send + Sync {
    fn source(&self) -> &CredentialSource;
    fn list_credentials(&self) -> Result<Vec<CredentialEntry>>;
    fn extract_credentials(&self, entry_ids: &[String]) -> Result<Vec<Credential>>;
}

pub type DynSourceAdapter = Arc<dyn SourceAdapter>;
