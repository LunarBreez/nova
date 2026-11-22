//! Nova : relevé CBOM (Cyber Bill of Materials) d'une machine.
//!
//! - [`model`] : le format du relevé ;
//! - [`collect`] : les collecteurs, qui mesurent une machine ;
//! - [`files`] : les empreintes de tous les fichiers ;
//! - [`output`] : l'écriture et la relecture d'un relevé ;
//! - [`cyclonedx`] : l'export des composants au format CycloneDX ;
//! - [`identifiers`] : PURL et CPE.

pub mod collect;
pub mod cyclonedx;
pub mod error;
pub mod files;
pub mod identifiers;
pub mod model;
pub mod output;
pub mod time;

pub use error::{Error, Result};

/// Version de l'outil.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Schéma JSON du format de relevé, tel que cette version l'écrit.
pub fn json_schema() -> String {
    let schema = schemars::schema_for!(model::Cbom);
    let mut text = serde_json::to_string_pretty(&schema).unwrap_or_default();
    text.push('\n');
    text
}
