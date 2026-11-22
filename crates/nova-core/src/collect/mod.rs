//! Collecteurs : ils mesurent une machine et rendent son relevé.

#[cfg(target_os = "linux")]
pub mod linux;
pub mod packages;

use std::path::PathBuf;

use crate::error::Result;
use crate::files;
use crate::model::Cbom;

/// Ce qu'il faut relever et sous quelle identité.
#[derive(Debug, Clone)]
pub struct Options {
    /// Racine du système à lire : `/` sur une vraie machine.
    pub sysroot: PathBuf,
    /// Identifiant d'inventaire de la machine.
    pub asset_id: Option<String>,
    /// Site où se trouve la machine.
    pub site: Option<String>,
    /// Personne qui fait le relevé.
    pub operator: Option<String>,
    /// Empreintes de fichiers à relever ; `None` pour s'en passer.
    pub files: Option<files::Options>,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            sysroot: PathBuf::from("/"),
            asset_id: None,
            site: None,
            operator: None,
            files: Some(files::Options::for_root("/")),
        }
    }
}

/// Un relevé et, si elles ont été demandées, ses empreintes de fichiers.
#[derive(Debug, Clone)]
pub struct Collected {
    /// Le relevé ; sa rubrique `files` est remplie à l'écriture.
    pub cbom: Cbom,
    /// Le parcours des fichiers.
    pub scan: Option<files::Scan>,
}

/// Relève la machine.
#[cfg(target_os = "linux")]
pub fn collect(options: &Options) -> Result<Collected> {
    use std::time::SystemTime;

    use crate::model::{Asset, Collection, FORMAT, FORMAT_VERSION, Method, Tool};
    use crate::time::Civil;
    use linux::{Sysroot, Warnings};

    let started_at = Civil::from_system(SystemTime::now()).rfc3339();
    let sysroot = Sysroot::new(&options.sysroot);
    let mut warnings = Warnings::default();
    let privileged = sysroot.is_live() && linux::is_privileged();
    if sysroot.is_live() && !privileged {
        warnings.push(
            "collection",
            "relevé sans droits d'administration : numéro de série, processus des autres \
             comptes et fichiers protégés peuvent manquer",
        );
    }

    let hostname = linux::hostname(&sysroot, &mut warnings);
    let operating_system = linux::operating_system(&sysroot, &mut warnings);
    let (hardware, firmware) =
        linux::hardware_and_firmware(&sysroot, &operating_system.architecture, &mut warnings);
    let software = linux::software(&sysroot, &operating_system, &mut warnings);
    let network = linux::network(&sysroot, &mut warnings);
    let services = linux::services(&sysroot, &mut warnings);
    let accounts = linux::accounts(&sysroot, &mut warnings);

    let scan = options.files.as_ref().map(files::scan).transpose()?;
    if let Some(scan) = &scan
        && let Some(first) = scan.unreadable_directories.first()
    {
        warnings.push(
            "files",
            format!(
                "{} répertoire(s) illisible(s), dont {first}",
                scan.unreadable_directories.len()
            ),
        );
    }

    let cbom = Cbom {
        format: FORMAT.into(),
        format_version: FORMAT_VERSION.into(),
        collection: Collection {
            tool: Tool {
                name: "nova".into(),
                version: crate::VERSION.into(),
            },
            method: Method::Measured,
            started_at,
            ended_at: Civil::from_system(SystemTime::now()).rfc3339(),
            privileged,
            operator: options.operator.clone(),
            warnings: warnings.0,
        },
        asset: Asset {
            id: options.asset_id.clone(),
            hostname,
            site: options.site.clone(),
        },
        hardware,
        firmware,
        operating_system,
        software,
        network,
        services,
        accounts,
        files: None,
    };
    Ok(Collected { cbom, scan })
}

/// Relève la machine : ce système n'a pas encore de collecteur.
#[cfg(not(target_os = "linux"))]
pub fn collect(_options: &Options) -> Result<Collected> {
    Err(crate::Error::new(format!(
        "le relevé n'est pas encore pris en charge sur {} ; seul Linux l'est dans cette version",
        std::env::consts::OS
    )))
}
