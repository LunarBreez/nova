//! Écriture et relecture d'un relevé.
//!
//! Un relevé tient en un ou deux fichiers voisins :
//!
//! - `<date>_<machine>.cbom.json` : le relevé ;
//! - `<date>_<machine>.files.jsonl` : la liste des empreintes, une ligne JSON
//!   par fichier, que le relevé référence et scelle par son SHA-256.

use std::fs;
use std::path::{Path, PathBuf};

use crate::collect::Collected;
use crate::error::{Context, Error, Result};
use crate::files::sha256_file;
use crate::model::{Cbom, FORMAT, FileInventory};

/// Fichiers écrits pour un relevé.
#[derive(Debug, Clone)]
pub struct Written {
    /// Le relevé.
    pub cbom: PathBuf,
    /// La liste des empreintes, si elle a été relevée.
    pub files: Option<PathBuf>,
}

/// Réduit un nom à ce qu'un nom de fichier accepte partout.
fn file_stem_part(value: &str) -> String {
    let cleaned: String = value
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '-' | '.') {
                c
            } else {
                '-'
            }
        })
        .collect();
    let cleaned = cleaned.trim_matches(|c| c == '-' || c == '.');
    if cleaned.is_empty() {
        "machine".into()
    } else {
        cleaned.to_owned()
    }
}

/// Base du nom des fichiers d'un relevé : `<AAAAMMJJ>_<identifiant ou nom d'hôte>`.
pub fn base_name(cbom: &Cbom) -> String {
    let date: String = cbom
        .collection
        .started_at
        .chars()
        .filter(char::is_ascii_digit)
        .take(8)
        .collect();
    let machine = cbom.asset.id.as_deref().unwrap_or(&cbom.asset.hostname);
    format!("{date}_{}", file_stem_part(machine))
}

/// Déplace un fichier ; le copie si la destination est sur un autre disque.
fn move_file(from: &Path, to: &Path) -> Result<()> {
    if fs::rename(from, to).is_ok() {
        return Ok(());
    }
    fs::copy(from, to).context(|| format!("écriture de {}", to.display()))?;
    let _ = fs::remove_file(from);
    Ok(())
}

/// Écrit un relevé dans un répertoire et rend les fichiers créés.
///
/// La liste des empreintes, déjà écrite pendant le parcours, prend ici son
/// nom définitif ; la rubrique `files` du relevé la référence et la scelle.
pub fn write(directory: &Path, collected: Collected) -> Result<(Cbom, Written)> {
    let Collected { mut cbom, scan } = collected;
    fs::create_dir_all(directory).context(|| format!("création de {}", directory.display()))?;
    let base = base_name(&cbom);

    let mut files_path = None;
    if let Some(scan) = scan {
        let name = format!("{base}.files.jsonl");
        let path = directory.join(&name);
        move_file(&scan.list, &path)?;
        let text = |path: &PathBuf| path.to_string_lossy().into_owned();
        cbom.files = Some(FileInventory {
            path: name,
            sha256: scan.sha256,
            root: text(&scan.options.root),
            excluded: scan.options.excluded.iter().map(text).collect(),
            one_file_system: scan.options.one_file_system,
            skipped_mounts: scan.skipped_mounts,
            sparse_limit: scan.options.sparse_limit,
            algorithm: "sha256".into(),
            entries: scan.entries,
            unreadable: scan.unreadable,
            sparse_skipped: scan.sparse_skipped,
            total_bytes: scan.total_bytes,
        });
        files_path = Some(path);
    }

    let mut text = serde_json::to_string_pretty(&cbom).context(|| "relevé".into())?;
    text.push('\n');
    let cbom_path = directory.join(format!("{base}.cbom.json"));
    fs::write(&cbom_path, text).context(|| format!("écriture de {}", cbom_path.display()))?;
    Ok((
        cbom,
        Written {
            cbom: cbom_path,
            files: files_path,
        },
    ))
}

/// Relit un relevé et refuse ce qui n'en est pas un.
pub fn read(path: &Path) -> Result<Cbom> {
    let text = fs::read_to_string(path).context(|| format!("lecture de {}", path.display()))?;
    let cbom: Cbom = serde_json::from_str(&text)
        .context(|| format!("{} n'est pas un relevé Nova", path.display()))?;
    if cbom.format != FORMAT {
        return Err(Error::new(format!(
            "{} : format « {} » inattendu, « {FORMAT} » attendu",
            path.display(),
            cbom.format
        )));
    }
    let major = cbom.format_version.split('.').next().unwrap_or_default();
    if major != "1" {
        return Err(Error::new(format!(
            "{} : version de format {} non prise en charge par cette version de Nova",
            path.display(),
            cbom.format_version
        )));
    }
    Ok(cbom)
}

/// Vérifie que la liste des empreintes voisine d'un relevé est bien celle
/// qu'il scelle. Rend le nombre de lignes vérifiées.
pub fn verify_files(cbom_path: &Path, cbom: &Cbom) -> Result<u64> {
    let Some(inventory) = &cbom.files else {
        return Err(Error::new(
            "ce relevé ne référence aucune liste d'empreintes",
        ));
    };
    let path = cbom_path
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join(&inventory.path);
    let actual = sha256_file(&path).context(|| format!("lecture de {}", path.display()))?;
    if actual != inventory.sha256 {
        return Err(Error::new(format!(
            "{} ne correspond pas au relevé : SHA-256 {actual}, attendu {}",
            path.display(),
            inventory.sha256
        )));
    }
    Ok(inventory.entries)
}
