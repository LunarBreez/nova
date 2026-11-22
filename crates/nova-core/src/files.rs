//! Empreintes de tous les fichiers d'une arborescence.
//!
//! Le parcours ne suit aucun lien symbolique et ne lit que les fichiers
//! ordinaires. Un fichier illisible reste **listé**, sans empreinte et avec la
//! raison : une liste qui tairait ce qu'elle n'a pas pu lire ne prouverait rien.
//! Le résultat est trié par chemin, donc identique d'un relevé à l'autre tant
//! que les fichiers ne changent pas.

use std::fs::{self, File};
use std::io::{IsTerminal, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::thread;
use std::time::Duration;

use sha2::{Digest, Sha256};

use crate::error::{Error, Result};
use crate::model::FileEntry;

/// Répertoires écartés par défaut, relatifs à la racine : des vues du noyau,
/// pas des fichiers.
pub const DEFAULT_EXCLUDED: [&str; 4] = ["proc", "sys", "dev", "run"];

/// Ce qu'il faut parcourir.
#[derive(Debug, Clone)]
pub struct Options {
    /// Racine du parcours.
    pub root: PathBuf,
    /// Répertoires écartés, en chemins absolus.
    pub excluded: Vec<PathBuf>,
    /// Nombre de fils de calcul.
    pub jobs: usize,
}

impl Options {
    /// Options par défaut pour une racine : vues du noyau écartées, un fil
    /// par cœur disponible.
    pub fn for_root(root: impl Into<PathBuf>) -> Self {
        let root = root.into();
        let excluded = DEFAULT_EXCLUDED.iter().map(|dir| root.join(dir)).collect();
        let jobs = thread::available_parallelism().map_or(1, usize::from);
        Self {
            root,
            excluded,
            jobs,
        }
    }
}

/// Résultat d'un parcours.
#[derive(Debug, Clone)]
pub struct Scan {
    /// Racine parcourue.
    pub root: PathBuf,
    /// Répertoires écartés.
    pub excluded: Vec<PathBuf>,
    /// Une entrée par fichier, triées par chemin.
    pub entries: Vec<FileEntry>,
    /// Répertoires qui n'ont pas pu être ouverts.
    pub unreadable_directories: Vec<String>,
}

/// Hexadécimal en minuscules.
pub fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

/// SHA-256 d'un bloc d'octets, en hexadécimal.
pub fn sha256_hex(bytes: &[u8]) -> String {
    hex(Sha256::digest(bytes).as_slice())
}

/// Liste les fichiers ordinaires sous la racine, sans suivre les liens.
fn walk(options: &Options) -> (Vec<PathBuf>, Vec<String>) {
    let mut files = Vec::new();
    let mut unreadable = Vec::new();
    let mut pending = vec![options.root.clone()];
    while let Some(directory) = pending.pop() {
        let entries = match fs::read_dir(&directory) {
            Ok(entries) => entries,
            Err(_) => {
                unreadable.push(directory.to_string_lossy().into_owned());
                continue;
            }
        };
        for entry in entries.flatten() {
            let Ok(kind) = entry.file_type() else {
                continue;
            };
            let path = entry.path();
            if kind.is_dir() {
                if !options.excluded.contains(&path) {
                    pending.push(path);
                }
            } else if kind.is_file() {
                files.push(path);
            }
        }
    }
    files.sort();
    unreadable.sort();
    (files, unreadable)
}

/// Calcule l'entrée d'un fichier.
fn hash_file(path: &Path) -> FileEntry {
    let display = path.to_string_lossy().into_owned();
    let failed = |error: std::io::Error| FileEntry {
        path: display.clone(),
        size: fs::symlink_metadata(path).ok().map(|m| m.len()),
        sha256: None,
        error: Some(error.kind().to_string()),
    };
    let mut file = match File::open(path) {
        Ok(file) => file,
        Err(error) => return failed(error),
    };
    let mut hasher = Sha256::new();
    let mut buffer = vec![0_u8; 1 << 20];
    let mut size = 0_u64;
    loop {
        match file.read(&mut buffer) {
            Ok(0) => break,
            Ok(read) => {
                hasher.update(&buffer[..read]);
                size += read as u64;
            }
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
            Err(error) => return failed(error),
        }
    }
    FileEntry {
        path: display,
        size: Some(size),
        sha256: Some(hex(hasher.finalize().as_slice())),
        error: None,
    }
}

/// Parcourt la racine et calcule l'empreinte de chaque fichier.
pub fn scan(options: &Options) -> Result<Scan> {
    if !options.root.is_dir() {
        return Err(Error::new(format!(
            "la racine des empreintes n'est pas un répertoire : {}",
            options.root.display()
        )));
    }
    let (paths, unreadable_directories) = walk(options);
    let total = paths.len();
    let next = AtomicUsize::new(0);
    let done = AtomicUsize::new(0);
    let show_progress = std::io::stderr().is_terminal();
    let jobs = options.jobs.max(1);

    let mut indexed: Vec<(usize, FileEntry)> = thread::scope(|scope| {
        let workers: Vec<_> = (0..jobs)
            .map(|_| {
                scope.spawn(|| {
                    let mut out = Vec::new();
                    loop {
                        let index = next.fetch_add(1, Ordering::Relaxed);
                        let Some(path) = paths.get(index) else {
                            break;
                        };
                        out.push((index, hash_file(path)));
                        done.fetch_add(1, Ordering::Relaxed);
                    }
                    out
                })
            })
            .collect();
        while show_progress && workers.iter().any(|worker| !worker.is_finished()) {
            eprint!(
                "\r  empreintes : {} / {total}",
                done.load(Ordering::Relaxed)
            );
            let _ = std::io::stderr().flush();
            thread::sleep(Duration::from_millis(200));
        }
        if show_progress {
            eprintln!("\r  empreintes : {total} / {total}");
        }
        let mut all = Vec::with_capacity(total);
        for worker in workers {
            match worker.join() {
                Ok(part) => all.extend(part),
                Err(_) => return Err(Error::new("un fil de calcul d'empreintes s'est arrêté")),
            }
        }
        Ok(all)
    })?;
    indexed.sort_by_key(|(index, _)| *index);

    Ok(Scan {
        root: options.root.clone(),
        excluded: options.excluded.clone(),
        entries: indexed.into_iter().map(|(_, entry)| entry).collect(),
        unreadable_directories,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("nova-files-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn hashes_files_sorted_and_skips_excluded_and_symlinks() {
        let root = temp_dir("scan");
        fs::create_dir_all(root.join("etc")).unwrap();
        fs::create_dir_all(root.join("proc")).unwrap();
        fs::write(root.join("etc/b.conf"), "abc").unwrap();
        fs::write(root.join("etc/a.conf"), "").unwrap();
        fs::write(root.join("proc/ignored"), "x").unwrap();
        #[cfg(unix)]
        std::os::unix::fs::symlink(root.join("etc/b.conf"), root.join("etc/link")).unwrap();

        let scan = scan(&Options::for_root(&root)).unwrap();
        let names: Vec<_> = scan
            .entries
            .iter()
            .map(|e| {
                e.path
                    .trim_start_matches(root.to_str().unwrap())
                    .replace('\\', "/")
            })
            .collect();
        assert_eq!(names, ["/etc/a.conf", "/etc/b.conf"]);
        assert_eq!(
            scan.entries[0].sha256.as_deref(),
            Some("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
        );
        assert_eq!(
            scan.entries[1].sha256.as_deref(),
            Some("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
        );
        assert_eq!(scan.entries[1].size, Some(3));
        fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn refuses_a_root_that_is_not_a_directory() {
        let missing = std::env::temp_dir().join("nova-files-does-not-exist");
        assert!(scan(&Options::for_root(missing)).is_err());
    }
}
