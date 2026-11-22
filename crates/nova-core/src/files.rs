//! Empreintes de tous les fichiers d'une arborescence.
//!
//! Le parcours ne suit aucun lien symbolique et ne lit que les fichiers
//! ordinaires. Un fichier illisible reste **listé**, sans empreinte et avec la
//! raison : une liste qui tairait ce qu'elle n'a pas pu lire ne prouverait rien.
//!
//! La liste est écrite **au fil de l'eau**, dans l'ordre des chemins : la
//! mémoire utilisée ne dépend pas du nombre de fichiers. L'ordre est celui
//! d'un parcours en profondeur où chaque répertoire est lu trié par nom ; il
//! est identique d'un relevé à l'autre tant que les fichiers ne changent pas.

use std::collections::BTreeMap;
use std::fs::{self, File};
use std::io::{BufWriter, IsTerminal, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{RecvTimeoutError, sync_channel};
use std::sync::{Arc, Condvar, Mutex, PoisonError};
use std::thread;
use std::time::{Duration, Instant};

use sha2::{Digest, Sha256};

use crate::error::{Context, Error, Result};
use crate::model::FileEntry;

/// Répertoires écartés par défaut, relatifs à la racine : des vues du noyau,
/// pas des fichiers.
pub const DEFAULT_EXCLUDED: [&str; 4] = ["proc", "sys", "dev", "run"];

/// Volume de vide au-delà duquel un fichier creux n'est pas lu : 1 Gio.
pub const DEFAULT_SPARSE_LIMIT: u64 = 1 << 30;

/// Raison écrite pour un fichier creux qui n'a pas été lu.
pub const SPARSE_NOT_READ: &str = "sparse file, not read";

/// Nombre d'entrées qui peuvent attendre leur tour d'écriture.
const WINDOW: u64 = 4096;

/// Ce qu'il faut parcourir.
#[derive(Debug, Clone)]
pub struct Options {
    /// Racine du parcours.
    pub root: PathBuf,
    /// Répertoires écartés, en chemins absolus.
    pub excluded: Vec<PathBuf>,
    /// Nombre de fils de calcul.
    pub jobs: usize,
    /// Ne pas entrer dans les autres systèmes de fichiers montés sous la
    /// racine (partages réseau, disques externes). Sans effet hors d'Unix.
    pub one_file_system: bool,
    /// Volume de vide, en octets, au-delà duquel un fichier creux est listé
    /// sans être lu ; `None` pour tout lire. La détection n'existe que sur
    /// Linux.
    pub sparse_limit: Option<u64>,
}

impl Options {
    /// Options par défaut pour une racine : vues du noyau écartées, un fil
    /// par cœur disponible, fichiers creux géants non lus.
    pub fn for_root(root: impl Into<PathBuf>) -> Self {
        let root = root.into();
        let excluded = DEFAULT_EXCLUDED.iter().map(|dir| root.join(dir)).collect();
        let jobs = thread::available_parallelism().map_or(1, usize::from);
        Self {
            root,
            excluded,
            jobs,
            one_file_system: false,
            sparse_limit: Some(DEFAULT_SPARSE_LIMIT),
        }
    }
}

/// Résultat d'un parcours : la liste est déjà écrite sur le disque.
#[derive(Debug, Clone)]
pub struct Scan {
    /// Les options du parcours.
    pub options: Options,
    /// Fichier où la liste a été écrite, une ligne JSON par fichier.
    pub list: PathBuf,
    /// SHA-256 de ce fichier.
    pub sha256: String,
    /// Nombre de fichiers listés.
    pub entries: u64,
    /// Nombre de fichiers listés sans empreinte.
    pub unreadable: u64,
    /// Parmi eux, nombre de fichiers creux qui n'ont pas été lus.
    pub sparse_skipped: u64,
    /// Taille cumulée des fichiers lus, en octets.
    pub total_bytes: u64,
    /// Répertoires qui n'ont pas pu être ouverts.
    pub unreadable_directories: Vec<String>,
    /// Points de montage qui n'ont pas été traversés.
    pub skipped_mounts: Vec<String>,
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

/// SHA-256 d'un fichier, lu par blocs.
pub fn sha256_file(path: &Path) -> std::io::Result<String> {
    let mut file = File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buffer = vec![0_u8; 1 << 20];
    loop {
        match file.read(&mut buffer) {
            Ok(0) => break,
            Ok(read) => hasher.update(&buffer[..read]),
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error),
        }
    }
    Ok(hex(hasher.finalize().as_slice()))
}

/// Identifiant du système de fichiers qui porte un chemin.
#[cfg(unix)]
fn device(path: &Path) -> Option<u64> {
    use std::os::unix::fs::MetadataExt;
    fs::symlink_metadata(path).ok().map(|meta| meta.dev())
}

/// Identifiant du système de fichiers : inconnu hors d'Unix.
#[cfg(not(unix))]
fn device(_path: &Path) -> Option<u64> {
    None
}

/// Sous-répertoires et fichiers ordinaires d'un répertoire, triés par nom.
/// Le booléen dit si l'entrée est un répertoire.
fn read_sorted(directory: &Path) -> Option<Vec<(PathBuf, bool)>> {
    let mut found = Vec::new();
    for entry in fs::read_dir(directory).ok()?.flatten() {
        let Ok(kind) = entry.file_type() else {
            continue;
        };
        if kind.is_dir() || kind.is_file() {
            found.push((entry.path(), kind.is_dir()));
        }
    }
    found.sort();
    Some(found)
}

/// Ce que le parcours a laissé de côté.
#[derive(Debug, Default)]
struct Walked {
    unreadable_directories: Vec<String>,
    skipped_mounts: Vec<String>,
}

/// Parcourt la racine en profondeur et remet chaque fichier ordinaire à
/// `emit`, dans l'ordre des chemins. S'arrête dès que `emit` rend `false`.
/// `list` est le fichier de liste en cours d'écriture : il n'est pas relevé.
fn walk(options: &Options, list: &Path, emit: &mut dyn FnMut(PathBuf) -> bool) -> Walked {
    let mut walked = Walked::default();
    let root_device = device(&options.root);
    let list = fs::canonicalize(list).unwrap_or_else(|_| list.to_path_buf());
    let mut stack = Vec::new();
    match read_sorted(&options.root) {
        Some(entries) => stack.push(entries.into_iter()),
        None => walked
            .unreadable_directories
            .push(options.root.to_string_lossy().into_owned()),
    }
    while let Some(top) = stack.last_mut() {
        let Some((path, is_directory)) = top.next() else {
            stack.pop();
            continue;
        };
        if !is_directory {
            let is_list = path.file_name() == list.file_name()
                && fs::canonicalize(&path).is_ok_and(|real| real == list);
            if !is_list && !emit(path) {
                break;
            }
            continue;
        }
        if options.excluded.contains(&path) {
            continue;
        }
        if options.one_file_system && device(&path) != root_device {
            walked
                .skipped_mounts
                .push(path.to_string_lossy().into_owned());
            continue;
        }
        match read_sorted(&path) {
            Some(entries) => stack.push(entries.into_iter()),
            None => walked
                .unreadable_directories
                .push(path.to_string_lossy().into_owned()),
        }
    }
    walked
}

/// Volume de vide d'un fichier creux, en octets ; le compte s'arrête dès que
/// `limit` est dépassée. Rend zéro si le système de fichiers ne sait pas dire
/// où sont les trous.
#[cfg(target_os = "linux")]
fn holes(file: &File, limit: u64) -> u64 {
    use nix::unistd::{Whence, lseek};
    use std::os::unix::fs::MetadataExt;

    let Ok(meta) = file.metadata() else {
        return 0;
    };
    let size = meta.len();
    // Un fichier dont tous les blocs sont alloués n'a pas de trou.
    if meta.blocks().saturating_mul(512) >= size {
        return 0;
    }
    let (mut position, mut holes) = (0_u64, 0_u64);
    while position < size && holes <= limit {
        let Ok(offset) = i64::try_from(position) else {
            break;
        };
        let Ok(data) = lseek(file, offset, Whence::SeekData) else {
            // Plus aucune donnée : le reste du fichier est un trou.
            holes += size - position;
            break;
        };
        let data = u64::try_from(data).unwrap_or(size).min(size);
        holes += data.saturating_sub(position);
        let Ok(offset) = i64::try_from(data) else {
            break;
        };
        let Ok(hole) = lseek(file, offset, Whence::SeekHole) else {
            break;
        };
        let hole = u64::try_from(hole).unwrap_or(size);
        if hole <= data {
            break;
        }
        position = hole;
    }
    let _ = lseek(file, 0, Whence::SeekSet);
    holes
}

/// Volume de vide d'un fichier creux : la détection n'existe que sur Linux.
#[cfg(not(target_os = "linux"))]
fn holes(_file: &File, _limit: u64) -> u64 {
    0
}

/// Calcule l'entrée d'un fichier. `read_bytes` avance au fil de la lecture.
fn hash_file(path: &Path, sparse_limit: Option<u64>, read_bytes: &AtomicU64) -> FileEntry {
    let display = path.to_string_lossy().into_owned();
    let failed = |reason: String| FileEntry {
        path: display.clone(),
        size: fs::symlink_metadata(path).ok().map(|m| m.len()),
        sha256: None,
        error: Some(reason),
    };
    let mut file = match File::open(path) {
        Ok(file) => file,
        Err(error) => return failed(error.kind().to_string()),
    };
    if let Some(limit) = sparse_limit
        && holes(&file, limit) > limit
    {
        return failed(SPARSE_NOT_READ.into());
    }
    let mut hasher = Sha256::new();
    let mut buffer = vec![0_u8; 1 << 20];
    let mut size = 0_u64;
    loop {
        match file.read(&mut buffer) {
            Ok(0) => break,
            Ok(read) => {
                hasher.update(&buffer[..read]);
                size += read as u64;
                read_bytes.fetch_add(read as u64, Ordering::Relaxed);
            }
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
            Err(error) => return failed(error.kind().to_string()),
        }
    }
    FileEntry {
        path: display,
        size: Some(size),
        sha256: Some(hex(hasher.finalize().as_slice())),
        error: None,
    }
}

/// Retient le parcours quand trop d'entrées attendent leur tour d'écriture :
/// un très gros fichier en cours de lecture ne doit pas laisser les entrées
/// suivantes s'accumuler en mémoire.
#[derive(Default)]
struct Gate {
    /// Nombre d'entrées écrites, et arrêt demandé.
    state: Mutex<(u64, bool)>,
    changed: Condvar,
}

impl Gate {
    /// Attend que l'entrée `sequence` puisse partir ; `false` si le parcours
    /// doit s'arrêter.
    fn wait_for(&self, sequence: u64) -> bool {
        let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        while !state.1 && sequence >= state.0 + WINDOW {
            state = self
                .changed
                .wait(state)
                .unwrap_or_else(PoisonError::into_inner);
        }
        !state.1
    }

    /// Une entrée de plus est écrite.
    fn advance(&self) {
        self.state.lock().unwrap_or_else(PoisonError::into_inner).0 += 1;
        self.changed.notify_all();
    }

    /// Arrête le parcours.
    fn stop(&self) {
        self.state.lock().unwrap_or_else(PoisonError::into_inner).1 = true;
        self.changed.notify_all();
    }
}

/// Octets occupés sur le système de fichiers de la racine.
// Les compteurs de statvfs font 32 bits sur les processeurs 32 bits.
#[cfg(target_os = "linux")]
#[allow(clippy::useless_conversion)]
fn used_bytes(root: &Path) -> Option<u64> {
    let stat = nix::sys::statvfs::statvfs(root).ok()?;
    let used = u64::from(stat.blocks()).checked_sub(u64::from(stat.blocks_free()))?;
    used.checked_mul(u64::from(stat.fragment_size()))
}

/// Octets occupés : inconnus hors de Linux.
#[cfg(not(target_os = "linux"))]
fn used_bytes(_root: &Path) -> Option<u64> {
    None
}

/// Un volume en gigaoctets, à la française.
fn gigabytes(bytes: u64) -> String {
    format!("{:.1} Go", bytes as f64 / 1e9).replace('.', ",")
}

/// Une durée arrondie, lisible.
fn rough_duration(seconds: f64) -> String {
    if seconds < 90.0 {
        format!("{} s", seconds.round().max(1.0))
    } else if seconds < 5400.0 {
        format!("{} min", (seconds / 60.0).round())
    } else {
        format!("{:.1} h", seconds / 3600.0).replace('.', ",")
    }
}

/// Avancement affiché pendant le parcours.
struct Progress {
    shown: bool,
    started: Instant,
    last: Instant,
    /// Volume occupé sur le système de fichiers de la racine.
    expected: Option<u64>,
}

impl Progress {
    fn start(root: &Path) -> Self {
        let shown = std::io::stderr().is_terminal();
        let expected = used_bytes(root);
        if shown && let Some(expected) = expected {
            eprintln!(
                "  empreintes : environ {} à lire sous {} ; la durée restante s'affiche \
                 après quelques secondes",
                gigabytes(expected),
                root.display()
            );
        }
        let now = Instant::now();
        Self {
            shown,
            started: now,
            last: now,
            expected,
        }
    }

    fn tick(&mut self, files: u64, bytes: u64) {
        if !self.shown || self.last.elapsed() < Duration::from_millis(200) {
            return;
        }
        self.last = Instant::now();
        let elapsed = self.started.elapsed().as_secs_f64();
        let mut line = format!("  empreintes : {files} fichiers, {} lus", gigabytes(bytes));
        if let Some(expected) = self.expected
            && elapsed >= 5.0
            && bytes > 0
            && expected > bytes
        {
            let remaining = (expected - bytes) as f64 / (bytes as f64 / elapsed);
            line.push_str(&format!(", reste environ {}", rough_duration(remaining)));
        }
        eprint!("\r{line:<78}");
        let _ = std::io::stderr().flush();
    }

    fn finish(&self, files: u64, bytes: u64) {
        if self.shown {
            let line = format!(
                "  empreintes : {files} fichiers, {} lus en {}",
                gigabytes(bytes),
                rough_duration(self.started.elapsed().as_secs_f64())
            );
            eprintln!("\r{line:<78}");
        }
    }
}

/// Parcourt la racine, calcule l'empreinte de chaque fichier et écrit la
/// liste dans `list` au fil de l'eau, une ligne JSON par fichier.
///
/// `list` peut se trouver sous la racine : il n'est pas relevé lui-même.
pub fn scan(options: &Options, list: &Path) -> Result<Scan> {
    if !options.root.is_dir() {
        return Err(Error::new(format!(
            "la racine des empreintes n'est pas un répertoire : {}",
            options.root.display()
        )));
    }
    let file = File::create(list).context(|| format!("création de {}", list.display()))?;
    let result = scan_into(options, list, BufWriter::new(file));
    if result.is_err() {
        let _ = fs::remove_file(list);
    }
    result
}

fn scan_into(options: &Options, list: &Path, mut out: BufWriter<File>) -> Result<Scan> {
    let gate = &Gate::default();
    let read_bytes = &AtomicU64::new(0);
    let jobs = options.jobs.max(1);
    let mut progress = Progress::start(&options.root);
    let mut hasher = Sha256::new();
    let (mut entries, mut unreadable, mut sparse_skipped, mut total_bytes) = (0_u64, 0, 0, 0);

    let (written, walked) = thread::scope(|scope| {
        let (path_tx, path_rx) = sync_channel::<(u64, PathBuf)>(1024);
        let (entry_tx, entry_rx) = sync_channel::<(u64, FileEntry)>(1024);

        let walker = scope.spawn(move || {
            let mut sequence = 0_u64;
            walk(options, list, &mut |path| {
                let sent = gate.wait_for(sequence) && path_tx.send((sequence, path)).is_ok();
                sequence += 1;
                sent
            })
        });

        // Les fils de calcul se partagent la file des chemins ; elle se ferme
        // quand le dernier s'arrête, ce qui libère le parcours.
        let path_rx = Arc::new(Mutex::new(path_rx));
        for _ in 0..jobs {
            let path_rx = Arc::clone(&path_rx);
            let entry_tx = entry_tx.clone();
            scope.spawn(move || {
                loop {
                    let job = match path_rx.lock() {
                        Ok(queue) => queue.recv(),
                        Err(_) => break,
                    };
                    let Ok((sequence, path)) = job else {
                        break;
                    };
                    let entry = hash_file(&path, options.sparse_limit, read_bytes);
                    if entry_tx.send((sequence, entry)).is_err() {
                        break;
                    }
                }
            });
        }
        drop(path_rx);
        drop(entry_tx);

        // Écriture dans l'ordre : les entrées arrivées en avance attendent.
        let mut write = || -> Result<()> {
            let mut waiting = BTreeMap::new();
            loop {
                match entry_rx.recv_timeout(Duration::from_millis(200)) {
                    Ok((sequence, entry)) => {
                        waiting.insert(sequence, entry);
                    }
                    Err(RecvTimeoutError::Timeout) => {}
                    Err(RecvTimeoutError::Disconnected) => break,
                }
                while let Some(entry) = waiting.remove(&entries) {
                    let mut line =
                        serde_json::to_string(&entry).context(|| "liste des empreintes".into())?;
                    line.push('\n');
                    out.write_all(line.as_bytes())
                        .context(|| format!("écriture de {}", list.display()))?;
                    hasher.update(line.as_bytes());
                    entries += 1;
                    if entry.sha256.is_some() {
                        total_bytes += entry.size.unwrap_or(0);
                    } else {
                        unreadable += 1;
                        if entry.error.as_deref() == Some(SPARSE_NOT_READ) {
                            sparse_skipped += 1;
                        }
                    }
                    gate.advance();
                }
                progress.tick(entries, read_bytes.load(Ordering::Relaxed));
            }
            if !waiting.is_empty() {
                return Err(Error::new("un fil de calcul d'empreintes s'est arrêté"));
            }
            out.flush()
                .context(|| format!("écriture de {}", list.display()))
        };
        let written = write();
        // Sur une erreur d'écriture, tout le monde doit s'arrêter.
        gate.stop();
        drop(entry_rx);
        (written, walker.join())
    });
    written?;
    let walked = walked.map_err(|_| Error::new("le parcours des fichiers s'est arrêté"))?;
    progress.finish(entries, total_bytes);

    Ok(Scan {
        options: options.clone(),
        list: list.to_path_buf(),
        sha256: hex(hasher.finalize().as_slice()),
        entries,
        unreadable,
        sparse_skipped,
        total_bytes,
        unreadable_directories: walked.unreadable_directories,
        skipped_mounts: walked.skipped_mounts,
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

    fn entries(scan: &Scan) -> Vec<FileEntry> {
        fs::read_to_string(&scan.list)
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect()
    }

    fn names(root: &Path, entries: &[FileEntry]) -> Vec<String> {
        entries
            .iter()
            .map(|e| {
                e.path
                    .trim_start_matches(root.to_str().unwrap())
                    .replace('\\', "/")
            })
            .collect()
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

        // La liste est écrite sous la racine : elle ne doit pas se relever.
        let scan = scan(&Options::for_root(&root), &root.join("list.jsonl")).unwrap();
        let entries = entries(&scan);
        assert_eq!(names(&root, &entries), ["/etc/a.conf", "/etc/b.conf"]);
        assert_eq!(
            entries[0].sha256.as_deref(),
            Some("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
        );
        assert_eq!(
            entries[1].sha256.as_deref(),
            Some("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
        );
        assert_eq!(entries[1].size, Some(3));
        assert_eq!((scan.entries, scan.unreadable, scan.total_bytes), (2, 0, 3));
        assert_eq!(scan.sha256, sha256_file(&scan.list).unwrap());
        fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn writes_many_files_in_path_order_whatever_the_thread_count() {
        let root = temp_dir("order");
        let mut expected = Vec::new();
        for directory in ["a", "a.b", "a/c", "b"] {
            fs::create_dir_all(root.join(directory)).unwrap();
            for index in 0..300 {
                let path = root.join(directory).join(format!("f{index:03}"));
                fs::write(&path, format!("{directory}{index}")).unwrap();
                expected.push(path);
            }
        }
        expected.sort();
        let expected: Vec<_> = expected
            .iter()
            .map(|path| path.to_string_lossy().into_owned())
            .collect();

        let list = temp_dir("order-out").join("list.jsonl");
        let mut sums = Vec::new();
        for jobs in [1, 8] {
            let mut options = Options::for_root(&root);
            options.jobs = jobs;
            let scan = scan(&options, &list).unwrap();
            let paths: Vec<_> = entries(&scan).into_iter().map(|e| e.path).collect();
            assert_eq!(paths, expected);
            sums.push(scan.sha256);
        }
        assert_eq!(sums[0], sums[1]);
        fs::remove_dir_all(&root).unwrap();
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn lists_a_huge_sparse_file_without_reading_it() {
        let root = temp_dir("sparse");
        // 1 To annoncé, quelques octets écrits : comme `/var/log/lastlog`.
        let file = File::create(root.join("lastlog")).unwrap();
        file.set_len(1 << 40).unwrap();
        fs::write(root.join("small"), "abc").unwrap();
        let list = temp_dir("sparse-out").join("list.jsonl");

        let started = Instant::now();
        let scan = scan(&Options::for_root(&root), &list).unwrap();
        assert!(started.elapsed() < Duration::from_secs(20));
        let entries = entries(&scan);
        // Certains systèmes de fichiers ne savent pas dire où sont les trous.
        if scan.sparse_skipped == 1 {
            assert_eq!(entries[0].size, Some(1 << 40));
            assert_eq!(entries[0].sha256, None);
            assert_eq!(entries[0].error.as_deref(), Some(SPARSE_NOT_READ));
            assert_eq!(scan.unreadable, 1);
        }
        assert!(entries[1].sha256.is_some());
        fs::remove_dir_all(&root).unwrap();
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn reads_a_sparse_file_under_the_limit() {
        let root = temp_dir("sparse-small");
        let file = File::create(root.join("holes")).unwrap();
        file.set_len(1 << 20).unwrap();
        let list = temp_dir("sparse-small-out").join("list.jsonl");
        let scan = scan(&Options::for_root(&root), &list).unwrap();
        assert_eq!(scan.sparse_skipped, 0);
        assert_eq!(entries(&scan)[0].size, Some(1 << 20));
        assert!(entries(&scan)[0].sha256.is_some());
        fs::remove_dir_all(&root).unwrap();
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn stays_on_one_file_system_when_asked() {
        // /proc est un autre système de fichiers que / sur toute machine Linux.
        if device(Path::new("/proc")) == device(Path::new("/")) {
            return;
        }
        let mut options = Options::for_root("/");
        // Tout est écarté sauf /proc, pour ne parcourir que lui.
        options.excluded = read_sorted(Path::new("/"))
            .unwrap()
            .into_iter()
            .filter(|(path, is_directory)| *is_directory && path != Path::new("/proc"))
            .map(|(path, _)| path)
            .collect();
        options.one_file_system = true;
        let walked = walk(&options, Path::new("/nonexistent"), &mut |_| true);
        assert_eq!(walked.skipped_mounts, ["/proc"]);
    }

    #[test]
    fn refuses_a_root_that_is_not_a_directory() {
        let missing = std::env::temp_dir().join("nova-files-does-not-exist");
        let list = std::env::temp_dir().join("nova-files-never.jsonl");
        assert!(scan(&Options::for_root(missing), &list).is_err());
    }
}
