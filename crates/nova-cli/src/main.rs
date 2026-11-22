//! `nova` : relevé CBOM d'une machine, en ligne de commande.

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Args, Parser, Subcommand};
use nova_core::error::Context;
use nova_core::{Result, collect, cyclonedx, files, output};

/// Relevé CBOM (Cyber Bill of Materials) d'une machine, hors ligne.
#[derive(Parser)]
#[command(name = "nova", version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Relève la machine : matériel, firmware, système, logiciels, réseau,
    /// services, comptes et empreintes de tous les fichiers.
    Collect(CollectArgs),
    /// Exporte les composants d'un relevé au format CycloneDX 1.6.
    Export(ExportArgs),
    /// Vérifie qu'un relevé et sa liste d'empreintes vont ensemble.
    Verify {
        /// Le relevé (`*.cbom.json`).
        cbom: PathBuf,
    },
    /// Affiche le schéma JSON du format de relevé.
    Schema,
}

#[derive(Args)]
struct CollectArgs {
    /// Répertoire où écrire le relevé.
    #[arg(short, long, default_value = ".")]
    output: PathBuf,
    /// Identifiant d'inventaire de la machine.
    #[arg(long)]
    asset_id: Option<String>,
    /// Site ou installation où se trouve la machine.
    #[arg(long)]
    site: Option<String>,
    /// Personne qui fait le relevé.
    #[arg(long)]
    operator: Option<String>,
    /// Ne pas relever les empreintes de fichiers.
    #[arg(long)]
    no_files: bool,
    /// Racine des empreintes de fichiers.
    #[arg(long, default_value = "/", conflicts_with = "no_files")]
    files_root: PathBuf,
    /// Répertoire à écarter des empreintes ; peut être répété.
    #[arg(long, value_name = "RÉPERTOIRE", conflicts_with = "no_files")]
    exclude: Vec<PathBuf>,
    /// Nombre de fils de calcul des empreintes (par défaut : un par cœur).
    #[arg(long, conflicts_with = "no_files")]
    jobs: Option<usize>,
    /// Ne pas entrer dans les autres systèmes de fichiers montés sous la
    /// racine : partages réseau, disques externes.
    #[arg(short = 'x', long, conflicts_with = "no_files")]
    one_file_system: bool,
    /// Lire aussi les fichiers creux géants, au lieu de les lister sans
    /// empreinte au-delà de 1 Gio de vide.
    #[arg(long, conflicts_with = "no_files")]
    hash_sparse: bool,
    /// Racine du système à lire, pour relever une arborescence d'essai.
    #[arg(long, default_value = "/", hide = true)]
    sysroot: PathBuf,
}

#[derive(Args)]
struct ExportArgs {
    /// Format d'export.
    #[arg(value_enum)]
    format: ExportFormat,
    /// Le relevé (`*.cbom.json`).
    cbom: PathBuf,
    /// Fichier à écrire ; par défaut, à côté du relevé.
    #[arg(short, long)]
    output: Option<PathBuf>,
}

#[derive(Clone, Copy, clap::ValueEnum)]
enum ExportFormat {
    /// CycloneDX 1.6, en JSON.
    Cyclonedx,
}

fn run_collect(args: CollectArgs) -> Result<()> {
    let files = (!args.no_files).then(|| {
        let mut options = files::Options::for_root(&args.files_root);
        options.excluded.extend(args.exclude);
        if let Some(jobs) = args.jobs {
            options.jobs = jobs;
        }
        options.one_file_system = args.one_file_system;
        if args.hash_sparse {
            options.sparse_limit = None;
        }
        options
    });
    let options = collect::Options {
        sysroot: args.sysroot,
        asset_id: args.asset_id,
        site: args.site,
        operator: args.operator,
        files,
        work_dir: args.output.clone(),
    };
    eprintln!("Relevé en cours…");
    let collected = collect::collect(&options)?;
    let (cbom, written) = output::write(&args.output, collected)?;

    println!("Relevé écrit : {}", written.cbom.display());
    println!(
        "  {} logiciel(s), {} interface(s), {} port(s) à l'écoute, {} service(s), {} compte(s)",
        cbom.software.len(),
        cbom.network.interfaces.len(),
        cbom.network.listening_sockets.len(),
        cbom.services.len(),
        cbom.accounts.len(),
    );
    if let (Some(path), Some(inventory)) = (&written.files, &cbom.files) {
        println!("Empreintes écrites : {}", path.display());
        println!(
            "  {} fichier(s), dont {} sans empreinte ({} illisible(s), {} creux)",
            inventory.entries,
            inventory.unreadable,
            inventory.unreadable - inventory.sparse_skipped,
            inventory.sparse_skipped
        );
    }
    if !cbom.collection.warnings.is_empty() {
        println!("Avertissements :");
        for warning in &cbom.collection.warnings {
            println!("  [{}] {}", warning.section, warning.message);
        }
    }
    Ok(())
}

fn run_export(args: ExportArgs) -> Result<()> {
    let cbom = output::read(&args.cbom)?;
    let text = match args.format {
        ExportFormat::Cyclonedx => cyclonedx::export_json(&cbom)?,
    };
    let path = args.output.unwrap_or_else(|| {
        let name = args.cbom.file_name().unwrap_or_default().to_string_lossy();
        let stem = name.strip_suffix(".cbom.json").unwrap_or(&name);
        args.cbom.with_file_name(format!("{stem}.cdx.json"))
    });
    std::fs::write(&path, text).context(|| format!("écriture de {}", path.display()))?;
    println!("Export CycloneDX écrit : {}", path.display());
    Ok(())
}

fn run_verify(path: PathBuf) -> Result<()> {
    let cbom = output::read(&path)?;
    let entries = output::verify_files(&path, &cbom)?;
    println!("Liste d'empreintes conforme au relevé : {entries} fichier(s).");
    Ok(())
}

fn main() -> ExitCode {
    let result = match Cli::parse().command {
        Commands::Collect(args) => run_collect(args),
        Commands::Export(args) => run_export(args),
        Commands::Verify { cbom } => run_verify(cbom),
        Commands::Schema => {
            print!("{}", nova_core::json_schema());
            Ok(())
        }
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("nova : {error}");
            ExitCode::FAILURE
        }
    }
}
