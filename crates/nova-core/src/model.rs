//! Le format du relevé CBOM de Nova.
//!
//! Un relevé décrit **une** machine : ce qu'elle est (matériel, firmware,
//! système, logiciels) et comment elle est configurée (réseau, services,
//! comptes). La liste des empreintes de fichiers, qui peut compter des
//! centaines de milliers de lignes, vit dans un fichier voisin que le relevé
//! référence et scelle par son SHA-256.
//!
//! Trois règles tiennent le format :
//!
//! - **les données brutes d'abord** : éditeur, produit et version sont
//!   toujours écrits tels que la machine les déclare ; les identifiants
//!   normalisés (PURL, CPE) s'y ajoutent sans les remplacer ;
//! - **un identifiant dit d'où il vient** : calculé, déclaré par le système,
//!   ou simple candidat à confirmer contre une base de vulnérabilités ;
//! - **une valeur inconnue est absente**, jamais une chaîne vide.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// Nom du format, première clé de tout relevé.
pub const FORMAT: &str = "nova-cbom";

/// Version du format. Le premier nombre change quand un lecteur existant ne
/// peut plus lire le relevé ; le second quand des champs s'ajoutent.
pub const FORMAT_VERSION: &str = "1.1";

/// Un relevé CBOM : l'état d'une machine à un instant donné.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct Cbom {
    /// Toujours `nova-cbom`.
    pub format: String,
    /// Version du format, par exemple `1.1`.
    pub format_version: String,
    /// Comment, quand et par quoi le relevé a été produit.
    pub collection: Collection,
    /// La machine relevée.
    pub asset: Asset,
    /// Matériel.
    pub hardware: Hardware,
    /// Firmware et démarrage.
    pub firmware: FirmwareSection,
    /// Système d'exploitation.
    pub operating_system: OperatingSystem,
    /// Logiciels installés.
    pub software: Vec<Software>,
    /// Interfaces réseau et ports à l'écoute.
    pub network: Network,
    /// Services déclarés au gestionnaire de services.
    pub services: Vec<Service>,
    /// Comptes locaux.
    pub accounts: Vec<Account>,
    /// Référence vers la liste des empreintes de fichiers, si elle a été relevée.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub files: Option<FileInventory>,
}

/// Provenance du relevé.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct Collection {
    /// L'outil qui a produit le relevé.
    pub tool: Tool,
    /// Comment les informations ont été obtenues.
    pub method: Method,
    /// Début du relevé, RFC 3339 en UTC.
    pub started_at: String,
    /// Fin du relevé, RFC 3339 en UTC.
    pub ended_at: String,
    /// Le relevé a-t-il été fait avec les droits d'administration ? Sans eux,
    /// certaines informations manquent : voir `warnings`.
    pub privileged: bool,
    /// Personne qui a fait le relevé, si elle s'est déclarée.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub operator: Option<String>,
    /// Ce que le relevé n'a pas pu lire. Un relevé sans avertissement est complet.
    pub warnings: Vec<Warning>,
}

/// Outil à l'origine d'un relevé.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct Tool {
    /// Nom de l'outil.
    pub name: String,
    /// Version de l'outil.
    pub version: String,
}

/// Manière dont les informations d'un relevé ont été obtenues.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum Method {
    /// Mesurées sur la machine par un collecteur.
    Measured,
    /// Reprises de fichiers extraits de l'équipement.
    Imported,
    /// Saisies par une personne.
    Declared,
}

/// Information que le relevé n'a pas pu obtenir.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct Warning {
    /// Rubrique concernée, par exemple `hardware` ou `network`.
    pub section: String,
    /// Ce qui manque et pourquoi.
    pub message: String,
}

/// Identité de la machine relevée.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct Asset {
    /// Identifiant d'inventaire donné par l'organisation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    /// Nom d'hôte.
    pub hostname: String,
    /// Site ou installation où se trouve la machine.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub site: Option<String>,
}

/// Identifiant normalisé d'un composant.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct Identifier {
    /// Famille de l'identifiant.
    pub scheme: Scheme,
    /// L'identifiant lui-même.
    pub value: String,
    /// D'où vient l'identifiant, donc quelle confiance lui accorder.
    pub origin: Origin,
}

/// Famille d'un identifiant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum Scheme {
    /// Package URL.
    Purl,
    /// Common Platform Enumeration.
    Cpe,
}

/// Origine d'un identifiant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum Origin {
    /// Construit mécaniquement depuis le gestionnaire de paquets : exact.
    Computed,
    /// Écrit par le système lui-même : exact.
    Declared,
    /// Deviné depuis l'éditeur, le produit et la version : à confirmer.
    Candidate,
}

/// Matériel de la machine.
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize, JsonSchema)]
pub struct Hardware {
    /// Le châssis ou la carte, tel que le constructeur le déclare.
    pub machine: Machine,
    /// Processeurs, regroupés par modèle.
    pub processors: Vec<Processor>,
    /// Mémoire vive totale, en octets.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub memory_bytes: Option<u64>,
    /// Disques.
    pub disks: Vec<Disk>,
}

/// Constructeur et modèle de la machine.
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize, JsonSchema)]
pub struct Machine {
    /// Constructeur.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vendor: Option<String>,
    /// Modèle.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,
    /// Version ou révision du modèle.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    /// Numéro de série.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub serial: Option<String>,
    /// Constructeur de la carte mère.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub board_vendor: Option<String>,
    /// Modèle de la carte mère.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub board_model: Option<String>,
    /// Identifiants normalisés.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub identifiers: Vec<Identifier>,
}

/// Un modèle de processeur et le nombre de cœurs logiques qui le portent.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct Processor {
    /// Constructeur.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vendor: Option<String>,
    /// Modèle.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,
    /// Architecture, par exemple `x86_64` ou `aarch64`.
    pub architecture: String,
    /// Nombre de cœurs logiques de ce modèle.
    pub logical_cores: u32,
}

/// Un disque.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct Disk {
    /// Nom du périphérique, par exemple `sda`.
    pub name: String,
    /// Constructeur.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vendor: Option<String>,
    /// Modèle.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,
    /// Numéro de série.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub serial: Option<String>,
    /// Version du firmware du disque.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub firmware_version: Option<String>,
    /// Capacité, en octets.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub size_bytes: Option<u64>,
    /// Support amovible ?
    pub removable: bool,
}

/// Firmware et mode de démarrage.
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize, JsonSchema)]
pub struct FirmwareSection {
    /// Mode de démarrage.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub boot_mode: Option<BootMode>,
    /// Secure Boot actif ? Absent si le firmware ne le dit pas.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub secure_boot: Option<bool>,
    /// Firmwares relevés.
    pub components: Vec<Firmware>,
}

/// Mode de démarrage de la machine.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum BootMode {
    /// UEFI.
    Uefi,
    /// BIOS hérité.
    Legacy,
}

/// Un firmware.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct Firmware {
    /// Ce que le firmware pilote : `system` (BIOS ou UEFI), `cpu-microcode`.
    pub kind: String,
    /// Éditeur.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vendor: Option<String>,
    /// Version.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    /// Date de publication, telle que le firmware l'écrit.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub release_date: Option<String>,
    /// Identifiants normalisés.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub identifiers: Vec<Identifier>,
}

/// Système d'exploitation.
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize, JsonSchema)]
pub struct OperatingSystem {
    /// Famille : `linux`, `windows`, `macos`.
    pub family: String,
    /// Identifiant court de la distribution, par exemple `debian`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    /// Nom.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Version.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    /// Nom complet affichable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pretty_name: Option<String>,
    /// Version du noyau.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kernel_release: Option<String>,
    /// Détail de compilation du noyau.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kernel_version: Option<String>,
    /// Architecture.
    pub architecture: String,
    /// Identifiants normalisés.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub identifiers: Vec<Identifier>,
}

/// Un logiciel installé.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct Software {
    /// Nom.
    pub name: String,
    /// Version, telle que la source la donne.
    pub version: String,
    /// Éditeur ou mainteneur.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vendor: Option<String>,
    /// Architecture du paquet.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub architecture: Option<String>,
    /// D'où vient l'information : `dpkg`, `rpm`, `apk`, `pacman`.
    pub source: String,
    /// Identifiants normalisés.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub identifiers: Vec<Identifier>,
}

/// Réseau de la machine.
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize, JsonSchema)]
pub struct Network {
    /// Interfaces réseau.
    pub interfaces: Vec<Interface>,
    /// Ports sur lesquels la machine attend des connexions.
    pub listening_sockets: Vec<ListeningSocket>,
}

/// Une interface réseau.
///
/// Le couple (MAC, IP) est la clé qui rattache un relevé aux conversations
/// d'une matrice de flux LFMS.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct Interface {
    /// Nom de l'interface.
    pub name: String,
    /// Adresse MAC canonique : minuscules, séparées par `:`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mac: Option<String>,
    /// Nature de l'interface.
    pub kind: InterfaceKind,
    /// État opérationnel, tel que le système le donne.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state: Option<String>,
    /// MTU.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mtu: Option<u32>,
    /// Adresses IP portées par l'interface.
    pub addresses: Vec<Address>,
}

/// Nature d'une interface réseau.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum InterfaceKind {
    /// Adossée à un périphérique matériel.
    Physical,
    /// Sans périphérique : pont, `veth`, tunnel.
    Virtual,
    /// Boucle locale.
    Loopback,
}

/// Une adresse IP et son préfixe.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, JsonSchema)]
pub struct Address {
    /// Adresse sous forme canonique.
    pub ip: String,
    /// Longueur du préfixe.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prefix_length: Option<u8>,
}

/// Un port à l'écoute.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, JsonSchema)]
pub struct ListeningSocket {
    /// Protocole de transport.
    pub protocol: Transport,
    /// Adresse d'écoute ; `0.0.0.0` ou `::` pour toutes les interfaces.
    pub address: String,
    /// Port.
    pub port: u16,
    /// Processus qui tient le port, s'il a pu être retrouvé.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub process: Option<Process>,
}

/// Protocole de transport.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum Transport {
    /// TCP.
    Tcp,
    /// UDP.
    Udp,
}

/// Un processus.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, JsonSchema)]
pub struct Process {
    /// Identifiant du processus au moment du relevé.
    pub pid: u32,
    /// Nom court.
    pub name: String,
    /// Chemin de l'exécutable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub executable: Option<String>,
}

/// Un service.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct Service {
    /// Nom du service.
    pub name: String,
    /// Gestionnaire de services : `systemd`.
    pub manager: String,
    /// Mode de démarrage, tel que le gestionnaire le donne (`enabled`, `disabled`…).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub startup: Option<String>,
    /// Le service tournait-il au moment du relevé ?
    pub running: bool,
}

/// Un compte local.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct Account {
    /// Nom du compte.
    pub name: String,
    /// Identifiant numérique.
    pub uid: u32,
    /// Groupe principal.
    pub gid: u32,
    /// Répertoire personnel.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub home: Option<String>,
    /// Interpréteur de connexion.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub shell: Option<String>,
}

/// Référence vers la liste des empreintes de fichiers.
///
/// La liste est un fichier JSON Lines voisin du relevé : une ligne
/// [`FileEntry`] par fichier, triées par chemin.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct FileInventory {
    /// Nom du fichier de liste, relatif au relevé.
    pub path: String,
    /// SHA-256 du fichier de liste : le relevé scelle sa liste.
    pub sha256: String,
    /// Racine parcourue.
    pub root: String,
    /// Répertoires écartés du parcours.
    pub excluded: Vec<String>,
    /// Le parcours est-il resté sur le système de fichiers de la racine ?
    #[serde(default)]
    pub one_file_system: bool,
    /// Points de montage que le parcours n'a pas traversés.
    #[serde(default)]
    pub skipped_mounts: Vec<String>,
    /// Volume de vide, en octets, au-delà duquel un fichier creux est listé
    /// sans être lu ; absent si tous les fichiers creux ont été lus.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sparse_limit: Option<u64>,
    /// Algorithme des empreintes : `sha256`.
    pub algorithm: String,
    /// Nombre de fichiers listés.
    pub entries: u64,
    /// Nombre de fichiers listés sans empreinte, faute d'avoir pu les lire.
    pub unreadable: u64,
    /// Parmi eux, nombre de fichiers creux qui n'ont pas été lus.
    #[serde(default)]
    pub sparse_skipped: u64,
    /// Taille cumulée des fichiers lus, en octets.
    pub total_bytes: u64,
}

/// Une ligne de la liste des empreintes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct FileEntry {
    /// Chemin du fichier sur la machine.
    pub path: String,
    /// Taille en octets.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub size: Option<u64>,
    /// SHA-256 du contenu ; absent si le fichier n'a pas pu être lu.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,
    /// Raison pour laquelle le fichier n'a pas été lu : l'erreur du système,
    /// ou `sparse file, not read` pour un fichier creux au-delà de la limite.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}
