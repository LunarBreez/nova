//! Collecteur Linux.
//!
//! Tout est lu dans `/proc`, `/sys` et `/etc`, sous une **racine système**
//! paramétrable : `/` sur une vraie machine, un répertoire d'essai dans les
//! tests. Seuls trois relevés sortent de ce cadre et n'ont lieu que sur une
//! vraie machine : les adresses IPv4 (`getifaddrs`), les paquets RPM et les
//! services systemd, dont les bases ne sont pas des fichiers texte.
//!
//! Le collecteur ne modifie rien et n'émet rien sur le réseau.

use std::collections::BTreeMap;
use std::fs;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::{Path, PathBuf};
use std::process::Command;

use super::packages::{self, Distro};
use crate::identifiers::{self, Part};
use crate::model::{
    Account, Address, BootMode, Disk, Firmware, FirmwareSection, Hardware, Interface,
    InterfaceKind, ListeningSocket, Machine, Network, OperatingSystem, Process, Processor, Service,
    Software, Transport, Warning,
};

/// Racine sous laquelle le système est lu.
#[derive(Debug, Clone)]
pub struct Sysroot(PathBuf);

impl Sysroot {
    /// Racine système à lire.
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self(root.into())
    }

    /// S'agit-il du système en cours d'exécution ?
    pub fn is_live(&self) -> bool {
        self.0 == Path::new("/")
    }

    /// Chemin réel d'un chemin absolu du système.
    pub fn path(&self, absolute: &str) -> PathBuf {
        self.0.join(absolute.trim_start_matches('/'))
    }

    /// Contenu texte d'un fichier, sans les blancs ni les octets nuls de fin ;
    /// `None` s'il est absent, illisible ou vide.
    pub fn read(&self, absolute: &str) -> Option<String> {
        let bytes = fs::read(self.path(absolute)).ok()?;
        let text = String::from_utf8_lossy(&bytes);
        let text = text.trim_matches(|c: char| c.is_whitespace() || c == '\0');
        (!text.is_empty()).then(|| text.to_owned())
    }

    /// Le fichier existe-t-il sans pouvoir être lu ?
    fn exists_unreadable(&self, absolute: &str) -> bool {
        let path = self.path(absolute);
        path.exists() && fs::read(path).is_err()
    }
}

/// Avertissements accumulés pendant le relevé.
#[derive(Debug, Default)]
pub struct Warnings(pub Vec<Warning>);

impl Warnings {
    /// Note qu'une information manque.
    pub fn push(&mut self, section: &str, message: impl Into<String>) {
        self.0.push(Warning {
            section: section.into(),
            message: message.into(),
        });
    }
}

/// Valeurs que les constructeurs laissent quand ils n'ont rien renseigné.
const PLACEHOLDERS: [&str; 12] = [
    "to be filled by o.e.m.",
    "default string",
    "not specified",
    "not applicable",
    "system product name",
    "system manufacturer",
    "system version",
    "system serial number",
    "none",
    "unknown",
    "n/a",
    "0",
];

/// Lit un champ déclaré par le constructeur, en écartant les valeurs de remplissage.
fn declared(sysroot: &Sysroot, path: &str) -> Option<String> {
    sysroot
        .read(path)
        .filter(|value| !PLACEHOLDERS.contains(&value.to_lowercase().as_str()))
}

/// Nom d'hôte.
pub fn hostname(sysroot: &Sysroot, warnings: &mut Warnings) -> String {
    sysroot
        .read("/proc/sys/kernel/hostname")
        .or_else(|| sysroot.read("/etc/hostname"))
        .unwrap_or_else(|| {
            warnings.push("asset", "nom d'hôte introuvable");
            "unknown".into()
        })
}

/// Lit `os-release` : `CLÉ=valeur`, valeur éventuellement entre guillemets.
pub fn parse_os_release(text: &str) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    for line in text.lines() {
        let line = line.trim();
        if line.starts_with('#') {
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let value = value.trim();
        let value = value
            .strip_prefix('"')
            .and_then(|v| v.strip_suffix('"'))
            .or_else(|| value.strip_prefix('\'').and_then(|v| v.strip_suffix('\'')))
            .unwrap_or(value);
        out.insert(
            key.trim().to_owned(),
            value.replace("\\\"", "\"").replace("\\$", "$"),
        );
    }
    out
}

/// Système d'exploitation.
pub fn operating_system(sysroot: &Sysroot, warnings: &mut Warnings) -> OperatingSystem {
    let release = sysroot
        .read("/etc/os-release")
        .or_else(|| sysroot.read("/usr/lib/os-release"))
        .map(|text| parse_os_release(&text))
        .unwrap_or_else(|| {
            warnings.push("operating_system", "fichier os-release introuvable");
            BTreeMap::new()
        });
    let get = |key: &str| release.get(key).filter(|v| !v.is_empty()).cloned();
    let id = get("ID");
    let version = get("VERSION_ID");

    let mut identifiers = Vec::new();
    if let Some(cpe) = get("CPE_NAME") {
        identifiers.push(identifiers::cpe_declared(&cpe));
    } else if let (Some(id), Some(version)) = (&id, &version) {
        let (vendor, product) = identifiers::os_cpe_names(id);
        identifiers.push(identifiers::cpe_candidate(
            Part::OperatingSystem,
            vendor,
            product,
            Some(version),
        ));
    }

    OperatingSystem {
        family: "linux".into(),
        id,
        name: get("NAME"),
        version,
        pretty_name: get("PRETTY_NAME"),
        kernel_release: sysroot.read("/proc/sys/kernel/osrelease"),
        kernel_version: sysroot.read("/proc/sys/kernel/version"),
        architecture: sysroot
            .read("/proc/sys/kernel/arch")
            .unwrap_or_else(|| std::env::consts::ARCH.to_owned()),
        identifiers,
    }
}

/// Constructeur d'un cœur ARM d'après son code d'implémenteur.
fn arm_implementer(code: &str) -> Option<&'static str> {
    match code.to_lowercase().as_str() {
        "0x41" => Some("ARM"),
        "0x42" => Some("Broadcom"),
        "0x51" => Some("Qualcomm"),
        "0x61" => Some("Apple"),
        _ => None,
    }
}

/// Lit `/proc/cpuinfo` : processeurs regroupés par modèle, et version du
/// microcode si le noyau la donne.
pub fn parse_cpuinfo(text: &str, architecture: &str) -> (Vec<Processor>, Option<String>) {
    let mut groups: BTreeMap<(Option<String>, Option<String>), u32> = BTreeMap::new();
    let mut microcode = None;
    for block in text.split("\n\n") {
        let field = |name: &str| {
            block.lines().find_map(|line| {
                let (key, value) = line.split_once(':')?;
                (key.trim() == name && !value.trim().is_empty()).then(|| value.trim().to_owned())
            })
        };
        if field("processor").is_none() {
            continue;
        }
        let vendor = field("vendor_id")
            .or_else(|| field("CPU implementer").and_then(|c| arm_implementer(&c).map(Into::into)));
        let model = field("model name")
            .or_else(|| field("CPU part").map(|part| format!("CPU part {part}")));
        if microcode.is_none() {
            microcode = field("microcode");
        }
        *groups.entry((vendor, model)).or_default() += 1;
    }
    let processors = groups
        .into_iter()
        .map(|((vendor, model), logical_cores)| Processor {
            vendor,
            model,
            architecture: architecture.to_owned(),
            logical_cores,
        })
        .collect();
    (processors, microcode)
}

/// Mémoire totale en octets, depuis `/proc/meminfo`.
pub fn parse_meminfo(text: &str) -> Option<u64> {
    let line = text.lines().find(|line| line.starts_with("MemTotal:"))?;
    let kilobytes: u64 = line.split_whitespace().nth(1)?.parse().ok()?;
    Some(kilobytes * 1024)
}

/// Disques, depuis `/sys/block` ; les périphériques sans matériel
/// (boucles, RAM, volumes assemblés) sont écartés.
fn disks(sysroot: &Sysroot) -> Vec<Disk> {
    let Ok(entries) = fs::read_dir(sysroot.path("/sys/block")) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        let base = format!("/sys/block/{name}");
        if !sysroot.path(&format!("{base}/device")).exists() {
            continue;
        }
        let read = |file: &str| sysroot.read(&format!("{base}/{file}"));
        out.push(Disk {
            vendor: read("device/vendor"),
            model: read("device/model"),
            serial: read("device/serial"),
            firmware_version: read("device/firmware_rev").or_else(|| read("device/rev")),
            // Le noyau compte toujours en secteurs de 512 octets.
            size_bytes: read("size")
                .and_then(|sectors| sectors.parse::<u64>().ok())
                .map(|sectors| sectors * 512),
            removable: read("removable").as_deref() == Some("1"),
            name,
        });
    }
    out.sort_by(|a, b| a.name.cmp(&b.name));
    out
}

/// Matériel et firmware : ils partagent leurs sources (DMI, `cpuinfo`).
pub fn hardware_and_firmware(
    sysroot: &Sysroot,
    architecture: &str,
    warnings: &mut Warnings,
) -> (Hardware, FirmwareSection) {
    let dmi = |field: &str| declared(sysroot, &format!("/sys/class/dmi/id/{field}"));
    let has_dmi = sysroot.path("/sys/class/dmi/id").exists();

    let mut machine = Machine {
        vendor: dmi("sys_vendor"),
        model: dmi("product_name"),
        version: dmi("product_version"),
        serial: dmi("product_serial"),
        board_vendor: dmi("board_vendor"),
        board_model: dmi("board_name"),
        identifiers: Vec::new(),
    };
    if sysroot.exists_unreadable("/sys/class/dmi/id/product_serial") {
        warnings.push(
            "hardware",
            "numéro de série illisible sans les droits d'administration",
        );
    }
    // Cartes sans DMI (Raspberry Pi et autres ARM) : l'arbre matériel.
    if machine.model.is_none() {
        machine.model = sysroot.read("/proc/device-tree/model");
    }
    if machine.serial.is_none() {
        machine.serial = sysroot.read("/proc/device-tree/serial-number");
    }
    if let (Some(vendor), Some(model)) = (&machine.vendor, &machine.model) {
        machine.identifiers.push(identifiers::cpe_candidate(
            Part::Hardware,
            vendor,
            model,
            None,
        ));
    }

    let (processors, microcode) = sysroot
        .read("/proc/cpuinfo")
        .map(|text| parse_cpuinfo(&text, architecture))
        .unwrap_or_default();
    if processors.is_empty() {
        warnings.push("hardware", "processeurs introuvables dans /proc/cpuinfo");
    }

    let mut components = Vec::new();
    let (bios_vendor, bios_version, bios_date) =
        (dmi("bios_vendor"), dmi("bios_version"), dmi("bios_date"));
    if bios_vendor.is_some() || bios_version.is_some() {
        let mut identifiers = Vec::new();
        // Le NVD range le firmware d'une machine sous « <modèle>_firmware ».
        if let (Some(vendor), Some(model), Some(version)) =
            (&machine.vendor, &machine.model, &bios_version)
        {
            identifiers.push(identifiers::cpe_candidate(
                Part::OperatingSystem,
                vendor,
                &format!("{model} firmware"),
                Some(version),
            ));
        }
        components.push(Firmware {
            kind: "system".into(),
            vendor: bios_vendor,
            version: bios_version,
            release_date: bios_date,
            identifiers,
        });
    }
    if let Some(version) = microcode {
        components.push(Firmware {
            kind: "cpu-microcode".into(),
            vendor: processors.first().and_then(|p| p.vendor.clone()),
            version: Some(version),
            release_date: None,
            identifiers: Vec::new(),
        });
    }

    let uefi = sysroot.path("/sys/firmware/efi").exists();
    let firmware = FirmwareSection {
        boot_mode: if uefi {
            Some(BootMode::Uefi)
        } else if has_dmi {
            Some(BootMode::Legacy)
        } else {
            None
        },
        // Variable UEFI : quatre octets d'attributs, puis l'état.
        secure_boot: fs::read(
            sysroot
                .path("/sys/firmware/efi/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c"),
        )
        .ok()
        .and_then(|bytes| bytes.get(4).map(|state| *state == 1)),
        components,
    };

    let hardware = Hardware {
        machine,
        processors,
        memory_bytes: sysroot
            .read("/proc/meminfo")
            .and_then(|t| parse_meminfo(&t)),
        disks: disks(sysroot),
    };
    (hardware, firmware)
}

/// Cherche un outil système dans les répertoires standard, jamais dans `PATH` :
/// lancé avec les droits d'administration, le collecteur ne doit pas exécuter
/// un programme déposé ailleurs.
fn system_tool(name: &str) -> Option<PathBuf> {
    ["/usr/bin", "/bin", "/usr/sbin", "/sbin"]
        .iter()
        .map(|dir| Path::new(dir).join(name))
        .find(|path| path.is_file())
}

/// Lance un outil système et rend sa sortie standard.
fn run(tool: &Path, args: &[&str]) -> Option<String> {
    let output = Command::new(tool)
        .args(args)
        .env_clear()
        .env("LC_ALL", "C")
        .output()
        .ok()?;
    output
        .status
        .success()
        .then(|| String::from_utf8_lossy(&output.stdout).into_owned())
}

/// Logiciels installés, tous gestionnaires de paquets confondus.
pub fn software(sysroot: &Sysroot, os: &OperatingSystem, warnings: &mut Warnings) -> Vec<Software> {
    let distro = Distro {
        id: os.id.as_deref().unwrap_or_default(),
        version_id: os.version.as_deref().unwrap_or_default(),
    };
    let mut out = Vec::new();
    let mut found = false;

    if let Some(text) = sysroot.read("/var/lib/dpkg/status") {
        found = true;
        out.extend(packages::parse_dpkg_status(&text, distro));
    }
    if let Some(text) = sysroot.read("/lib/apk/db/installed") {
        found = true;
        out.extend(packages::parse_apk_installed(&text, distro));
    }
    if let Ok(entries) = fs::read_dir(sysroot.path("/var/lib/pacman/local")) {
        found = true;
        for entry in entries.flatten() {
            if let Ok(text) = fs::read_to_string(entry.path().join("desc")) {
                out.extend(packages::parse_pacman_desc(&text, distro));
            }
        }
    }
    let has_rpm_database = ["/var/lib/rpm", "/usr/lib/sysimage/rpm"]
        .iter()
        .any(|dir| sysroot.path(dir).is_dir());
    if has_rpm_database {
        // La base RPM est binaire : seul l'outil `rpm` la lit.
        let queried = sysroot
            .is_live()
            .then(|| system_tool("rpm"))
            .flatten()
            .and_then(|rpm| run(&rpm, &["-qa", "--qf", packages::RPM_QUERY_FORMAT]));
        match queried {
            Some(text) => {
                found = true;
                out.extend(packages::parse_rpm_query(&text, distro));
            }
            None => warnings.push(
                "software",
                "base RPM présente mais illisible sans l'outil rpm",
            ),
        }
    }
    if !found {
        warnings.push("software", "aucun gestionnaire de paquets reconnu");
    }
    out.sort_by(|a, b| {
        (&a.name, &a.version, &a.architecture).cmp(&(&b.name, &b.version, &b.architecture))
    });
    out
}

/// MAC canonique : minuscules séparées par `:` ; `None` pour une MAC nulle
/// ou qui n'en est pas une.
pub fn canonical_mac(value: &str) -> Option<String> {
    let digits: Vec<char> = value
        .chars()
        .filter(|c| !matches!(c, ':' | '-' | '.' | ' '))
        .collect();
    if digits.len() != 12
        || !digits.iter().all(char::is_ascii_hexdigit)
        || digits.iter().all(|c| *c == '0')
    {
        return None;
    }
    let pairs: Vec<String> = digits
        .chunks(2)
        .map(|pair| pair.iter().map(char::to_ascii_lowercase).collect())
        .collect();
    Some(pairs.join(":"))
}

/// Lit `/proc/net/if_inet6` : adresses IPv6 par interface.
pub fn parse_if_inet6(text: &str) -> BTreeMap<String, Vec<Address>> {
    let mut out: BTreeMap<String, Vec<Address>> = BTreeMap::new();
    for line in text.lines() {
        let fields: Vec<&str> = line.split_whitespace().collect();
        let [address, _index, prefix, _scope, _flags, name] = fields[..] else {
            continue;
        };
        let (Ok(bits), Ok(prefix)) = (
            u128::from_str_radix(address, 16),
            u8::from_str_radix(prefix, 16),
        ) else {
            continue;
        };
        if address.len() != 32 {
            continue;
        }
        out.entry(name.to_owned()).or_default().push(Address {
            ip: Ipv6Addr::from(bits).to_string(),
            prefix_length: Some(prefix),
        });
    }
    out
}

/// Adresses IPv4 du système en cours d'exécution, par interface.
fn live_ipv4() -> BTreeMap<String, Vec<Address>> {
    let mut out: BTreeMap<String, Vec<Address>> = BTreeMap::new();
    let Ok(addresses) = nix::ifaddrs::getifaddrs() else {
        return out;
    };
    for interface in addresses {
        let Some(ip) = interface
            .address
            .as_ref()
            .and_then(|address| address.as_sockaddr_in())
            .map(|address| address.ip())
        else {
            continue;
        };
        let prefix_length = interface
            .netmask
            .as_ref()
            .and_then(|mask| mask.as_sockaddr_in())
            .map(|mask| u32::from(mask.ip()).count_ones() as u8);
        out.entry(interface.interface_name)
            .or_default()
            .push(Address {
                ip: ip.to_string(),
                prefix_length,
            });
    }
    out
}

/// Interfaces réseau.
pub fn interfaces(sysroot: &Sysroot, warnings: &mut Warnings) -> Vec<Interface> {
    let Ok(entries) = fs::read_dir(sysroot.path("/sys/class/net")) else {
        warnings.push(
            "network",
            "interfaces réseau introuvables dans /sys/class/net",
        );
        return Vec::new();
    };
    let mut ipv4 = if sysroot.is_live() {
        live_ipv4()
    } else {
        BTreeMap::new()
    };
    let mut ipv6 = sysroot
        .read("/proc/net/if_inet6")
        .map(|text| parse_if_inet6(&text))
        .unwrap_or_default();

    let mut out = Vec::new();
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        let base = format!("/sys/class/net/{name}");
        if !sysroot.path(&base).is_dir() {
            continue;
        }
        let read = |file: &str| sysroot.read(&format!("{base}/{file}"));
        // 772 est le type ARPHRD_LOOPBACK.
        let kind = if read("type").as_deref() == Some("772") {
            InterfaceKind::Loopback
        } else if sysroot.path(&format!("{base}/device")).exists() {
            InterfaceKind::Physical
        } else {
            InterfaceKind::Virtual
        };
        let mut addresses = ipv4.remove(&name).unwrap_or_default();
        addresses.extend(ipv6.remove(&name).unwrap_or_default());
        addresses.sort();
        out.push(Interface {
            mac: read("address").and_then(|mac| canonical_mac(&mac)),
            kind,
            state: read("operstate"),
            mtu: read("mtu").and_then(|mtu| mtu.parse().ok()),
            addresses,
            name,
        });
    }
    out.sort_by(|a, b| a.name.cmp(&b.name));
    out
}

/// Une ligne de `/proc/net/{tcp,udp}{,6}` : adresse locale, port, état, inode.
struct ProcSocket {
    address: String,
    port: u16,
    state: u8,
    remote_is_any: bool,
    inode: u64,
}

/// Décode une adresse telle que le noyau l'écrit : des mots de 32 bits en
/// hexadécimal, chacun dans l'ordre des octets de la machine.
fn kernel_address(hex: &str) -> Option<String> {
    let word = |index: usize| -> Option<[u8; 4]> {
        let digits = hex.get(index * 8..index * 8 + 8)?;
        Some(u32::from_str_radix(digits, 16).ok()?.to_ne_bytes())
    };
    match hex.len() {
        8 => Some(Ipv4Addr::from(word(0)?).to_string()),
        32 => {
            let mut bytes = [0_u8; 16];
            for index in 0..4 {
                bytes[index * 4..index * 4 + 4].copy_from_slice(&word(index)?);
            }
            Some(Ipv6Addr::from(bytes).to_string())
        }
        _ => None,
    }
}

/// Lit une table de sockets du noyau.
fn parse_proc_sockets(text: &str) -> Vec<ProcSocket> {
    let mut out = Vec::new();
    for line in text.lines().skip(1) {
        let fields: Vec<&str> = line.split_whitespace().collect();
        let (Some(local), Some(remote), Some(state), Some(inode)) =
            (fields.get(1), fields.get(2), fields.get(3), fields.get(9))
        else {
            continue;
        };
        let Some((address, port)) = local.rsplit_once(':') else {
            continue;
        };
        let (Some(address), Ok(port), Ok(state), Ok(inode)) = (
            kernel_address(address),
            u16::from_str_radix(port, 16),
            u8::from_str_radix(state, 16),
            inode.parse::<u64>(),
        ) else {
            continue;
        };
        out.push(ProcSocket {
            address,
            port,
            state,
            remote_is_any: remote.chars().all(|c| matches!(c, '0' | ':')),
            inode,
        });
    }
    out
}

/// Associe chaque socket ouvert à son processus, en lisant les descripteurs
/// de `/proc/<pid>/fd`. Sans droits d'administration, seuls les processus du
/// compte courant sont visibles.
fn socket_owners(sysroot: &Sysroot) -> BTreeMap<u64, Process> {
    let mut out = BTreeMap::new();
    let Ok(entries) = fs::read_dir(sysroot.path("/proc")) else {
        return out;
    };
    for entry in entries.flatten() {
        let Ok(pid) = entry.file_name().to_string_lossy().parse::<u32>() else {
            continue;
        };
        let Ok(descriptors) = fs::read_dir(entry.path().join("fd")) else {
            continue;
        };
        let mut process = None;
        for descriptor in descriptors.flatten() {
            let Ok(target) = fs::read_link(descriptor.path()) else {
                continue;
            };
            let target = target.to_string_lossy();
            let Some(inode) = target
                .strip_prefix("socket:[")
                .and_then(|rest| rest.strip_suffix(']'))
                .and_then(|inode| inode.parse::<u64>().ok())
            else {
                continue;
            };
            let process = process.get_or_insert_with(|| Process {
                pid,
                name: sysroot
                    .read(&format!("/proc/{pid}/comm"))
                    .unwrap_or_else(|| "?".into()),
                executable: fs::read_link(entry.path().join("exe"))
                    .ok()
                    .map(|exe| exe.to_string_lossy().into_owned()),
            });
            out.entry(inode).or_insert_with(|| process.clone());
        }
    }
    out
}

/// Ports à l'écoute : TCP en état d'écoute, UDP liés sans correspondant.
pub fn listening_sockets(sysroot: &Sysroot, warnings: &mut Warnings) -> Vec<ListeningSocket> {
    /// État `TCP_LISTEN` du noyau.
    const TCP_LISTEN: u8 = 0x0A;
    let owners = socket_owners(sysroot);
    let mut out = Vec::new();
    let mut read_any = false;
    let mut without_owner = 0_usize;
    for (file, protocol) in [
        ("tcp", Transport::Tcp),
        ("tcp6", Transport::Tcp),
        ("udp", Transport::Udp),
        ("udp6", Transport::Udp),
    ] {
        let Some(text) = sysroot.read(&format!("/proc/net/{file}")) else {
            continue;
        };
        read_any = true;
        for socket in parse_proc_sockets(&text) {
            let listening = match protocol {
                Transport::Tcp => socket.state == TCP_LISTEN,
                Transport::Udp => socket.remote_is_any && socket.port != 0,
            };
            if !listening {
                continue;
            }
            let process = owners.get(&socket.inode).cloned();
            if process.is_none() {
                without_owner += 1;
            }
            out.push(ListeningSocket {
                protocol,
                address: socket.address,
                port: socket.port,
                process,
            });
        }
    }
    if !read_any {
        warnings.push("network", "tables de sockets introuvables dans /proc/net");
    }
    if without_owner > 0 {
        warnings.push(
            "network",
            format!("{without_owner} port(s) à l'écoute sans processus identifié"),
        );
    }
    out.sort();
    out.dedup();
    out
}

/// Lit les sorties de `systemctl list-unit-files` et `systemctl list-units
/// --state=running`, sans légende.
pub fn parse_systemd(unit_files: &str, running_units: &str) -> Vec<Service> {
    let unit_name = |line: &str| {
        line.split_whitespace()
            .next()
            .filter(|name| name.ends_with(".service"))
            .map(str::to_owned)
    };
    let mut services: BTreeMap<String, Service> = BTreeMap::new();
    for line in unit_files.lines() {
        let Some(name) = unit_name(line) else {
            continue;
        };
        services.insert(
            name.clone(),
            Service {
                name,
                manager: "systemd".into(),
                startup: line.split_whitespace().nth(1).map(str::to_owned),
                running: false,
            },
        );
    }
    for line in running_units.lines() {
        let Some(name) = unit_name(line) else {
            continue;
        };
        services
            .entry(name.clone())
            .or_insert_with(|| Service {
                name,
                manager: "systemd".into(),
                startup: None,
                running: false,
            })
            .running = true;
    }
    services.into_values().collect()
}

/// Services du gestionnaire de services.
pub fn services(sysroot: &Sysroot, warnings: &mut Warnings) -> Vec<Service> {
    if !sysroot.is_live() {
        return Vec::new();
    }
    let Some(systemctl) = system_tool("systemctl") else {
        warnings.push(
            "services",
            "gestionnaire de services non reconnu (systemd absent)",
        );
        return Vec::new();
    };
    let common = ["--type=service", "--no-legend", "--plain", "--no-pager"];
    let unit_files = run(
        &systemctl,
        &[&["list-unit-files"][..], &common[..]].concat(),
    );
    let running = run(
        &systemctl,
        &[&["list-units", "--state=running"][..], &common[..]].concat(),
    );
    match (unit_files, running) {
        (Some(unit_files), Some(running)) => parse_systemd(&unit_files, &running),
        _ => {
            warnings.push("services", "systemctl n'a pas répondu");
            Vec::new()
        }
    }
}

/// Lit `/etc/passwd`.
pub fn parse_passwd(text: &str) -> Vec<Account> {
    let mut out = Vec::new();
    for line in text.lines() {
        let fields: Vec<&str> = line.split(':').collect();
        let [name, _password, uid, gid, _comment, home, shell] = fields[..] else {
            continue;
        };
        let (Ok(uid), Ok(gid)) = (uid.parse(), gid.parse()) else {
            continue;
        };
        out.push(Account {
            name: name.to_owned(),
            uid,
            gid,
            home: (!home.is_empty()).then(|| home.to_owned()),
            shell: (!shell.is_empty()).then(|| shell.to_owned()),
        });
    }
    out.sort_by(|a, b| (a.uid, &a.name).cmp(&(b.uid, &b.name)));
    out
}

/// Comptes locaux.
pub fn accounts(sysroot: &Sysroot, warnings: &mut Warnings) -> Vec<Account> {
    sysroot
        .read("/etc/passwd")
        .map(|text| parse_passwd(&text))
        .unwrap_or_else(|| {
            warnings.push("accounts", "fichier /etc/passwd introuvable");
            Vec::new()
        })
}

/// Réseau : interfaces et ports à l'écoute.
pub fn network(sysroot: &Sysroot, warnings: &mut Warnings) -> Network {
    Network {
        interfaces: interfaces(sysroot, warnings),
        listening_sockets: listening_sockets(sysroot, warnings),
    }
}

/// Le relevé tourne-t-il avec les droits d'administration ?
pub fn is_privileged() -> bool {
    nix::unistd::geteuid().is_root()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn os_release_strips_quotes() {
        let release = parse_os_release(
            "# commentaire\nNAME=\"Debian GNU/Linux\"\nID=debian\nVERSION_ID='12'\nEMPTY=\n",
        );
        assert_eq!(release["NAME"], "Debian GNU/Linux");
        assert_eq!(release["ID"], "debian");
        assert_eq!(release["VERSION_ID"], "12");
        assert_eq!(release["EMPTY"], "");
    }

    #[test]
    fn cpuinfo_groups_identical_cores() {
        let text = "processor\t: 0\nvendor_id\t: GenuineIntel\nmodel name\t: Intel(R) Core(TM) i7\nmicrocode\t: 0xf4\n\nprocessor\t: 1\nvendor_id\t: GenuineIntel\nmodel name\t: Intel(R) Core(TM) i7\nmicrocode\t: 0xf4\n";
        let (processors, microcode) = parse_cpuinfo(text, "x86_64");
        assert_eq!(processors.len(), 1);
        assert_eq!(processors[0].logical_cores, 2);
        assert_eq!(processors[0].vendor.as_deref(), Some("GenuineIntel"));
        assert_eq!(microcode.as_deref(), Some("0xf4"));
    }

    #[test]
    fn cpuinfo_reads_arm_cores_without_model_name() {
        let text = "processor\t: 0\nCPU implementer\t: 0x41\nCPU part\t: 0xd0b\n\nprocessor\t: 1\nCPU implementer\t: 0x41\nCPU part\t: 0xd0b\n\nModel\t\t: Raspberry Pi 5\n";
        let (processors, microcode) = parse_cpuinfo(text, "aarch64");
        assert_eq!(processors.len(), 1);
        assert_eq!(processors[0].vendor.as_deref(), Some("ARM"));
        assert_eq!(processors[0].model.as_deref(), Some("CPU part 0xd0b"));
        assert_eq!(processors[0].logical_cores, 2);
        assert!(microcode.is_none());
    }

    #[test]
    fn meminfo_converts_kilobytes() {
        assert_eq!(
            parse_meminfo("MemTotal:       16303428 kB\nMemFree: 1 kB\n"),
            Some(16_303_428 * 1024)
        );
        assert_eq!(parse_meminfo("MemFree: 1 kB\n"), None);
    }

    #[test]
    fn mac_is_canonical_and_null_mac_is_dropped() {
        assert_eq!(
            canonical_mac("E0-D5-5E-28-9B-D4").as_deref(),
            Some("e0:d5:5e:28:9b:d4")
        );
        assert_eq!(canonical_mac("00:00:00:00:00:00"), None);
        assert_eq!(canonical_mac("pas une mac"), None);
    }

    #[test]
    fn if_inet6_decodes_addresses() {
        let text = "fe80000000000000e2d55efffe289bd4 02 40 20 80     eth0\n00000000000000000000000000000001 01 80 10 80       lo\n";
        let addresses = parse_if_inet6(text);
        assert_eq!(addresses["eth0"][0].ip, "fe80::e2d5:5eff:fe28:9bd4");
        assert_eq!(addresses["eth0"][0].prefix_length, Some(64));
        assert_eq!(addresses["lo"][0].ip, "::1");
        assert_eq!(addresses["lo"][0].prefix_length, Some(128));
    }

    #[cfg(target_endian = "little")]
    #[test]
    fn proc_sockets_decode_kernel_addresses() {
        let text = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n   0: 0100007F:0277 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 4242 1 0000000000000000 100 0 0 10 0\n   1: 0100007F:C350 0100007F:0277 01 00000000:00000000 00:00000000 00000000  1000        0 4243 1 0000000000000000 20 4 30 10 -1\n";
        let sockets = parse_proc_sockets(text);
        assert_eq!(sockets.len(), 2);
        assert_eq!(sockets[0].address, "127.0.0.1");
        assert_eq!(sockets[0].port, 631);
        assert_eq!(sockets[0].state, 0x0A);
        assert_eq!(sockets[0].inode, 4242);
        assert!(sockets[0].remote_is_any);
        assert!(!sockets[1].remote_is_any);
        assert_eq!(
            kernel_address("00000000000000000000000001000000").as_deref(),
            Some("::1")
        );
    }

    #[test]
    fn systemd_merges_unit_files_and_running_units() {
        let unit_files = "ssh.service enabled enabled\ncups.service disabled enabled\nfoo.socket enabled enabled\n";
        let running = "ssh.service loaded active running OpenBSD Secure Shell server\nuser@1000.service loaded active running User Manager\n";
        let services = parse_systemd(unit_files, running);
        assert_eq!(services.len(), 3);
        assert_eq!(services[0].name, "cups.service");
        assert!(!services[0].running);
        assert_eq!(services[1].name, "ssh.service");
        assert_eq!(services[1].startup.as_deref(), Some("enabled"));
        assert!(services[1].running);
        assert!(services[2].startup.is_none());
    }

    #[test]
    fn passwd_skips_malformed_lines() {
        let accounts = parse_passwd(
            "root:x:0:0:root:/root:/bin/bash\nligne cassée\nsvc:x:999:999::/nonexistent:\n",
        );
        assert_eq!(accounts.len(), 2);
        assert_eq!(accounts[0].name, "root");
        assert_eq!(accounts[1].shell, None);
    }
}
