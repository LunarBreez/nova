//! Logiciels installés, lus dans les bases des gestionnaires de paquets.
//!
//! Chaque lecteur prend le **texte** de la base et rend des [`Software`] :
//! aucun n'ouvre de fichier, ce qui les rend vérifiables sur des extraits.

use crate::identifiers::purl;
use crate::model::Software;

/// Distribution pour laquelle les paquets ont été construits.
#[derive(Debug, Clone, Copy)]
pub struct Distro<'a> {
    /// Identifiant court (`ID` de `os-release`).
    pub id: &'a str,
    /// Version (`VERSION_ID` de `os-release`).
    pub version_id: &'a str,
}

impl Distro<'_> {
    /// Qualificatif `distro` d'un PURL, par exemple `debian-12`.
    fn qualifier(&self) -> String {
        if self.id.is_empty() || self.version_id.is_empty() {
            String::new()
        } else {
            format!("{}-{}", self.id, self.version_id)
        }
    }
}

/// Rend `None` pour une chaîne vide.
fn non_empty(value: &str) -> Option<String> {
    let value = value.trim();
    (!value.is_empty()).then(|| value.to_owned())
}

/// Lit `/var/lib/dpkg/status` : un paragraphe par paquet, seuls les paquets
/// à l'état `installed` sont retenus.
pub fn parse_dpkg_status(text: &str, distro: Distro<'_>) -> Vec<Software> {
    let distro_qualifier = distro.qualifier();
    let mut out = Vec::new();
    for paragraph in text.split("\n\n") {
        let (mut name, mut version, mut arch, mut maintainer, mut status) = ("", "", "", "", "");
        for line in paragraph.lines() {
            // Une ligne qui commence par un blanc continue le champ précédent.
            if line.starts_with([' ', '\t']) {
                continue;
            }
            let Some((key, value)) = line.split_once(':') else {
                continue;
            };
            let value = value.trim();
            match key {
                "Package" => name = value,
                "Version" => version = value,
                "Architecture" => arch = value,
                "Maintainer" => maintainer = value,
                "Status" => status = value,
                _ => {}
            }
        }
        if name.is_empty() || version.is_empty() || !status.ends_with(" installed") {
            continue;
        }
        out.push(Software {
            name: name.to_owned(),
            version: version.to_owned(),
            vendor: non_empty(maintainer),
            architecture: non_empty(arch),
            source: "dpkg".into(),
            identifiers: vec![purl(
                "deb",
                Some(distro.id),
                name,
                version,
                &[("arch", arch), ("distro", &distro_qualifier)],
            )],
        });
    }
    out
}

/// Lit `/lib/apk/db/installed` (Alpine) : un paragraphe par paquet, une
/// lettre par champ.
pub fn parse_apk_installed(text: &str, distro: Distro<'_>) -> Vec<Software> {
    let distro_qualifier = distro.qualifier();
    let mut out = Vec::new();
    for paragraph in text.split("\n\n") {
        let (mut name, mut version, mut arch, mut maintainer) = ("", "", "", "");
        for line in paragraph.lines() {
            let Some((key, value)) = line.split_once(':') else {
                continue;
            };
            match key {
                "P" => name = value,
                "V" => version = value,
                "A" => arch = value,
                "m" => maintainer = value,
                _ => {}
            }
        }
        if name.is_empty() || version.is_empty() {
            continue;
        }
        out.push(Software {
            name: name.to_owned(),
            version: version.to_owned(),
            vendor: non_empty(maintainer),
            architecture: non_empty(arch),
            source: "apk".into(),
            identifiers: vec![purl(
                "apk",
                Some(distro.id),
                name,
                version,
                &[("arch", arch), ("distro", &distro_qualifier)],
            )],
        });
    }
    out
}

/// Lit un fichier `desc` de `/var/lib/pacman/local/<paquet>/` : chaque champ
/// est un titre `%NOM%` suivi de sa valeur sur la ligne suivante.
pub fn parse_pacman_desc(text: &str, distro: Distro<'_>) -> Option<Software> {
    let field = |title: &str| {
        let mut lines = text.lines();
        lines.find(|line| *line == title)?;
        lines
            .next()
            .map(str::trim)
            .filter(|value| !value.is_empty())
    };
    let name = field("%NAME%")?;
    let version = field("%VERSION%")?;
    let arch = field("%ARCH%").unwrap_or_default();
    Some(Software {
        name: name.to_owned(),
        version: version.to_owned(),
        vendor: field("%PACKAGER%").map(str::to_owned),
        architecture: non_empty(arch),
        source: "pacman".into(),
        identifiers: vec![purl(
            "alpm",
            Some(distro.id),
            name,
            version,
            &[("arch", arch)],
        )],
    })
}

/// Format demandé à `rpm -qa` : six champs séparés par des tabulations.
pub const RPM_QUERY_FORMAT: &str =
    "%{NAME}\\t%{EPOCH}\\t%{VERSION}\\t%{RELEASE}\\t%{ARCH}\\t%{VENDOR}\\n";

/// Rend vide un champ que rpm écrit `(none)` faute de valeur.
fn present(value: &str) -> &str {
    if value == "(none)" { "" } else { value }
}

/// Lit la sortie de `rpm -qa --qf` au format [`RPM_QUERY_FORMAT`].
pub fn parse_rpm_query(text: &str, distro: Distro<'_>) -> Vec<Software> {
    let distro_qualifier = distro.qualifier();
    let mut out = Vec::new();
    for line in text.lines() {
        let fields: Vec<&str> = line.split('\t').collect();
        let [name, epoch, version, release, arch, vendor] = fields[..] else {
            continue;
        };
        // Les clés de signature importées apparaissent comme des paquets.
        if name.is_empty() || name == "gpg-pubkey" {
            continue;
        }
        let (epoch, arch) = (present(epoch), present(arch));
        let full_version = format!("{version}-{release}");
        out.push(Software {
            name: name.to_owned(),
            version: if epoch.is_empty() {
                full_version.clone()
            } else {
                format!("{epoch}:{full_version}")
            },
            vendor: non_empty(present(vendor)),
            architecture: non_empty(arch),
            source: "rpm".into(),
            identifiers: vec![purl(
                "rpm",
                Some(distro.id),
                name,
                &full_version,
                &[
                    ("arch", arch),
                    ("distro", &distro_qualifier),
                    ("epoch", epoch),
                ],
            )],
        });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const DEBIAN: Distro<'static> = Distro {
        id: "debian",
        version_id: "12",
    };

    #[test]
    fn dpkg_keeps_only_installed_packages() {
        let status = "\
Package: openssl
Status: install ok installed
Maintainer: Debian OpenSSL Team <pkg-openssl-devel@alioth-lists.debian.net>
Architecture: amd64
Version: 3.0.15-1~deb12u1
Description: Secure Sockets Layer toolkit
 Version: ceci est une ligne de description, pas un champ

Package: removed-tool
Status: deinstall ok config-files
Architecture: all
Version: 1.0
";
        let packages = parse_dpkg_status(status, DEBIAN);
        assert_eq!(packages.len(), 1);
        let openssl = &packages[0];
        assert_eq!(openssl.name, "openssl");
        assert_eq!(openssl.version, "3.0.15-1~deb12u1");
        assert_eq!(openssl.architecture.as_deref(), Some("amd64"));
        assert_eq!(
            openssl.identifiers[0].value,
            "pkg:deb/debian/openssl@3.0.15-1~deb12u1?arch=amd64&distro=debian-12"
        );
    }

    #[test]
    fn apk_reads_single_letter_fields() {
        let installed = "C:Q1abc=\nP:musl\nV:1.2.5-r0\nA:x86_64\nm:Timo Teräs <t@example.org>\n\nP:busybox\nV:1.36.1-r29\nA:x86_64\n";
        let distro = Distro {
            id: "alpine",
            version_id: "3.20.3",
        };
        let packages = parse_apk_installed(installed, distro);
        assert_eq!(packages.len(), 2);
        assert_eq!(
            packages[0].identifiers[0].value,
            "pkg:apk/alpine/musl@1.2.5-r0?arch=x86_64&distro=alpine-3.20.3"
        );
        assert!(packages[1].vendor.is_none());
    }

    #[test]
    fn pacman_reads_titled_fields() {
        let desc = "%NAME%\nzlib\n\n%VERSION%\n1:1.3.1-2\n\n%ARCH%\nx86_64\n\n%PACKAGER%\nSomeone <s@example.org>\n";
        let distro = Distro {
            id: "arch",
            version_id: "",
        };
        let package = parse_pacman_desc(desc, distro).unwrap();
        assert_eq!(package.version, "1:1.3.1-2");
        assert_eq!(
            package.identifiers[0].value,
            "pkg:alpm/arch/zlib@1:1.3.1-2?arch=x86_64"
        );
        assert!(parse_pacman_desc("%NAME%\n\n", distro).is_none());
    }

    #[test]
    fn rpm_handles_epoch_and_skips_keys() {
        let output = "bash\t(none)\t5.2.26\t4.el9\tx86_64\tRed Hat, Inc.\n\
openssl-libs\t1\t3.2.2\t6.el9_5\tx86_64\tRed Hat, Inc.\n\
gpg-pubkey\t(none)\tfd431d51\t4ae0493b\t(none)\t(none)\n\
ligne incomplète\n";
        let distro = Distro {
            id: "rhel",
            version_id: "9.5",
        };
        let packages = parse_rpm_query(output, distro);
        assert_eq!(packages.len(), 2);
        assert_eq!(packages[0].version, "5.2.26-4.el9");
        assert_eq!(packages[1].version, "1:3.2.2-6.el9_5");
        assert_eq!(
            packages[1].identifiers[0].value,
            "pkg:rpm/rhel/openssl-libs@3.2.2-6.el9_5?arch=x86_64&distro=rhel-9.5&epoch=1"
        );
    }
}
