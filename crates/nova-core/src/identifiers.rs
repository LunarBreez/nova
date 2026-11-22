//! Identifiants normalisés : PURL et CPE.
//!
//! Un PURL se **calcule** depuis ce que le gestionnaire de paquets sait déjà :
//! il est exact hors ligne. Un CPE ne se calcule pas : ses noms d'éditeur et
//! de produit sont attribués par le NVD. Sauf quand le système le déclare
//! lui-même, Nova n'écrit donc qu'un CPE **candidat**, à confirmer par le
//! logiciel qui détient la base de vulnérabilités.

use crate::model::{Identifier, Origin, Scheme};

/// Encode une valeur pour un PURL : tout sauf les caractères non réservés
/// et `:` est percent-encodé.
fn purl_encode(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for byte in value.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'.' | b'-' | b'_' | b'~' | b':' => {
                out.push(char::from(byte));
            }
            _ => out.push_str(&format!("%{byte:02X}")),
        }
    }
    out
}

/// Construit un PURL.
///
/// `qualifiers` est émis trié par clé ; une valeur vide est écartée.
pub fn purl(
    kind: &str,
    namespace: Option<&str>,
    name: &str,
    version: &str,
    qualifiers: &[(&str, &str)],
) -> Identifier {
    let mut value = format!("pkg:{kind}/");
    if let Some(namespace) = namespace.filter(|n| !n.is_empty()) {
        value.push_str(&purl_encode(&namespace.to_lowercase()));
        value.push('/');
    }
    value.push_str(&purl_encode(name));
    if !version.is_empty() {
        value.push('@');
        value.push_str(&purl_encode(version));
    }
    let mut qualifiers: Vec<_> = qualifiers.iter().filter(|(_, v)| !v.is_empty()).collect();
    qualifiers.sort();
    for (index, (key, val)) in qualifiers.iter().enumerate() {
        value.push(if index == 0 { '?' } else { '&' });
        value.push_str(key);
        value.push('=');
        value.push_str(&purl_encode(val));
    }
    Identifier {
        scheme: Scheme::Purl,
        value,
        origin: Origin::Computed,
    }
}

/// Met une valeur libre sous la forme d'un attribut CPE 2.3 : minuscules,
/// espaces et caractères non ASCII en `_`, ponctuation échappée. Une valeur
/// vide devient `*`.
fn cpe_attribute(value: &str) -> String {
    let mut out = String::new();
    let mut pending_separator = false;
    for ch in value.trim().chars() {
        if ch.is_whitespace() {
            pending_separator = true;
            continue;
        }
        if pending_separator && !out.is_empty() {
            out.push('_');
        }
        pending_separator = false;
        if ch.is_ascii_alphanumeric() || matches!(ch, '_' | '-' | '.') {
            out.push(ch.to_ascii_lowercase());
        } else if ch.is_ascii_punctuation() {
            out.push('\\');
            out.push(ch);
        } else {
            // Un CPE n'admet que l'ASCII imprimable.
            out.push('_');
        }
    }
    if out.is_empty() { "*".into() } else { out }
}

/// Partie d'un CPE.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Part {
    /// Matériel.
    Hardware,
    /// Système d'exploitation ou firmware.
    OperatingSystem,
}

/// Construit un CPE 2.3 **candidat** depuis un éditeur, un produit et une version.
pub fn cpe_candidate(part: Part, vendor: &str, product: &str, version: Option<&str>) -> Identifier {
    let part = match part {
        Part::Hardware => 'h',
        Part::OperatingSystem => 'o',
    };
    let version = version.map_or_else(|| "*".to_owned(), cpe_attribute);
    Identifier {
        scheme: Scheme::Cpe,
        value: format!(
            "cpe:2.3:{part}:{}:{}:{version}:*:*:*:*:*:*:*",
            cpe_attribute(vendor),
            cpe_attribute(product),
        ),
        origin: Origin::Candidate,
    }
}

/// Reprend un CPE que le système déclare lui-même.
pub fn cpe_declared(value: &str) -> Identifier {
    Identifier {
        scheme: Scheme::Cpe,
        value: value.to_owned(),
        origin: Origin::Declared,
    }
}

/// Éditeur et produit sous lesquels le NVD range les distributions courantes.
///
/// Hors de cette table, l'identifiant de la distribution sert des deux côtés :
/// le résultat reste de toute façon un candidat.
pub fn os_cpe_names(id: &str) -> (&str, &str) {
    match id {
        "ubuntu" => ("canonical", "ubuntu_linux"),
        "debian" => ("debian", "debian_linux"),
        "rhel" => ("redhat", "enterprise_linux"),
        "fedora" => ("fedoraproject", "fedora"),
        "centos" => ("centos", "centos"),
        "alpine" => ("alpinelinux", "alpine_linux"),
        other => (other, other),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn purl_deb_encodes_version_and_sorts_qualifiers() {
        let id = purl(
            "deb",
            Some("Ubuntu"),
            "libstdc++6",
            "1:14.2.0-4ubuntu2~24.04",
            &[("distro", "ubuntu-24.04"), ("arch", "amd64")],
        );
        assert_eq!(
            id.value,
            "pkg:deb/ubuntu/libstdc%2B%2B6@1:14.2.0-4ubuntu2~24.04?arch=amd64&distro=ubuntu-24.04"
        );
        assert_eq!(id.origin, Origin::Computed);
    }

    #[test]
    fn purl_drops_empty_qualifiers() {
        let id = purl("apk", Some("alpine"), "musl", "1.2.5-r0", &[("arch", "")]);
        assert_eq!(id.value, "pkg:apk/alpine/musl@1.2.5-r0");
    }

    #[test]
    fn cpe_candidate_normalises_free_text() {
        let id = cpe_candidate(Part::Hardware, "Dell Inc.", "PowerEdge R740 (rev A)", None);
        assert_eq!(
            id.value,
            r"cpe:2.3:h:dell_inc.:poweredge_r740_\(rev_a\):*:*:*:*:*:*:*:*"
        );
        assert_eq!(id.origin, Origin::Candidate);
    }

    #[test]
    fn cpe_candidate_with_version() {
        let id = cpe_candidate(
            Part::OperatingSystem,
            "canonical",
            "ubuntu_linux",
            Some("24.04"),
        );
        assert_eq!(
            id.value,
            "cpe:2.3:o:canonical:ubuntu_linux:24.04:*:*:*:*:*:*:*"
        );
    }
}
