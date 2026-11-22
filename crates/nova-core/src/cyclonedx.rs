//! Export des composants d'un relevé au format CycloneDX 1.6.
//!
//! Le relevé Nova reste la référence. L'export n'en reprend que ce que
//! CycloneDX sait décrire : la machine, ses processeurs et disques, ses
//! firmwares, son système d'exploitation et ses logiciels, avec leurs PURL et
//! CPE. La configuration (interfaces, ports, services, comptes) et la liste
//! des empreintes de fichiers n'y figurent pas.
//!
//! L'export est déterministe : un même relevé donne le même document, numéro
//! de série compris.

use serde_json::{Map, Value, json};

use crate::error::{Context, Result};
use crate::files::sha256_hex;
use crate::model::{Cbom, Identifier, Origin, Scheme};

/// Ajoute une clé si la valeur existe.
fn set(object: &mut Map<String, Value>, key: &str, value: Option<&str>) {
    if let Some(value) = value {
        object.insert(key.into(), json!(value));
    }
}

/// Une propriété CycloneDX, dans l'espace de noms `nova:`.
fn property(name: &str, value: impl ToString) -> Value {
    json!({ "name": format!("nova:{name}"), "value": value.to_string() })
}

/// Reporte les identifiants d'un composant : un PURL, un CPE, et l'origine du
/// CPE en propriété, puisque CycloneDX ne sait pas dire qu'il est candidat.
fn set_identifiers(
    object: &mut Map<String, Value>,
    properties: &mut Vec<Value>,
    identifiers: &[Identifier],
) {
    if let Some(purl) = identifiers.iter().find(|id| id.scheme == Scheme::Purl) {
        object.insert("purl".into(), json!(purl.value));
    }
    if let Some(cpe) = identifiers.iter().find(|id| id.scheme == Scheme::Cpe) {
        object.insert("cpe".into(), json!(cpe.value));
        let origin = match cpe.origin {
            Origin::Computed => "computed",
            Origin::Declared => "declared",
            Origin::Candidate => "candidate",
        };
        properties.push(property("cpe:origin", origin));
    }
}

/// Termine un composant : type, référence, propriétés.
fn component(
    kind: &str,
    reference: String,
    mut object: Map<String, Value>,
    properties: Vec<Value>,
) -> Value {
    object.insert("type".into(), json!(kind));
    object.insert("bom-ref".into(), json!(reference));
    if !properties.is_empty() {
        object.insert("properties".into(), Value::Array(properties));
    }
    Value::Object(object)
}

/// Numéro de série dérivé du relevé : la forme d'un UUID, les octets d'un SHA-256.
fn serial_number(cbom: &Cbom) -> Result<String> {
    let digest = sha256_hex(&serde_json::to_vec(cbom).context(|| "relevé".into())?);
    let variant = match &digest[16..17] {
        "0" | "4" | "8" | "c" => '8',
        "1" | "5" | "9" | "d" => '9',
        "2" | "6" | "a" | "e" => 'a',
        _ => 'b',
    };
    Ok(format!(
        "urn:uuid:{}-{}-5{}-{variant}{}-{}",
        &digest[0..8],
        &digest[8..12],
        &digest[13..16],
        &digest[17..20],
        &digest[20..32]
    ))
}

/// Convertit un relevé en document CycloneDX 1.6.
pub fn export(cbom: &Cbom) -> Result<Value> {
    let machine = &cbom.hardware.machine;

    let mut root = Map::new();
    root.insert(
        "name".into(),
        json!(machine.model.as_deref().unwrap_or(&cbom.asset.hostname)),
    );
    set(&mut root, "version", machine.version.as_deref());
    if let Some(vendor) = &machine.vendor {
        root.insert("manufacturer".into(), json!({ "name": vendor }));
    }
    let mut properties = vec![property("hostname", &cbom.asset.hostname)];
    if let Some(id) = &cbom.asset.id {
        properties.push(property("asset:id", id));
    }
    if let Some(site) = &cbom.asset.site {
        properties.push(property("asset:site", site));
    }
    if let Some(serial) = &machine.serial {
        properties.push(property("serial", serial));
    }
    set_identifiers(&mut root, &mut properties, &machine.identifiers);
    let root = component("device", "machine".into(), root, properties);

    let mut components = Vec::new();

    for (index, processor) in cbom.hardware.processors.iter().enumerate() {
        let mut object = Map::new();
        object.insert(
            "name".into(),
            json!(processor.model.as_deref().unwrap_or("processor")),
        );
        if let Some(vendor) = &processor.vendor {
            object.insert("manufacturer".into(), json!({ "name": vendor }));
        }
        let properties = vec![
            property("architecture", &processor.architecture),
            property("logical_cores", processor.logical_cores),
        ];
        components.push(component(
            "device",
            format!("processor-{index}"),
            object,
            properties,
        ));
    }

    for disk in &cbom.hardware.disks {
        let mut object = Map::new();
        object.insert(
            "name".into(),
            json!(disk.model.as_deref().unwrap_or(&disk.name)),
        );
        if let Some(vendor) = &disk.vendor {
            object.insert("manufacturer".into(), json!({ "name": vendor }));
        }
        let mut properties = vec![property("device", &disk.name)];
        if let Some(serial) = &disk.serial {
            properties.push(property("serial", serial));
        }
        if let Some(version) = &disk.firmware_version {
            properties.push(property("firmware_version", version));
        }
        if let Some(size) = disk.size_bytes {
            properties.push(property("size_bytes", size));
        }
        components.push(component(
            "device",
            format!("disk-{}", disk.name),
            object,
            properties,
        ));
    }

    for (index, firmware) in cbom.firmware.components.iter().enumerate() {
        let mut object = Map::new();
        object.insert("name".into(), json!(format!("{} firmware", firmware.kind)));
        set(&mut object, "version", firmware.version.as_deref());
        set(&mut object, "publisher", firmware.vendor.as_deref());
        let mut properties = Vec::new();
        if let Some(date) = &firmware.release_date {
            properties.push(property("release_date", date));
        }
        set_identifiers(&mut object, &mut properties, &firmware.identifiers);
        components.push(component(
            "firmware",
            format!("firmware-{index}"),
            object,
            properties,
        ));
    }

    {
        let os = &cbom.operating_system;
        let mut object = Map::new();
        object.insert(
            "name".into(),
            json!(
                os.name
                    .as_deref()
                    .or(os.id.as_deref())
                    .unwrap_or(&os.family)
            ),
        );
        set(&mut object, "version", os.version.as_deref());
        set(&mut object, "description", os.pretty_name.as_deref());
        let mut properties = vec![property("architecture", &os.architecture)];
        if let Some(kernel) = &os.kernel_release {
            properties.push(property("kernel_release", kernel));
        }
        set_identifiers(&mut object, &mut properties, &os.identifiers);
        components.push(component(
            "operating-system",
            "operating-system".into(),
            object,
            properties,
        ));
    }

    for (index, software) in cbom.software.iter().enumerate() {
        let mut object = Map::new();
        object.insert("name".into(), json!(software.name));
        object.insert("version".into(), json!(software.version));
        set(&mut object, "publisher", software.vendor.as_deref());
        let mut properties = vec![property("source", &software.source)];
        set_identifiers(&mut object, &mut properties, &software.identifiers);
        components.push(component(
            "library",
            format!("software-{index}"),
            object,
            properties,
        ));
    }

    Ok(json!({
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": serial_number(cbom)?,
        "version": 1,
        "metadata": {
            "timestamp": cbom.collection.ended_at,
            "tools": {
                "components": [{
                    "type": "application",
                    "name": cbom.collection.tool.name,
                    "version": cbom.collection.tool.version,
                }]
            },
            "component": root,
        },
        "components": components,
    }))
}

/// Convertit un relevé en texte JSON CycloneDX 1.6, indenté.
pub fn export_json(cbom: &Cbom) -> Result<String> {
    let mut text =
        serde_json::to_string_pretty(&export(cbom)?).context(|| "export CycloneDX".into())?;
    text.push('\n');
    Ok(text)
}
