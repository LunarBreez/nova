//! Relevé de bout en bout sur une arborescence système d'essai.

#![cfg(target_os = "linux")]
#![allow(clippy::unwrap_used)]

use std::fs;
use std::path::{Path, PathBuf};

use nova_core::model::{BootMode, InterfaceKind, Origin, Transport};
use nova_core::{collect, cyclonedx, files, output};

/// Écrit un fichier sous la racine d'essai, en créant ses répertoires.
fn put(root: &Path, path: &str, content: &str) {
    let path = root.join(path.trim_start_matches('/'));
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, content).unwrap();
}

/// Construit une petite machine Debian fictive.
fn fake_machine(name: &str) -> PathBuf {
    let root = std::env::temp_dir().join(format!("nova-releve-{name}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&root);
    put(&root, "/proc/sys/kernel/hostname", "automate-01\n");
    put(&root, "/proc/sys/kernel/osrelease", "6.1.0-28-amd64\n");
    put(&root, "/proc/sys/kernel/arch", "x86_64\n");
    put(
        &root,
        "/etc/os-release",
        "NAME=\"Debian GNU/Linux\"\nID=debian\nVERSION_ID=\"12\"\nPRETTY_NAME=\"Debian GNU/Linux 12 (bookworm)\"\n",
    );
    put(&root, "/sys/class/dmi/id/sys_vendor", "Acme Industrie\n");
    put(&root, "/sys/class/dmi/id/product_name", "IPC-500\n");
    put(
        &root,
        "/sys/class/dmi/id/product_version",
        "To Be Filled By O.E.M.\n",
    );
    put(&root, "/sys/class/dmi/id/product_serial", "SN123456\n");
    put(&root, "/sys/class/dmi/id/bios_vendor", "Acme BIOS\n");
    put(&root, "/sys/class/dmi/id/bios_version", "1.4.2\n");
    put(&root, "/sys/class/dmi/id/bios_date", "03/12/2021\n");
    put(
        &root,
        "/proc/cpuinfo",
        "processor\t: 0\nvendor_id\t: GenuineIntel\nmodel name\t: Intel(R) Atom(TM) E3845\nmicrocode\t: 0x90d\n\nprocessor\t: 1\nvendor_id\t: GenuineIntel\nmodel name\t: Intel(R) Atom(TM) E3845\nmicrocode\t: 0x90d\n",
    );
    put(&root, "/proc/meminfo", "MemTotal:        4000000 kB\n");
    put(&root, "/sys/block/sda/size", "1000\n");
    put(&root, "/sys/block/sda/removable", "0\n");
    put(&root, "/sys/block/sda/device/model", "INDUSTRIAL SSD  \n");
    put(&root, "/sys/block/loop0/size", "8\n");
    put(
        &root,
        "/var/lib/dpkg/status",
        "Package: openssh-server\nStatus: install ok installed\nArchitecture: amd64\nVersion: 1:9.2p1-2+deb12u3\n\nPackage: bash\nStatus: install ok installed\nArchitecture: amd64\nVersion: 5.2.15-2+b7\n",
    );
    put(&root, "/sys/class/net/eth0/address", "00:1B:44:11:3A:B7\n");
    put(&root, "/sys/class/net/eth0/operstate", "up\n");
    put(&root, "/sys/class/net/eth0/mtu", "1500\n");
    put(&root, "/sys/class/net/eth0/type", "1\n");
    put(&root, "/sys/class/net/eth0/device/vendor", "0x8086\n");
    put(&root, "/sys/class/net/lo/address", "00:00:00:00:00:00\n");
    put(&root, "/sys/class/net/lo/type", "772\n");
    put(
        &root,
        "/proc/net/if_inet6",
        "fe80000000000000021b44fffe113ab7 02 40 20 80     eth0\n",
    );
    put(
        &root,
        "/proc/net/tcp",
        "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n   0: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 777 1 0 100 0 0 10 0\n",
    );
    put(
        &root,
        "/etc/passwd",
        "root:x:0:0:root:/root:/bin/bash\noperateur:x:1000:1000::/home/operateur:/bin/bash\n",
    );
    root
}

fn options(root: &Path, with_files: bool) -> collect::Options {
    collect::Options {
        sysroot: root.to_path_buf(),
        asset_id: Some("PC-000042".into()),
        site: Some("Usine Nord".into()),
        operator: None,
        files: with_files.then(|| files::Options::for_root(root.join("etc"))),
    }
}

#[test]
fn collects_a_fake_machine() {
    let root = fake_machine("collect");
    let cbom = collect::collect(&options(&root, false)).unwrap().cbom;

    assert_eq!(cbom.format, "nova-cbom");
    assert_eq!(cbom.asset.hostname, "automate-01");
    assert_eq!(cbom.asset.id.as_deref(), Some("PC-000042"));
    assert!(!cbom.collection.privileged);

    let machine = &cbom.hardware.machine;
    assert_eq!(machine.vendor.as_deref(), Some("Acme Industrie"));
    assert_eq!(machine.serial.as_deref(), Some("SN123456"));
    assert_eq!(
        machine.version, None,
        "une valeur de remplissage n'est pas une information"
    );
    assert_eq!(
        machine.identifiers[0].value,
        "cpe:2.3:h:acme_industrie:ipc-500:*:*:*:*:*:*:*:*"
    );
    assert_eq!(machine.identifiers[0].origin, Origin::Candidate);
    assert_eq!(cbom.hardware.processors[0].logical_cores, 2);
    assert_eq!(cbom.hardware.memory_bytes, Some(4_096_000_000));
    assert_eq!(cbom.hardware.disks.len(), 1, "loop0 n'est pas un disque");
    assert_eq!(
        cbom.hardware.disks[0].model.as_deref(),
        Some("INDUSTRIAL SSD")
    );
    assert_eq!(cbom.hardware.disks[0].size_bytes, Some(512_000));

    assert_eq!(cbom.firmware.boot_mode, Some(BootMode::Legacy));
    assert_eq!(cbom.firmware.components.len(), 2);
    assert_eq!(
        cbom.firmware.components[0].identifiers[0].value,
        "cpe:2.3:o:acme_industrie:ipc-500_firmware:1.4.2:*:*:*:*:*:*:*"
    );

    let os = &cbom.operating_system;
    assert_eq!(os.kernel_release.as_deref(), Some("6.1.0-28-amd64"));
    assert_eq!(
        os.identifiers[0].value,
        "cpe:2.3:o:debian:debian_linux:12:*:*:*:*:*:*:*"
    );

    let names: Vec<_> = cbom.software.iter().map(|s| s.name.as_str()).collect();
    assert_eq!(names, ["bash", "openssh-server"]);
    assert_eq!(
        cbom.software[1].identifiers[0].value,
        "pkg:deb/debian/openssh-server@1:9.2p1-2%2Bdeb12u3?arch=amd64&distro=debian-12"
    );

    let interfaces = &cbom.network.interfaces;
    assert_eq!(interfaces.len(), 2);
    assert_eq!(interfaces[0].name, "eth0");
    assert_eq!(interfaces[0].mac.as_deref(), Some("00:1b:44:11:3a:b7"));
    assert_eq!(interfaces[0].kind, InterfaceKind::Physical);
    assert_eq!(interfaces[0].addresses[0].ip, "fe80::21b:44ff:fe11:3ab7");
    assert_eq!(interfaces[1].kind, InterfaceKind::Loopback);
    assert_eq!(interfaces[1].mac, None);

    let sockets = &cbom.network.listening_sockets;
    assert_eq!(sockets.len(), 1);
    assert_eq!(sockets[0].protocol, Transport::Tcp);
    assert_eq!(
        (sockets[0].address.as_str(), sockets[0].port),
        ("0.0.0.0", 22)
    );

    assert_eq!(cbom.accounts.len(), 2);
    fs::remove_dir_all(&root).unwrap();
}

#[test]
fn writes_reads_back_verifies_and_exports() {
    let root = fake_machine("write");
    let out = root.join("sortie");
    let collected = collect::collect(&options(&root, true)).unwrap();
    let (cbom, written) = output::write(&out, collected).unwrap();

    let name = written
        .cbom
        .file_name()
        .unwrap()
        .to_string_lossy()
        .into_owned();
    assert!(name.ends_with("_PC-000042.cbom.json"), "{name}");
    let inventory = cbom.files.as_ref().unwrap();
    assert_eq!(inventory.entries, 2);
    assert_eq!(inventory.unreadable, 0);

    let read_back = output::read(&written.cbom).unwrap();
    assert_eq!(read_back, cbom);
    assert_eq!(output::verify_files(&written.cbom, &read_back).unwrap(), 2);

    // Une liste modifiée après coup n'est plus celle que le relevé scelle.
    let list = written.files.unwrap();
    let mut tampered = fs::read_to_string(&list).unwrap();
    tampered.push_str("{\"path\":\"/etc/ajout\"}\n");
    fs::write(&list, tampered).unwrap();
    assert!(output::verify_files(&written.cbom, &read_back).is_err());

    let first = cyclonedx::export_json(&cbom).unwrap();
    assert_eq!(
        first,
        cyclonedx::export_json(&cbom).unwrap(),
        "export déterministe"
    );
    let document: serde_json::Value = serde_json::from_str(&first).unwrap();
    assert_eq!(document["specVersion"], "1.6");
    assert_eq!(document["metadata"]["component"]["name"], "IPC-500");
    let components = document["components"].as_array().unwrap();
    let kinds: Vec<_> = components
        .iter()
        .map(|c| c["type"].as_str().unwrap())
        .collect();
    assert_eq!(
        kinds,
        [
            "device",
            "device",
            "firmware",
            "firmware",
            "operating-system",
            "library",
            "library"
        ]
    );
    let os = &components[4];
    assert_eq!(os["cpe"], "cpe:2.3:o:debian:debian_linux:12:*:*:*:*:*:*:*");
    assert_eq!(os["properties"][2]["value"], "candidate");
    fs::remove_dir_all(&root).unwrap();
}

#[test]
fn refuses_a_file_that_is_not_a_releve() {
    let dir = std::env::temp_dir().join(format!("nova-releve-refus-{}", std::process::id()));
    fs::create_dir_all(&dir).unwrap();
    let path = dir.join("autre.json");
    fs::write(&path, "{\"bomFormat\":\"CycloneDX\"}").unwrap();
    assert!(output::read(&path).is_err());
    fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn committed_schema_matches_the_code() {
    let committed = include_str!("../../../schema/nova-cbom-1.schema.json");
    assert_eq!(
        committed,
        nova_core::json_schema(),
        "schéma périmé : relancer `nova schema > schema/nova-cbom-1.schema.json`"
    );
}
