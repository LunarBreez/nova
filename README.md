# Nova

Relevé **CBOM** (Cyber Bill of Materials) d'une machine, hors ligne.

Un SBOM décrit un logiciel. Un système industriel est aussi fait de matériel,
de firmware, d'un système d'exploitation et d'une configuration, souvent sur
des postes isolés. Nova relève tout cela en une commande, sans connexion et
sans rien installer sur la cible, et l'écrit dans un format structuré.

Un relevé décrit **une** machine :

| Rubrique | Contenu |
| --- | --- |
| Matériel | constructeur, modèle, numéro de série, processeurs, mémoire, disques |
| Firmware | BIOS ou UEFI, microcode, mode de démarrage, Secure Boot |
| Système | distribution, version, noyau, architecture |
| Logiciels | paquets installés (dpkg, rpm, apk, pacman) |
| Réseau | interfaces avec MAC et adresses IP, ports à l'écoute et leur processus |
| Services | services systemd, mode de démarrage, état |
| Comptes | comptes locaux |
| Fichiers | SHA-256 de tous les fichiers du système |

## État

Version 0.1, premier jalon.

- Le collecteur relève **Linux** (x86 et ARM). Windows et macOS ne sont pas
  encore pris en charge : `nova collect` y répond par une erreur claire, les
  autres commandes y fonctionnent.
- Nova **ne recherche pas de vulnérabilités** : il fournit les identifiants
  (PURL, CPE) qu'un outil doté d'une base de vulnérabilités saura rapprocher.

## Construire

```bash
cargo build --release          # la commande : target/release/nova
cargo build --release -p nova-gui   # l'interface gpui, sur demande
```

La commande n'a aucune dépendance système. L'interface s'appuie sur
[gpui](https://www.gpui.rs/) et demande ses bibliothèques (Vulkan, X11 ou
Wayland, xkbcommon).

## Utiliser

```bash
sudo nova collect --output releves --asset-id PC-000042 --site "Usine Nord"
```

écrit deux fichiers :

- `20261122_PC-000042.cbom.json` : le relevé ;
- `20261122_PC-000042.files.jsonl` : les empreintes, une ligne JSON par fichier.

Sans `sudo`, le relevé fonctionne mais signale ce qu'il n'a pas pu lire :
numéro de série, processus des autres comptes, fichiers protégés.

| Commande | Effet |
| --- | --- |
| `nova collect` | relève la machine |
| `nova collect --no-files` | relève sans les empreintes de fichiers |
| `nova collect --files-root /opt --exclude /opt/cache` | limite les empreintes à une arborescence |
| `nova verify RELEVE.cbom.json` | vérifie que la liste d'empreintes est celle que le relevé scelle |
| `nova export cyclonedx RELEVE.cbom.json` | exporte les composants en CycloneDX 1.6 |
| `nova schema` | affiche le schéma JSON du format |

L'interface fait la même chose dans une fenêtre :

```bash
nova-gui [--no-files] [--start] [DOSSIER]
```

## Garanties

- **Lecture seule** : Nova ne modifie rien sur la machine relevée, hormis les
  fichiers du relevé dans le dossier de sortie.
- **Aucune émission réseau** : rien n'est envoyé, rien n'est téléchargé.
- **Rien n'est tu** : ce que le relevé n'a pas pu lire figure dans ses
  avertissements ; un fichier illisible reste listé, sans empreinte, avec la
  raison.
- **Outils système de confiance** : les rares outils appelés (`systemctl`,
  `rpm`) sont cherchés dans les répertoires système, jamais dans `PATH`.

## Format

Le format du relevé est décrit dans [docs/FORMAT.md](docs/FORMAT.md) et par le
schéma [schema/nova-cbom-1.schema.json](schema/nova-cbom-1.schema.json).

Le relevé Nova est la référence. L'export CycloneDX en est déduit et ne
reprend que ce que ce standard sait décrire : machine, processeurs, disques,
firmwares, système et logiciels, avec leurs PURL et CPE. La configuration
(interfaces, ports, services, comptes) et les empreintes de fichiers n'y
figurent pas.

### PURL et CPE

- Un **PURL** se calcule depuis le gestionnaire de paquets : il est exact hors
  ligne.
- Un **CPE** ne se calcule pas : ses noms sont attribués par le NVD. Nova
  reprend celui que le système déclare quand il existe ; sinon il écrit un
  CPE **candidat**, marqué comme tel, que l'outil détenteur de la base de
  vulnérabilités doit confirmer.

Dans tous les cas, l'éditeur, le produit et la version sont écrits tels que
la machine les donne : un identifiant deviné à tort ne fait perdre aucune
information.

## Avec Lunar

[Lunar](https://github.com/LunarBreez/Lunar) relève ce qui est **observé sur le
réseau** et l'exporte en matrice de flux LFMS. Nova relève ce que la machine
**déclare d'elle-même**. Le couple (MAC, IP) de chaque interface, écrit sous la
même forme canonique des deux côtés, permet de rattacher un relevé aux
conversations d'une matrice.

## Développer

```bash
cargo fmt --all --check
cargo clippy --all-targets -- -D warnings
cargo test
```

Le schéma versionné est vérifié par les tests ; après un changement du
format : `cargo run -- schema > schema/nova-cbom-1.schema.json`.

## Licence

AGPL-3.0-only. Voir [LICENSE](LICENSE).
