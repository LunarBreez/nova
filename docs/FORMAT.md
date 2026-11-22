# Format du relevé Nova (`nova-cbom` 1.1)

Référence exacte : [`schema/nova-cbom-1.schema.json`](../schema/nova-cbom-1.schema.json),
généré depuis le code (`nova schema`). Ce document en donne les règles.

## Deux fichiers

| Fichier | Contenu |
| --- | --- |
| `<AAAAMMJJ>_<machine>.cbom.json` | le relevé, un objet JSON |
| `<AAAAMMJJ>_<machine>.files.jsonl` | les empreintes : une ligne JSON par fichier, triées par chemin |

`<machine>` est l'identifiant d'inventaire s'il a été donné, sinon le nom
d'hôte. La liste des empreintes est séparée parce qu'elle peut compter des
centaines de milliers de lignes ; le relevé la référence dans sa rubrique
`files` et la **scelle** par son SHA-256 (`nova verify`).

## Règles

1. **Données brutes d'abord.** Éditeur, produit et version sont écrits tels
   que la machine les déclare. Les identifiants normalisés s'y ajoutent.
2. **Un identifiant dit d'où il vient** (`origin`) :
   - `computed` : construit depuis le gestionnaire de paquets, exact ;
   - `declared` : écrit par le système lui-même, exact ;
   - `candidate` : deviné depuis l'éditeur, le produit et la version, à
     confirmer contre une base de vulnérabilités.
3. **Une valeur inconnue est absente**, jamais une chaîne vide. Les valeurs de
   remplissage des constructeurs (`To Be Filled By O.E.M.`…) sont écartées.
4. **Ce qui n'a pas pu être lu est dit** dans `collection.warnings`.
5. **Ordre stable** : logiciels, interfaces, ports, services, comptes et
   fichiers sont triés.
6. **Adresses canoniques** : MAC en minuscules séparées par `:`, IPv6 selon la
   RFC 5952. Ce sont les formes des matrices de flux LFMS de Lunar.
7. **Dates en UTC**, RFC 3339.

## Rubriques

| Clé | Contenu |
| --- | --- |
| `format`, `format_version` | `nova-cbom`, `1.1` |
| `collection` | outil, méthode (`measured`, `imported`, `declared`), début et fin, droits, opérateur, avertissements |
| `asset` | identifiant d'inventaire, nom d'hôte, site |
| `hardware` | machine, processeurs, mémoire, disques |
| `firmware` | mode de démarrage, Secure Boot, firmwares |
| `operating_system` | distribution, version, noyau, architecture |
| `software` | paquets installés et leur PURL |
| `network.interfaces` | nom, MAC, nature, état, MTU, adresses |
| `network.listening_sockets` | protocole, adresse, port, processus |
| `services` | nom, gestionnaire, mode de démarrage, état |
| `accounts` | nom, uid, gid, répertoire, interpréteur |
| `files` | référence et sceau de la liste des empreintes |

`collection.method` vaut `measured` pour un relevé du collecteur. Les valeurs
`imported` et `declared` sont réservées aux équipements sur lesquels aucun
programme ne peut tourner (fichiers extraits, saisie manuelle).

## Liste des empreintes

```json
{"path":"/etc/hostname","size":11,"sha256":"…"}
{"path":"/etc/shadow","size":1432,"error":"permission denied"}
{"path":"/var/log/lastlog","size":337154048000,"error":"sparse file, not read"}
```

Le parcours ne suit aucun lien symbolique, ne lit que les fichiers ordinaires
et écarte par défaut `/proc`, `/sys`, `/dev` et `/run`.

- **Ordre.** Les lignes suivent un parcours en profondeur où chaque
  répertoire est lu trié par nom : `/a/x` vient avant `/a.b`. La liste est
  écrite au fil de l'eau ; un lecteur peut la lire ligne à ligne sans la
  charger en entier.
- **Fichiers creux.** Un fichier qui annonce plus de 1 Gio de vide (limite
  écrite dans `files.sparse_limit`) est listé avec sa taille, sans empreinte,
  avec la raison `sparse file, not read`. `files.sparse_skipped` les compte.
  Le lire n'apporterait presque que des zéros et peut durer des heures.
- **Autres systèmes de fichiers.** Si `files.one_file_system` est vrai, le
  parcours n'est pas entré dans les points de montage ; ils sont nommés dans
  `files.skipped_mounts`.

Depuis la version 1.1 : `one_file_system`, `skipped_mounts`, `sparse_limit`
et `sparse_skipped` dans `files`.

## Évolution

Le second nombre de `format_version` augmente quand des champs s'ajoutent ;
un lecteur doit ignorer les champs qu'il ne connaît pas. Le premier nombre
augmente quand un lecteur existant ne peut plus lire le relevé.
