# Privacy / Confidentialité

## English

Atlas stores connection metadata on your computer: process names and executable paths, PID, local/remote IPs and ports, protocol, state, observation timestamps, inferred DNS names, geolocation results and reputation matches. SQLite and its WAL files are stored under `%LOCALAPPDATA%\AtlasReseau`, unless `--data-dir` overrides it. Inactive connection history is retained for 30 days. Settings for the view and manually chosen map origin may also live in browser local storage. Executable icons are extracted locally. Packet payloads are not stored.

The local API listens on `127.0.0.1`, not the LAN. Host/Origin validation and a custom header protect write requests; this is not a security boundary against malicious software already running on your machine. Do not expose the port through a proxy or tunnel.

Outgoing requests:

| Feature | Destination | Information sent |
| --- | --- | --- |
| Reputation updates (enabled by default) | spamhaus.org, raw.githubusercontent.com | Fixed list URLs; no observed connection list |
| Geolocation (opt-in each launch) | ipwho.is | Public destination IP being located |
| Online map tiles (optional) | OpenStreetMap tile servers | Requested tile coordinates/zoom |

All remote services also see the request's source IP and normal HTTP metadata. Geolocation does not send process names or executable paths. Reputation matching happens locally. DNS names are read from Windows' existing cache. Offline map geometry is embedded. For offline operation pass `--offline-lists` and leave geolocation and online tiles disabled.

To remove history, first stop Atlas, then delete only its data folder (or the custom folder you explicitly selected). Clear the site's browser storage to remove view settings. Deleting files is not guaranteed secure erasure. Never attach an unredacted database, network screenshot or log to a public issue.

## Français

Atlas stocke localement les métadonnées : noms et chemins des processus, PID, IP/ports locaux et distants, protocole, état, dates, noms DNS déduits, géolocalisations et correspondances de réputation. La base SQLite et ses fichiers WAL sont dans `%LOCALAPPDATA%\AtlasReseau`, sauf option `--data-dir`. L'historique inactif est conservé 30 jours. Les réglages d'affichage et l'origine manuelle de la carte peuvent être dans le stockage local du navigateur. Les icônes sont extraites localement. Aucun contenu de paquet n'est enregistré.

L'API écoute sur `127.0.0.1`, pas sur le réseau local. Les validations Host/Origin et l'en-tête personnalisé des écritures ne protègent pas contre un logiciel malveillant déjà présent sur le PC. N'exposez pas ce port par proxy ou tunnel.

Les mises à jour de listes, activées par défaut, contactent spamhaus.org et raw.githubusercontent.com avec des URL fixes, sans transmettre les connexions observées. La géolocalisation, facultative à chaque lancement, envoie les IP publiques de destination à ipwho.is. Les tuiles facultatives OpenStreetMap transmettent les coordonnées des tuiles et le zoom. Ces services voient aussi l'IP de la requête et ses métadonnées HTTP. Les noms/chemins des processus ne sont pas transmis au service de géolocalisation. La comparaison des listes et la lecture du cache DNS Windows sont locales.

Pour fonctionner hors ligne : `--offline-lists`, géolocalisation et tuiles en ligne désactivées. Pour supprimer l'historique, arrêtez Atlas puis supprimez uniquement son dossier de données (ou le dossier personnalisé choisi). Effacez le stockage du site dans le navigateur pour les réglages d'affichage. Cela ne garantit pas un effacement sécurisé du disque. Ne joignez jamais de base, capture réseau ou journal non anonymisé à une issue publique.
