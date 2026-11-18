# Atlas

[English](README.md) · [Télécharger pour Windows](https://github.com/dandyArise/Atlas/releases/latest) · [Compilations](https://github.com/dandyArise/Atlas/actions)

**Voyez où se connectent vos applications Windows.** Atlas est un moniteur réseau écrit en Rust, avec carte du monde, icônes des applications, historique local et alertes de réputation. Inspiré de la visibilité offerte par Little Snitch, ce projet est indépendant et sans affiliation.

Atlas **observe les connexions** : il ne bloque pas le trafic et ne remplace pas un pare-feu. L'interface est actuellement en français ; la documentation existe en français et en anglais.

## Fonctionnalités

- Connexions TCP actives associées aux processus Windows.
- Activité UDP collectée avec Windows ETW en mode administrateur.
- UDP sur le port 443 signalé **« QUIC possible »** : une heuristique, pas une identification certaine.
- Carte avec destinations, lignes de connexion schématiques et icônes extraites localement des applications.
- Regroupement par application, pays, nom DNS possible ou serveur ; recherche et filtres par protocole, pays, alerte et date.
- Historique SQLite local ; conservation des enregistrements inactifs pendant 30 jours.
- Comparaison locale avec Spamhaus DROP IPv4/IPv6 et les domaines StevenBlack, avec indication de la source des alertes.
- Fond de carte embarqué hors ligne ; géolocalisation IP et tuiles OpenStreetMap facultatives.

## Télécharger et lancer

Windows 10/11 x64 et un navigateur moderne sont nécessaires. Téléchargez `Atlas-<version>-windows-x64.zip` et `SHA256SUMS.txt` dans les [Releases](https://github.com/dandyArise/Atlas/releases), puis extrayez l'archive dans un dossier vous appartenant. Rust n'est pas nécessaire pour utiliser l'EXE.

1. Double-cliquez sur **Start-Atlas.cmd** pour observer le TCP.
2. Pour l'UDP, utilisez **Start-Atlas-UDP.cmd** et acceptez l'invite UAC. Arrêtez d'abord une instance non élevée avec **Stop-Atlas.cmd**.
3. Le navigateur ouvre **http://127.0.0.1:47831/**. Activez la géolocalisation dans l'interface pour placer les destinations publiques sur la carte.
4. Utilisez **Stop-Atlas.cmd** pour arrêter le collecteur. Fermer le navigateur ne l'arrête pas.

Double-cliquez sur les fichiers `.cmd` dans l'Explorateur : ne collez pas leur contenu batch dans PowerShell. Les exécutables ne sont pas signés ; Windows peut afficher un avertissement d'éditeur inconnu. Vérifiez le ZIP avec la somme publiée :

```powershell
Get-FileHash .\Atlas-0.2.1-windows-x64.zip -Algorithm SHA256
```

## Confidentialité et accès réseau

L'historique est conservé dans `%LOCALAPPDATA%\AtlasReseau\history.sqlite` : noms et chemins des processus, adresses et horodatages notamment. Atlas ne le téléverse pas. Le serveur HTTP écoute uniquement sur localhost et vérifie l'origine des requêtes locales. La base, les exports et les captures d'écran doivent rester privés.

La géolocalisation facultative transmet les IP publiques de destination à **ipwho.is**. Les tuiles facultatives contactent **OpenStreetMap**. Les listes de réputation sont téléchargées au démarrage si nécessaire puis actualisées quotidiennement ; la comparaison est locale. Ces services voient l'IP à l'origine des requêtes. La géolocalisation est désactivée après chaque redémarrage. Voir les [détails de confidentialité](docs/PRIVACY.md) et les [mentions tierces](THIRD_PARTY_NOTICES.md).

## Limites

- La géolocalisation IP est approximative. Une ligne sur la carte ne représente pas le trajet des paquets. Les IP privées/locales ne sont pas géolocalisées. L'origine peut être placée manuellement.
- Les destinations UDP nécessitent ETW avec élévation ; elles restent actives environ 30 secondes après un événement observé. Aucun contenu de paquet n'est enregistré.
- QUIC peut utiliser d'autres ports ; UDP/443 peut transporter autre chose.
- Les domaines sont déduits du cache DNS Windows : ils peuvent manquer ou être ambigus, notamment avec les IP partagées et le DNS chiffré.
- La carte affiche la page courante (200 connexions au maximum) ; les compteurs peuvent couvrir tous les résultats filtrés.
- Une liste fournit un indice, pas une preuve d'activité malveillante. Les alertes de domaines dépendent des observations DNS. Pas de blocage automatique, de réanalyse rétroactive de l'historique ni de notification de bureau.

## Compiler et vérifier

Installez Rust avec la chaîne MSVC, Visual Studio Build Tools (développement Desktop en C++), Python 3.11+ et Node.js (vérification de syntaxe JavaScript uniquement).

```powershell
cargo fmt --check
cargo clippy --locked -- -D warnings
cargo test --locked
node --check web/app.js
cargo build --release --locked
python verify.py target/release/atlas-reseau.exe
powershell -NoProfile -File scripts/package.ps1
```

`verify.py` utilise une base temporaire et un port localhost disponible, désactive les téléchargements de listes et vérifie la collecte TCP, les contrôles d'accès de l'API, les ressources, les icônes, la persistance et l'arrêt. Il ne prouve pas la collecte UDP/QUIC réelle ni la disponibilité des services externes. Un test de géolocalisation en ligne est ignoré par défaut.

Le workflow Windows exécute ces contrôles sur les push et pull requests puis produit un ZIP portable et ses sommes SHA-256. Un tag `v<version>` correspondant à `Cargo.toml` publie aussi une release GitHub après réussite. Les releases sont compilées sur GitHub, sans utiliser le dossier d'historique d'un utilisateur.

Options avancées : `atlas-reseau.exe --port 47832 --data-dir <dossier>` ; `--offline-lists` désactive les téléchargements de listes. Le fond de carte par défaut est embarqué ; n'activez ni géolocalisation ni tuiles en ligne pour un usage hors ligne.

## Contribution et licence

Voir [CONTRIBUTING.md](CONTRIBUTING.md) et [SECURITY.md](SECURITY.md). Ne publiez pas d'historique réel, de chemin personnel ou de capture non anonymisée dans les issues publiques.

Le code Atlas est sous [licence MIT](LICENSE). Les dépendances, données cartographiques et listes externes conservent leurs licences propres. Les archives incluent les mentions de licence des dépendances.
