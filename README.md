# Nsharp - Network Scanner

Un scanner réseau léger et rapide développé en .NET 8 avec une interface Blazor Server. Ce projet permet d'effectuer des scans de ports TCP, de détecter les services en cours d'exécution et de générer des rapports PDF, le tout sans dépendances externes lourdes.

## 🚀 Démarrage rapide

### Prérequis
- [.NET 8.0 SDK](https://dotnet.microsoft.com/download/dotnet/8.0)
- [Docker](https://www.docker.com/) (optionnel)

### Méthode 1 : Avec Docker (Recommandé)

```bash
# Construire l'image
docker build -t nsharp .

# Lancer le conteneur
docker run -p 8080:8080 nsharp
```
L'application sera accessible sur **http://localhost:8080**

### 💡 Conseil : Accès réseau complet (mode Host)

Pour permettre au scanner d'accéder directement aux interfaces réseau de la machine hôte (idéal pour scanner le LAN ou `localhost` sans isolation), utilisez l'option `--network host` (recommandé sous Linux) :

```bash
docker run --network host nsharp
```
*Note : Sur macOS et Windows, le mode host fonctionne différemment. Pour scanner la machine hôte, utilisez la cible `host.docker.internal`.*

### Méthode 2 : Avec dotnet CLI

```bash
# Clonez le dépôt
git clone https://github.com/votre-user/Nsharp.git
cd Nsharp

# Lancez l'application
dotnet run
```
L'application sera accessible sur **http://localhost:5224**

Pour le développement avec rechargement à chaud (Hot Reload) :
```bash
dotnet watch run
```

## 📋 Fonctionnalités

- **Scan de Ports TCP** : Scan rapide multi-threadé pour identifier les ports ouverts.
- **Détection de Services** : Identification avancée des protocoles (HTTP, SSH, FTP, SMTP, DNS, etc.) via analyse des bannières et requêtes spécifiques.
- **Détection d'OS** : Estimation du système d'exploitation basée sur le TTL (Time To Live).
- **Rapport PDF** : Génération native de rapports PDF détaillés (sans librairie tierce).
- **Interface Réactive** : UI moderne construite avec Blazor Server et Bootstrap.
- **Mode Sombre/Clair** : Support natif du thème système.

## 🛠️ Architecture et Technologies

Ce projet est conçu pour être minimaliste et autonome :

- **Framework** : .NET 8 (Blazor Server)
- **Réseau** : `System.Net.Sockets` pour les connexions TCP brutes.
- **PDF** : Générateur PDF personnalisé implémenté "from scratch" (aucune dépendance type iText ou QuestPDF).
- **Interface** : Razor Components + CSS Scoped + Bootstrap.

### Structure du projet

```
Nsharp/
├── Components/          # Composants UI Blazor
│   ├── Pages/           # Pages (Home, etc.)
│   └── Layout/          # Layouts (NavMenu, MainLayout)
├── Services/            # Logique métier
│   ├── NetworkScanner.cs           # Moteur de scan principal
│   ├── AdvancedServiceDetector.cs  # Logique de fingerprinting des services
│   └── PdfReportService.cs         # Générateur de PDF natif
├── Models/              # Modèles de données (ScanResult, etc.)
└── wwwroot/             # Ressources statiques (CSS, JS)
```

## 🔧 Configuration

Le scanner est configuré pour être performant par défaut :
- **Concurrence** : Scanne plusieurs ports en parallèle pour plus de rapidité.
- **Timeouts** : Délais ajustés pour éviter les blocages sur les ports filtrés.

## 📄 Rapports

Les rapports PDF générés sont stockés temporairement sur le serveur (dans le dossier temporaire du système) et peuvent être téléchargés directement depuis l'interface après un scan.
