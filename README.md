# Nsharp Scanner - Version Blazor Server

Scanner réseau professionnel avec détection avancée de services et génération de rapports PDF.

## 🚀 Lancement du projet

### Méthode 1 : Avec dotnet CLI
```bash
cd /Users/aymenebelmeguenai/NsharpBlazor
dotnet run
```

Puis ouvrez votre navigateur sur **http://localhost:5000**

### Méthode 2 : Mode développement avec rechargement automatique
```bash
cd /Users/aymenebelmeguenai/NsharpBlazor
dotnet watch run
```

## 📋 Fonctionnalités

✅ **Scan réseau rapide** (TCP Connect + SYN scan si privilèges root)
✅ **Détection avancée de services** (HTTP, HTTPS, SSH, FTP, SMTP, CUPS/IPP, etc.)
✅ **Détection d'OS** basée sur TTL et services
✅ **Interface moderne** adaptée au mode clair/sombre
✅ **Export PDF** des résultats de scan
✅ **Architecture Blazor Server** pour une expérience web réactive

## 🛠️ Technologies

- **.NET 8** - Framework principal
- **Blazor Server** - Framework UI interactif
- **SharpPcap** - Capture de paquets réseau
- **PacketDotNet** - Manipulation de paquets TCP/IP

## 📦 Structure du projet

```
NsharpBlazor/
├── Components/
│   └── Pages/
│       └── Home.razor          # Interface principale
├── Services/
│   ├── NetworkScanner.cs       # Logique de scan
│   ├── AdvancedServiceDetector.cs
│   ├── SynScanner.cs
│   └── PdfReportService.cs
├── Models/
│   ├── ScanResult.cs
│   └── ScanResponse.cs
├── wwwroot/
│   └── app.css                 # Styles personnalisés
└── Program.cs                  # Configuration Blazor

```

## 🔧 Configuration

Pour utiliser le scan SYN (plus rapide), exécutez avec les privilèges root/admin :
```bash
sudo dotnet run
```

Sinon, le scanner utilisera automatiquement un fallback TCP Connect.

## 📄 Export PDF

Les PDFs générés sont sauvegardés dans : `/tmp/scan_report_YYYYMMDD_HHMMSS.pdf`

## 🎨 Interface

- **Panel gauche** : Configuration du scan (cible, ports, options)
- **Panel droit** : Résultats détaillés avec informations de service
- **Thème adaptatif** : S'adapte automatiquement au mode clair/sombre du système

## ⚠️ Notes importantes

- Le scan SYN nécessite des privilèges élevés (root/admin)
- Le scan peut prendre du temps selon le nombre de ports
- Les PDFs sont générés côté serveur

---

**Développé avec ❤️ en .NET 8 + Blazor Server**

