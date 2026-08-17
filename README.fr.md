# Infrastrukturhelden Script Collection

Scripts PowerShell et utilitaires d'infrastructure de Fabian Niesen.

- Versions linguistiques : [English](README.md) | [Deutsch](README.de.md) | [Español](README.es.md) | [Français](README.fr.md)

> **Note de traduction**
> Les fichiers README non anglais ont été créés avec l'aide de l'IA pour faciliter l'utilisation. En cas d'ambiguïté, `README.md` fait foi.

- Blog allemand : [https://www.infrastrukturhelden.de](https://www.infrastrukturhelden.de)
- Blog anglais : [https://www.infrastructureheroes.org/](https://www.infrastructureheroes.org/)

> **Avertissement**
> Ce dépôt et tous les scripts inclus sont fournis « en l'état », sans garantie ni condition d'aucune sorte, expresse ou implicite, y compris notamment la qualité marchande, l'adéquation à un usage particulier et l'absence de contrefaçon.
> Vous êtes seul responsable de l'examen, des tests et de la validation de chaque script avant toute utilisation. L'auteur et les contributeurs ne pourront être tenus responsables de tout dommage direct, indirect, accessoire, consécutif ou spécial résultant de l'utilisation ou du mauvais usage de ces scripts.

## Aperçu du dépôt

Ce dépôt contient des scripts d'administration pour :

- Opérations Active Directory et identité
- Chiffrement BitLocker et des postes
- Stratégie de groupe (GPO)
- Opérations WSUS et contrôles de santé
- Création de packages Intune et dépannage
- Configuration des outils Azure
- Diagnostic réseau et configuration client
- Tâches de maintenance Exchange
- Automatisation du cycle de vie des utilisateurs
- Durcissement et nettoyage de Windows
- Listes d'autorisation Linux/Squid pour proxys d'entreprise

## Table des matières

- [Aperçu du dépôt](#aperçu-du-dépôt)
- [Inventaire des scripts](#inventaire-des-scripts)
  - [Scripts racine](#scripts-racine)
  - [ActiveDirectory](#activedirectory)
  - [Azure](#azure)
  - [BitLocker](#bitlocker)
  - [Exchange](#exchange)
  - [GPO](#gpo)
  - [Intune](#intune)
  - [Linux-Files](#linux-files)
  - [Network](#network)
  - [User](#user)
  - [Windows](#windows)
  - [WSUS](#wsus)
- [Modèles de GPO](#modèles-de-gpo)
- [Fichiers supplémentaires](#fichiers-supplémentaires)
- [Notes](#notes)


## Inventaire des scripts

Les tableaux ci-dessous sont générés par [`Tools/Update-Readme.ps1`](./Tools/Update-Readme.ps1). Les textes d'objet sont maintenus dans [`Tools/readme-inventory.json`](./Tools/readme-inventory.json) ; la version, la licence et les liens d'articles proviennent des en-têtes des scripts. Ne modifiez pas les tableaux à la main.

> **Notes version/licence**
> - **Version** : déterminée dans cet ordre : variable `$ScriptVersion` dans le script, puis `$script:BuildVer`, puis le premier mot de `Version    :` dans l'en-tête, sinon `n/d`.
> - **Licence** : lue sur la ligne `License    :` de l'en-tête, à défaut sur une mention de licence explicite de l'en-tête. Si aucune n'existe, `Non spécifiée`.
> - **Article** : issu de la section `.LINK` de l'en-tête (`EN` = infrastructureheroes.org, `DE` = infrastrukturhelden.de).

<!-- BEGIN GENERATED: inventory -->
### Scripts racine

| Fichier | Objet | Version | Licence | Article |
|---|---|---|---|---|
| `Set-WinRelease.ps1` | Définir des clés de registre pour maintenir Windows sur une version précise (version cible des mises à jour de fonctionnalités). | 1.1 | Licence MIT (MIT) | &ndash; |
| `Get-WindowsSid.ps1` | Collecter les SID Windows des ordinateurs AD accessibles via Sysinternals PSGetSid. | 1.2 | Licence MIT (MIT) | [EN](https://www.infrastructureheroes.org/microsoft-infrastructure/microsoft-windows/the-windows-sid-and-an-old-problem/) / [DE](https://www.infrastrukturhelden.de/microsoft-infrastruktur/microsoft-windows/die-windows-sid-und-ein-altes-problem/) |
| `install-greenshot.ps1` | Installer la version ZIP de Greenshot et créer les entrées du menu Démarrer. | 1.1 | Licence MIT (MIT) | &ndash; |
| `Set-Network.ps1` | Appliquer les paramètres réseau courants (domaine DNS, NetBIOS, IPv6). | 1.2 | Licence MIT (MIT) | &ndash; |
| `New-DokuwikiAnimal.ps1` | Créer une structure DokuWiki « animal » avec les groupes AD et les partages correspondants. | 0.1 | Licence MIT (MIT) | &ndash; |
| `send-files.ps1` | Envoyer par e-mail les fichiers d'un répertoire. | 1.3 | Licence MIT (MIT) | [DE](https://www.infrastrukturhelden.de/?p=13527) |
| `generate-hosts.ps1` | Générer un fichier hosts à partir d'Active Directory. | 1.1 | Licence MIT (MIT) | &ndash; |

### ActiveDirectory

| Fichier | Objet | Version | Licence | Article |
|---|---|---|---|---|
| `ActiveDirectory/Configure-AD.ps1` | Configurer un domaine AD (corbeille, préparation gMSA, magasin central, stratégies de mot de passe, structure d'OU). | 0.2 | Licence MIT (MIT) | &ndash; |
| `ActiveDirectory/Get-ADPermissionsReport.ps1` | Exporter un rapport CSV des autorisations Active Directory. | 0.2 | Non spécifiée | &ndash; |
| `ActiveDirectory/Get-DFSRBacklog.ps1` | Contrôler le backlog DFSR et générer des rapports de réplication (export CSV et comparaison de hachages en option). | 0.5 | GNU General Public License v3 (GPLv3) | &ndash; |
| `ActiveDirectory/Get-LAPSAuditReport.ps1` | Interroger les événements de sécurité liés à l'audit de Microsoft LAPS. | n/d | Non spécifiée | &ndash; |
| `ActiveDirectory/Get-LocalNTLMlogs.ps1` | Analyser et classifier les événements locaux `Microsoft-Windows-NTLM/Operational`. | 1.0 | GNU General Public License v3 (GPLv3) | &ndash; |
| `ActiveDirectory/Get-NTLMLogons.ps1` | Analyser les journaux de sécurité pour les ouvertures de session NTLM et l'usage de l'authentification. | 1.3 | GNU General Public License v3 (GPLv3) | &ndash; |
| `ActiveDirectory/Get-PKICertlist.ps1` | Énumérer les certificats et modèles du contexte AD CS / PKI. | n/d | Non spécifiée | &ndash; |
| `ActiveDirectory/Locate-46xx.ps1` | Localiser les événements de verrouillage AD (événements de sécurité 46xx). | 1.0 | Non spécifiée | &ndash; |
| `ActiveDirectory/Locate-ADLockout.ps1` | Identifier la source des verrouillages de comptes dans Active Directory. | 1.0 | Non spécifiée | &ndash; |
| `ActiveDirectory/Repair-DFSR.ps1` | Réparer la réplication DFS-R (y compris SYSVOL) sur les contrôleurs de domaine. | 0.1 | Non spécifiée | &ndash; |
| `ActiveDirectory/Reset-DSRM.ps1` | Réinitialiser le mot de passe DSRM sur un contrôleur de domaine. | 0.3 | GNU General Public License v3 (GPLv3) | &ndash; |
| `ActiveDirectory/execute-RemoteScriptWithLAPS.ps1` | Exécuter des scripts distants avec des comptes administrateur locaux gérés par Microsoft LAPS. | 1.1 | Non spécifiée | [DE](https://www.infrastrukturhelden.de/microsoft-infrastruktur/active-directory/powershell-skripte-mit-local-administrator-password-solution-laps-nutzen-und-auditieren/) |
| `ActiveDirectory/get-CVE20201472Events.ps1` | Vérifier sur les contrôleurs de domaine les événements Netlogon liés à CVE-2020-1472 (5827-5829). | 1.0 | Non spécifiée | [DE](https://www.infrastrukturhelden.de/?p=14850) |
| `ActiveDirectory/get-adinfo.ps1` | Collecter les informations principales de la forêt et du domaine AD et générer le rapport. | 0.7 | GNU General Public License v3 (GPLv3) | &ndash; |
| `ActiveDirectory/install-AD.ps1` | Installer et initialiser un nouveau domaine Active Directory. | 0.1 | Non spécifiée | &ndash; |
| `ActiveDirectory/install-DC.ps1` | Installer ou promouvoir un contrôleur de domaine supplémentaire. | 0.1 | Non spécifiée | &ndash; |
| `ActiveDirectory/move-FSMO.ps1` | Transférer les rôles FSMO vers un nouveau contrôleur de domaine. | 0.1 | Non spécifiée | &ndash; |
| `ActiveDirectory/set-BSI-TR-02102-2.ps1` | Configurer les paramètres cryptographiques de Windows selon BSI TR-02102-2 (durcissement TLS et suites de chiffrement). | 0.3 | GNU General Public License v3 (GPLv3) | &ndash; |

### Azure

| Fichier | Objet | Version | Licence | Article |
|---|---|---|---|---|
| `Azure/Install-AzCopy.ps1` | Télécharger et installer la dernière version d'AzCopy pour l'utilisateur courant. | 1.0 | Non spécifiée | &ndash; |
| `Azure/Install-AzModule.ps1` | Installer ou mettre à jour les modules Azure PowerShell (`Az`). | n/d | Non spécifiée | &ndash; |

### BitLocker

| Fichier | Objet | Version | Licence | Article |
|---|---|---|---|---|
| `BitLocker/List-BitLockerrecoveryKeys.ps1` | Lister les clés de récupération BitLocker stockées dans Active Directory. | n/d | Non spécifiée | &ndash; |
| `BitLocker/Start-Bitlocker.ps1` | Démarrer le chiffrement BitLocker avec des paramètres prédéfinis (y compris les scénarios avec PIN). | n/d | Non spécifiée | &ndash; |
| `BitLocker/Update-BitLockerRecovery.ps1` | Téléverser vers Active Directory les informations de récupération BitLocker manquantes. | 1.2 | Non spécifiée | [DE](https://www.infrastrukturhelden.de/microsoft-infrastruktur/active-directory/bitlocker-wiederherstellungs-keys-nachtraglich-im-ad-sichern/) |

### Exchange

| Fichier | Objet | Version | Licence | Article |
|---|---|---|---|---|
| `Exchange/Set-MaintananceMode.ps1` | Placer un nœud DAG Exchange 2013 en mode maintenance. | 0.2 | Non spécifiée | &ndash; |
| `Exchange/Set-Ex2013Vdir.ps1` | Configurer les répertoires virtuels et les URL d'Exchange 2013. | 0.1 | Non spécifiée | &ndash; |

### GPO

| Fichier | Objet | Version | Licence | Article |
|---|---|---|---|---|
| `GPO/Check-LocalGroupPolicy.ps1` | Détecter et corriger les problèmes de traitement des stratégies de groupe locales à partir des journaux d'événements. | 0.4 | Licence MIT (MIT) | &ndash; |
| `GPO/get-GPOBackup.ps1` | Créer des sauvegardes de GPO horodatées, avec rapports HTML. | 1.8 | Licence MIT (MIT) | [DE](https://www.infrastrukturhelden.de/microsoft-infrastruktur/active-directory/gruppenrichtlinien-richtig-sichern-und-dokumentieren.html) |
| `GPO/get-GPOreport.ps1` | Exporter et documenter les liaisons et métadonnées des GPO. | n/d | Non spécifiée | &ndash; |
| `GPO/invoke-GPupdateDomain.ps1` | Déclencher un GPUpdate distant pour les ordinateurs d'une OU (ou d'un périmètre plus large). | 1.1 | Licence MIT (MIT) | &ndash; |

### Intune

| Fichier | Objet | Version | Licence | Article |
|---|---|---|---|---|
| `Intune/create-package.ps1` | Générer des packages `.intunewin` à partir de dossiers sources. | 1.0 | Non spécifiée | &ndash; |
| `Intune/get-AutopilotLogs.ps1` | Collecter les journaux et diagnostics du pré-provisionnement Autopilot. | 1.0.2 | Licence MIT (MIT) | &ndash; |

### Linux-Files

| Fichier | Objet | Version | Licence | Article |
|---|---|---|---|---|
| `Linux-Files/allow_windowsupdate.squid` | Liste d'autorisation (ACL Squid) pour les points de terminaison Windows Update. | n/d | Non spécifiée | &ndash; |
| `Linux-Files/allow_psgallery.squid` | Liste d'autorisation (ACL Squid) pour les points de terminaison PowerShell Gallery / NuGet. | n/d | Non spécifiée | &ndash; |
| `Linux-Files/allow_github.squid` | Liste d'autorisation (ACL Squid) pour les points de terminaison GitHub. | n/d | Non spécifiée | &ndash; |
| `Linux-Files/allow_vscode.squid` | Liste d'autorisation (ACL Squid) pour les points de terminaison Visual Studio Code. | n/d | Non spécifiée | &ndash; |

### Network

| Fichier | Objet | Version | Licence | Article |
|---|---|---|---|---|
| `Network/Check-Network.ps1` | Valider la connectivité et la configuration réseau d'un client. | 0.6 | MIT (code de test LDAP : MIT &copy; Evotec) | &ndash; |
| `Network/disable-NetBios.ps1` | Désactiver NetBIOS sur TCP/IP sur les cartes réseau actives. | n/d | Non spécifiée | &ndash; |

### User

| Fichier | Objet | Version | Licence | Article |
|---|---|---|---|---|
| `User/create-user.ps1` | Créer des utilisateurs AD (y compris l'intégration Microsoft 365). | 0.3 | Licence MIT (MIT) | [DE](https://www.infrastrukturhelden.de/microsoft-infrastruktur/active-directory/benutzer-einfachen-anlegen-mit-powershell/) |
| `User/Get-LastLogonOU.ps1` | Rapporter la dernière ouverture de session des utilisateurs d'une OU (contexte AD et Exchange). | 0.2 | Licence MIT (MIT) | &ndash; |

### Windows

| Fichier | Objet | Version | Licence | Article |
|---|---|---|---|---|
| `Windows/set-cert4rdp.ps1` | Affecter le certificat RDP émis par une autorité de certification donnée. | 0.2 | Licence MIT (MIT) | &ndash; |
| `Windows/Remove-AzureArc.ps1` | Supprimer l'agent et les composants Azure Arc, avec redémarrage automatique si nécessaire. | 1.1 | Licence MIT (MIT) | &ndash; |

### WSUS

| Fichier | Objet | Version | Licence | Article |
|---|---|---|---|---|
| `WSUS/decline-WSUSUpdatesTypes.ps1` | Refuser des classifications ou produits de mise à jour sélectionnés dans WSUS. | 1.8 | Licence MIT (MIT) | [DE](https://www.infrastrukturhelden.de/microsoft-infrastruktur/wsus/windows-server-update-services-bereinigen.html) |
| `WSUS/Reset-WSUSClient.cmd` | Réinitialiser la configuration du client WSUS et son état de détection. | n/d | Non spécifiée | &ndash; |
| `WSUS/start-WsusServerSync.ps1` | Démarrer la synchronisation WSUS (prend en charge les serveurs amont/aval récursifs et la journalisation par e-mail). | n/d | Non spécifiée | &ndash; |
| `WSUS/Get-WsusHealth.ps1` | Exécuter des contrôles de santé WSUS complets et produire une sortie de diagnostic. | 1.3 | MIT (code de test LDAP : MIT &copy; Evotec) | [DE](https://www.infrastrukturhelden.de/microsoft-infrastruktur/wsus/wsus-fehleranalyse-und-health-checks-praxisleitfaden-mit-powershell/) |
<!-- END GENERATED: inventory -->

## Modèles de GPO

Objets de stratégie de groupe d'exemple publiés avec les articles. Chaque modèle comporte une description Markdown et une sauvegarde de GPO importable (ZIP). Détails et licence : [`GPO/Templates/readme.md`](./GPO/Templates/readme.md).

<!-- BEGIN GENERATED: gpo-templates -->
| Modèle | Objet | Sauvegarde GPO |
|---|---|---|
| [`GPO/Templates/Win11-24H2-IT-Grundschutz-Darksite.md`](./GPO/Templates/Win11-24H2-IT-Grundschutz-Darksite.md) | Windows 11 24H2 &ndash; protection de base informatique (darksite / communication cloud restreinte). | [ZIP](./GPO/Templates/Win11-24H2-IT-Grundschutz-Darksite.zip) |
| [`GPO/Templates/Win11-Disable-Copilot.md`](./GPO/Templates/Win11-Disable-Copilot.md) | Windows 11 &ndash; désactiver Microsoft Copilot et les fonctions d'IA. | [ZIP](./GPO/Templates/Win11-Disable-Copilot.zip) |
| [`GPO/Templates/MSOffice-Deactivate-Copilot.md`](./GPO/Templates/MSOffice-Deactivate-Copilot.md) | Microsoft Office &ndash; désactiver Copilot et les fonctions d'IA. | [ZIP](./GPO/Templates/MSOffice-Deactivate-Copilot.zip) |
| [`GPO/Templates/VisualStudio-Deactivate-Copilot.md`](./GPO/Templates/VisualStudio-Deactivate-Copilot.md) | Visual Studio &ndash; désactiver Copilot et les fonctions d'IA. | [ZIP](./GPO/Templates/VisualStudio-Deactivate-Copilot.zip) |
<!-- END GENERATED: gpo-templates -->

## Fichiers supplémentaires

- `Intune/Readme.md` – Notes spécifiques Intune (en allemand).
- `Dokumente/Zertifizierungsstellen mit Windows Server 2012R2.pdf` – documentation des autorités de certification (PKI/CA) au format PDF.
- `GPO/Templates/readme.md` – index et conditions de licence des modèles de GPO.

## Notes

- Certains scripts sont matures et versionnés.
- D'autres sont des aides opérationnelles rapides pour l'administration quotidienne.
- Validez toujours les scripts dans un environnement de test avant usage en production.
- Vous cherchez les [diagrammes de cycle de vie](https://github.com/FabianNiesen/InfrastrukturHelden-LifeCycle-diagrams) ? Ils se trouvent dans un dépôt séparé.

[![ko-fi](https://ko-fi.com/img/githubbutton_sm.svg)](https://ko-fi.com/Z8Z8FB6VH)
