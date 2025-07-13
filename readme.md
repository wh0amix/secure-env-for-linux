# 🔐 Environnement Sécurisé Linux

## 📋 Description du Projet

Ce projet implémente un **environnement sécurisé chiffré** pour la gestion centralisée et sécurisée des clés SSH, GPG et configurations système. Il répond aux exigences de sécurité en entreprise en offrant un coffre-fort numérique portable et chiffré.

## 🎯 Objectifs

- **Sécurité** : Chiffrement LUKS de niveau militaire
- **Portabilité** : Migration facile entre postes de travail
- **Centralisation** : Gestion unifiée des credentials
- **Automatisation** : Scripts pour toutes les opérations courantes

## 🏗️ Architecture

```
Environnement Sécurisé
├── 📁 Fichier LUKS (5GB)
│   ├── 🔐 Chiffrement AES-256
│   └── 🗂️ Système de fichiers ext4
├── 🔑 Gestion GPG
│   ├── Génération automatique
│   ├── Import/Export trousseau
│   └── Stockage sécurisé
├── 🌐 Configuration SSH
│   ├── Template sécurisé
│   ├── Import configurations existantes
│   └── Gestion des clés
└── ⚙️ Système d'alias
    ├── Lien symbolique
    └── Commandes simplifiées
```

## 🚀 Installation

### Prérequis

```bash
# Debian/Ubuntu/Parrot OS
sudo apt-get update
sudo apt-get install cryptsetup-bin e2fsprogs gnupg2 openssh-client util-linux
```

### Déploiement

```bash
# 1. Télécharger le script
git clone https://github.com/wh0amix/secure-env-for-linux
cd secure-env-for-linux

# 2. Rendre exécutable
chmod +x secure_env.sh

# 3. Installation complète
./secure_env.sh install
```

## 📖 Guide d'Utilisation

### Commandes Principales

| Commande | Description | Exemple |
|----------|-------------|---------|
| `install` | Installation de l'environnement | `./secure_env.sh install` |
| `open` | Ouverture du coffre | `./secure_env.sh open` |
| `close` | Fermeture du coffre | `./secure_env.sh close` |
| `status` | Statut de l'environnement | `./secure_env.sh status` |
| `help` | Aide complète | `./secure_env.sh help` |

### Gestion GPG

| Commande | Description |
|----------|-------------|
| `create-gpg` | Création automatisée de clés GPG |
| `import-gpg` | Import des clés depuis le coffre |
| `export-gpg` | Export des clés vers le coffre |

### Configuration SSH

| Commande | Description |
|----------|-------------|
| `import-ssh` | Import des configurations SSH existantes |
| `permissions` | Configuration des permissions sécurisées |

## 🔧 Workflow Typique

### 1. Premier Déploiement

```bash
# Installation
./secure_env.sh install
# → Création du coffre 5GB chiffré LUKS
# → Configuration de la structure sécurisée

# Ouverture
./secure_env.sh open
# → Montage du coffre chiffré

# Génération des clés
./secure_env.sh create-gpg
# → Création automatique paire GPG 4096-bit

# Import des configurations existantes
./secure_env.sh import-ssh
# → Parse ~/.ssh/config et import sélectif

# Fermeture sécurisée
./secure_env.sh close
```

### 2. Utilisation Quotidienne

```bash
# Ouverture de session
./secure_env.sh open
source ~/.secure_aliases

# Utilisation des alias sécurisés
evsh production-server    # SSH avec config sécurisée
evgpg --list-keys        # GPG avec trousseau isolé

# Fermeture de session
./secure_env.sh close
```


## 🔒 Fonctionnalités de Sécurité

### Chiffrement

- **LUKS** : Chiffrement de volume Linux standard
- **AES-256** : Algorithme de chiffrement
- **PBKDF2** : Dérivation de clé renforcée
- **Entropie** : Génération `/dev/urandom`

### Permissions

```bash
Fichier coffre     : 600 (rw-------)
Répertoire GPG     : 700 (rwx------)
Clés privées       : 600 (rw-------)
Clés publiques     : 644 (rw-r--r--)
Configurations SSH : 600 (rw-------)
```

### SSH Durci

```bash
# Algorithmes sécurisés uniquement
Ciphers: aes256-gcm@openssh.com, chacha20-poly1305@openssh.com
MACs: hmac-sha2-256-etm@openssh.com, hmac-sha2-512-etm@openssh.com
KexAlgorithms: curve25519-sha256@libssh.org, diffie-hellman-group16-sha512

# Sécurité renforcée
PubkeyAuthentication: yes
PasswordAuthentication: no
StrictHostKeyChecking: ask
```

## 📁 Structure des Données

```
~/secure_vault.img (Fichier LUKS 5GB)
│
└── /tmp/secure_vault_mount/ (Point de montage)
    ├── config/
    │   ├── ssh_config_template      # Template SSH sécurisé
    │   └── imported_*.conf          # Configurations importées
    ├── gpg/
    │   ├── pubring.kbx             # Trousseau public GPG
    │   ├── secring.gpg             # Trousseau privé GPG
    │   ├── public_key.asc          # Export clé publique
    │   └── private_key.asc         # Export clé privée
    ├── ssh/
    │   ├── imported_keys           # Clés SSH importées
    │   └── *.pub                   # Clés publiques SSH
    └── aliases                     # Fichier d'alias système
```

## ⚡ Alias Prédéfinis

```bash
# SSH sécurisé
alias evsh="ssh -F /tmp/secure_vault_mount/config/ssh_config_template"

# GPG isolé
alias evgpg="GNUPGHOME=/tmp/secure_vault_mount/gpg gpg"

# Gestion du coffre
alias vault-open="./secure_env.sh open"
alias vault-close="./secure_env.sh close"
alias vault-status="mountpoint -q /tmp/secure_vault_mount && echo 'Ouvert' || echo 'Fermé'"

# Navigation
alias cdvault="cd /tmp/secure_vault_mount"
alias lsvault="ls -la /tmp/secure_vault_mount"
```

## 🛠️ Dépannage

### Problèmes Courants

#### Coffre non monté
```bash
# Diagnostic
./secure_env.sh status

# Forcer la fermeture
sudo umount /tmp/secure_vault_mount 2>/dev/null || true
sudo cryptsetup luksClose secure_vault 2>/dev/null || true

# Réouverture
./secure_env.sh open
```

#### Permissions incorrectes
```bash
# Reconfiguration automatique
./secure_env.sh permissions
```

#### Dépendances manquantes
```bash
# Vérification
./secure_env.sh help

# Installation manuelle
sudo apt-get install cryptsetup-bin e2fsprogs gnupg2
```

### Récupération d'Urgence

```bash
# Accès manuel au coffre
sudo cryptsetup luksOpen ~/secure_vault.img secure_vault_recovery
sudo mkdir -p /mnt/recovery
sudo mount /dev/mapper/secure_vault_recovery /mnt/recovery

# Extraction des données
cp -r /mnt/recovery/* /tmp/backup/

# Nettoyage
sudo umount /mnt/recovery
sudo cryptsetup luksClose secure_vault_recovery
```

## 📊 Spécifications Techniques

### Performances

| Métrique | Valeur |
|----------|---------|
| **Taille du coffre** | 5 GB |
| **Temps de création** | ~2-5 minutes |
| **Temps d'ouverture** | ~5-10 secondes |
| **Algorithme de chiffrement** | AES-256-XTS |
| **Taille des clés GPG** | 4096 bits RSA |

### Compatibilité

| Système | Support |
|---------|---------|
| **Ubuntu 20.04+** | ✅ Testé |
| **Debian 11+** | ✅ Testé |
| **Parrot OS** | ✅ Testé |
| **Kali Linux** | ✅ Compatible |
| **CentOS/RHEL** | ⚠️ Adaptation requise |


## 🔐 Sécurité et Conformité

### Standards Respectés

- **NIST SP 800-111** : Guide de stockage des clés cryptographiques
- **RFC 4880** : Standard OpenPGP
- **FIPS 140-2** : Niveau de sécurité cryptographique
- **Common Criteria** : Évaluation de sécurité

### Recommandations

1. **Mot de passe LUKS** : Minimum 20 caractères, complexe
2. **Sauvegarde** : Duplication régulière du fichier `.img`
3. **Audit** : Vérification périodique des permissions
4. **Rotation** : Renouvellement des clés selon la politique
5. **Logs** : Surveillance des accès système

## 📚 Documentation Avancée

### Configuration SSH Personnalisée

```bash
# Édition du template
nano /tmp/secure_vault_mount/config/ssh_config_template

# Ajout d'un nouvel hôte
echo "Host monserveur
    HostName 192.168.1.100
    User admin
    Port 2222
    IdentityFile /tmp/secure_vault_mount/ssh/monserveur_key" >> ssh_config_template
```

### Automatisation avec Cron

```bash
# Sauvegarde automatique (coffre fermé)
0 2 * * * [ ! -d "/tmp/secure_vault_mount" ] && cp ~/secure_vault.img ~/backup/secure_vault_$(date +\%Y\%m\%d).img
```

### Intégration CI/CD

```bash
# Variables d'environnement
export VAULT_PASSWORD_FILE="/secure/vault_password"
export VAULT_MOUNT_POINT="/tmp/secure_vault_mount"

# Script de déploiement
if ./secure_env.sh status | grep -q "fermé"; then
    echo "$VAULT_PASSWORD" | ./secure_env.sh open
fi
```

## 🤝 Contribution

### Structure du Code

```bash
secure_env.sh
├── Configuration (lignes 1-50)
├── Fonctions utilitaires (51-150)
├── Gestion LUKS (151-300)
├── Gestion GPG (301-450)
├── Gestion SSH (451-600)
├── Interface utilisateur (601-700)
└── Main et gestion d'erreurs (701-fin)
```

### Tests

```bash
# Test d'installation
./tests/test_install.sh

# Test de fonctionnalités
./tests/test_features.sh

# Test de sécurité
./tests/test_security.sh
```


## 📄 Licence

Ce projet est distribué sous licence [MIT](LICENSE). Utilisation libre pour projets académiques et professionnels.



*Développé dans le cadre du projet Linux - Environnement Sécurisé*  
*Version 1.0 - 2025*