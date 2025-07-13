#!/bin/bash

# Script d'environnement sécurisé - Projet Linux
# Auteur: Wh0amix
# Version: 1.0

set -euo pipefail

# Configuration par défaut
VAULT_SIZE="5G"
VAULT_NAME="secure_vault"
VAULT_FILE="$HOME/${VAULT_NAME}.img"
VAULT_MOUNT="/tmp/${VAULT_NAME}_mount"
VAULT_MAPPER="/dev/mapper/${VAULT_NAME}"
CONFIG_DIR="config"
GPG_DIR="gpg"
SSH_DIR="ssh"
ALIAS_FILE="aliases"

# Couleurs pour l'affichage
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Fonction pour trouver une commande dans les chemins système
find_command() {
    local cmd="$1"
    local search_paths=("/usr/bin" "/usr/sbin" "/sbin" "/bin")
    
    # Vérifier d'abord avec command -v
    if command -v "$cmd" &> /dev/null; then
        echo "$cmd"
        return 0
    fi
    
    # Chercher dans les chemins système
    for path in "${search_paths[@]}"; do
        if [ -x "$path/$cmd" ]; then
            echo "$path/$cmd"
            return 0
        fi
    done
    
    return 1
}

# Fonction d'affichage avec couleurs
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Fonction pour vérifier les dépendances
check_dependencies() {
    local deps=("cryptsetup" "gpg" "ssh-keygen" "dd" "mkfs.ext4")
    local missing=()
    
    # Chemins possibles pour les commandes système
    local search_paths=("/usr/bin" "/usr/sbin" "/sbin" "/bin")
    
    for dep in "${deps[@]}"; do
        local found=false
        
        # Vérifier d'abord avec command -v
        if command -v "$dep" &> /dev/null; then
            found=true
        else
            # Chercher dans les chemins système
            for path in "${search_paths[@]}"; do
                if [ -x "$path/$dep" ]; then
                    found=true
                    break
                fi
            done
        fi
        
        if [ "$found" = false ]; then
            missing+=("$dep")
        fi
    done
    
    if [ ${#missing[@]} -ne 0 ]; then
        log_error "Dépendances manquantes: ${missing[*]}"
        log_info "Installez avec: sudo apt-get install cryptsetup gnupg openssh-client"
        
        # Aide supplémentaire pour le diagnostic
        log_info "Diagnostic des chemins:"
        for dep in "${missing[@]}"; do
            local found_path=$(sudo find /usr /sbin -name "$dep" 2>/dev/null | head -1)
            if [ -n "$found_path" ]; then
                log_info "  $dep trouvé dans: $found_path"
                log_info "  Ajoutez $(dirname "$found_path") à votre PATH"
            fi
        done
        
        exit 1
    fi
}

# Fonction pour créer l'environnement sécurisé
create_vault() {
    log_info "Création de l'environnement sécurisé..."
    
    if [ -f "$VAULT_FILE" ]; then
        log_warning "Le fichier coffre existe déjà: $VAULT_FILE"
        read -p "Voulez-vous le recréer? (y/N): " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            return 0
        fi
        rm -f "$VAULT_FILE"
    fi
    
    # Création du fichier de 5G
    log_info "Création du fichier de $VAULT_SIZE..."
    dd if=/dev/urandom of="$VAULT_FILE" bs=1M count=5120 status=progress
    
    # Configuration LUKS
    log_info "Configuration du chiffrement LUKS..."
    echo "Entrez le mot de passe pour le coffre:"
    $(find_command "cryptsetup") luksFormat "$VAULT_FILE"
    
    # Ouverture et formatage
    echo "Confirmez le mot de passe pour ouvrir le coffre:"
    sudo $(find_command "cryptsetup") luksOpen "$VAULT_FILE" "$VAULT_NAME"
    
    # Formatage en ext4
    log_info "Formatage en ext4..."
    sudo $(find_command "mkfs.ext4") "$VAULT_MAPPER"
    
    # Montage et création de la structure
    mkdir -p "$VAULT_MOUNT"
    sudo mount "$VAULT_MAPPER" "$VAULT_MOUNT"
    
    # Création de la structure des répertoires
    sudo mkdir -p "$VAULT_MOUNT/$CONFIG_DIR"
    sudo mkdir -p "$VAULT_MOUNT/$GPG_DIR"
    sudo mkdir -p "$VAULT_MOUNT/$SSH_DIR"
    
    # Permissions correctes
    sudo chown -R "$USER:$USER" "$VAULT_MOUNT"
    chmod 700 "$VAULT_MOUNT"
    chmod 700 "$VAULT_MOUNT/$GPG_DIR"
    chmod 700 "$VAULT_MOUNT/$SSH_DIR"
    
    # Création du fichier d'alias
    create_alias_file
    
    # Configuration SSH template
    create_ssh_config_template
    
    log_success "Environnement sécurisé créé avec succès!"
    
    # Fermeture
    close_vault
}

# Fonction pour ouvrir l'environnement
open_vault() {
    log_info "Ouverture de l'environnement sécurisé..."
    
    if [ ! -f "$VAULT_FILE" ]; then
        log_error "Fichier coffre non trouvé: $VAULT_FILE"
        exit 1
    fi
    
    if mountpoint -q "$VAULT_MOUNT"; then
        log_warning "L'environnement est déjà ouvert"
        return 0
    fi
    
    # Ouverture LUKS
    echo "Entrez le mot de passe du coffre:"
    sudo $(find_command "cryptsetup") luksOpen "$VAULT_FILE" "$VAULT_NAME"
    
    # Montage
    mkdir -p "$VAULT_MOUNT"
    sudo mount "$VAULT_MAPPER" "$VAULT_MOUNT"
    
    # Permissions
    sudo chown -R "$USER:$USER" "$VAULT_MOUNT"
    
    log_success "Environnement ouvert: $VAULT_MOUNT"
    
    # Création du lien symbolique pour les alias
    if [ -f "$VAULT_MOUNT/$ALIAS_FILE" ]; then
        ln -sf "$VAULT_MOUNT/$ALIAS_FILE" "$HOME/.secure_aliases"
        log_info "Lien symbolique créé: ~/.secure_aliases"
        log_info "Ajoutez 'source ~/.secure_aliases' dans votre ~/.bashrc"
    fi
}

# Fonction pour fermer l'environnement
close_vault() {
    log_info "Fermeture de l'environnement sécurisé..."
    
    if ! mountpoint -q "$VAULT_MOUNT"; then
        log_warning "L'environnement n'est pas ouvert"
        return 0
    fi
    
    # Démontage
    sudo umount "$VAULT_MOUNT"
    
    # Fermeture LUKS
    sudo $(find_command "cryptsetup") luksClose "$VAULT_NAME"
    
    # Suppression du lien symbolique
    rm -f "$HOME/.secure_aliases"
    
    log_success "Environnement fermé avec succès"
}

# Fonction pour créer une paire de clés GPG
create_gpg_key() {
    if ! mountpoint -q "$VAULT_MOUNT"; then
        log_error "L'environnement doit être ouvert"
        exit 1
    fi
    
    log_info "Création d'une paire de clés GPG..."
    
    read -p "Nom complet: " name
    read -p "Adresse email: " email
    read -p "Commentaire (optionnel): " comment
    
    # Génération automatique de la clé
    cat > "$VAULT_MOUNT/$GPG_DIR/gpg_batch" << EOF
%echo Génération de la clé GPG
Key-Type: RSA
Key-Length: 4096
Subkey-Type: RSA
Subkey-Length: 4096
Name-Real: $name
Name-Comment: $comment
Name-Email: $email
Expire-Date: 2y
%no-protection
%commit
%echo Clé GPG générée
EOF
    
    # Création du répertoire GPG temporaire
    export GNUPGHOME="$VAULT_MOUNT/$GPG_DIR"
    chmod 700 "$GNUPGHOME"
    
    # Génération de la clé
    gpg --batch --generate-key "$VAULT_MOUNT/$GPG_DIR/gpg_batch"
    
    # Export des clés
    KEY_ID=$(gpg --list-secret-keys --with-colons | grep "^sec" | head -1 | cut -d: -f5)
    gpg --export --armor "$KEY_ID" > "$VAULT_MOUNT/$GPG_DIR/public_key.asc"
    gpg --export-secret-keys --armor "$KEY_ID" > "$VAULT_MOUNT/$GPG_DIR/private_key.asc"
    
    # Permissions restrictives pour la clé privée
    chmod 600 "$VAULT_MOUNT/$GPG_DIR/private_key.asc"
    
    # Nettoyage
    rm "$VAULT_MOUNT/$GPG_DIR/gpg_batch"
    
    log_success "Paire de clés GPG créée (ID: $KEY_ID)"
    log_info "Clé publique: $VAULT_MOUNT/$GPG_DIR/public_key.asc"
    log_warning "Clé privée: $VAULT_MOUNT/$GPG_DIR/private_key.asc (GARDEZ-LA SECRÈTE!)"
}

# Fonction pour importer les clés GPG depuis le coffre
import_gpg_from_vault() {
    if ! mountpoint -q "$VAULT_MOUNT"; then
        log_error "L'environnement doit être ouvert"
        exit 1
    fi
    
    log_info "Import des clés GPG depuis le coffre..."
    
    if [ ! -f "$VAULT_MOUNT/$GPG_DIR/private_key.asc" ]; then
        log_error "Aucune clé privée trouvée dans le coffre"
        exit 1
    fi
    
    # Import des clés
    gpg --import "$VAULT_MOUNT/$GPG_DIR/public_key.asc"
    gpg --import "$VAULT_MOUNT/$GPG_DIR/private_key.asc"
    
    log_success "Clés GPG importées dans le trousseau système"
}

# Fonction pour exporter les clés GPG vers le coffre
export_gpg_to_vault() {
    if ! mountpoint -q "$VAULT_MOUNT"; then
        log_error "L'environnement doit être ouvert"
        exit 1
    fi
    
    log_info "Export des clés GPG vers le coffre..."
    
    # Liste des clés disponibles
    echo "Clés GPG disponibles:"
    gpg --list-secret-keys --keyid-format LONG
    
    read -p "Entrez l'ID de la clé à exporter: " key_id
    
    if [ -z "$key_id" ]; then
        log_error "ID de clé requis"
        exit 1
    fi
    
    # Export des clés
    gpg --export --armor "$key_id" > "$VAULT_MOUNT/$GPG_DIR/public_key_$key_id.asc"
    gpg --export-secret-keys --armor "$key_id" > "$VAULT_MOUNT/$GPG_DIR/private_key_$key_id.asc"
    
    # Permissions restrictives
    chmod 600 "$VAULT_MOUNT/$GPG_DIR/private_key_$key_id.asc"
    
    log_success "Clés GPG exportées vers le coffre"
}

# Fonction pour créer le fichier de configuration SSH template
create_ssh_config_template() {
    cat > "$VAULT_MOUNT/$CONFIG_DIR/ssh_config_template" << 'EOF'
# Configuration SSH Template - Environnement Sécurisé
# Utilisez avec: ssh -F chemin_vers_ce_fichier

# Configuration globale
Host *
    # Sécurité renforcée
    Protocol 2
    Ciphers aes256-gcm@openssh.com,chacha20-poly1305@openssh.com,aes256-ctr
    MACs hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com
    KexAlgorithms curve25519-sha256@libssh.org,diffie-hellman-group16-sha512
    HostKeyAlgorithms ssh-ed25519,ssh-rsa
    
    # Authentification
    PubkeyAuthentication yes
    PasswordAuthentication no
    ChallengeResponseAuthentication no
    
    # Paramètres de connexion
    ServerAliveInterval 60
    ServerAliveCountMax 3
    TCPKeepAlive yes
    
    # Vérification des hôtes
    StrictHostKeyChecking ask
    HashKnownHosts yes

# Exemple de configuration d'hôte
# Host exemple
#     HostName exemple.com
#     User utilisateur
#     Port 22
#     IdentityFile VAULT_PATH/ssh/exemple_key
#     LocalForward 8080 localhost:8080
EOF
    
    log_success "Template de configuration SSH créé"
}

# Fonction pour créer le fichier d'alias
create_alias_file() {
    cat > "$VAULT_MOUNT/$ALIAS_FILE" << EOF
#!/bin/bash
# Alias pour l'environnement sécurisé

# SSH avec configuration du coffre
alias evsh="ssh -F $VAULT_MOUNT/$CONFIG_DIR/ssh_config_template"

# GPG avec répertoire du coffre
alias evgpg="GNUPGHOME=$VAULT_MOUNT/$GPG_DIR gpg"

# Raccourcis pour le coffre
alias vault-open="$0 open"
alias vault-close="$0 close"
alias vault-status="mountpoint -q $VAULT_MOUNT && echo 'Coffre ouvert' || echo 'Coffre fermé'"

# Navigation rapide
alias cdvault="cd $VAULT_MOUNT"
alias lsvault="ls -la $VAULT_MOUNT"
EOF
    
    chmod +x "$VAULT_MOUNT/$ALIAS_FILE"
    log_success "Fichier d'alias créé"
}

# Fonction pour importer les configurations SSH existantes
import_ssh_config() {
    if ! mountpoint -q "$VAULT_MOUNT"; then
        log_error "L'environnement doit être ouvert"
        exit 1
    fi
    
    local ssh_config="$HOME/.ssh/config"
    
    if [ ! -f "$ssh_config" ]; then
        log_warning "Aucun fichier de configuration SSH trouvé"
        return 0
    fi
    
    log_info "Parsing du fichier SSH existant..."
    
    # Extraction des hosts
    local hosts=($(grep "^Host " "$ssh_config" | awk '{print $2}' | grep -v "\*"))
    
    if [ ${#hosts[@]} -eq 0 ]; then
        log_warning "Aucun host trouvé dans la configuration SSH"
        return 0
    fi
    
    echo "Hosts trouvés:"
    for i in "${!hosts[@]}"; do
        echo "$((i+1)). ${hosts[$i]}"
    done
    
    read -p "Choisissez un host à importer (numéro): " choice
    
    if ! [[ "$choice" =~ ^[0-9]+$ ]] || [ "$choice" -lt 1 ] || [ "$choice" -gt ${#hosts[@]} ]; then
        log_error "Choix invalide"
        exit 1
    fi
    
    local selected_host="${hosts[$((choice-1))]}"
    log_info "Import de la configuration pour: $selected_host"
    
    # Extraction de la configuration pour cet host
    awk "/^Host $selected_host$/,/^Host / { if (/^Host / && \$2 != \"$selected_host\") exit; print }" "$ssh_config" > "$VAULT_MOUNT/$CONFIG_DIR/imported_${selected_host}.conf"
    
    # Recherche et copie de la clé privée
    local identity_file=$(grep "IdentityFile" "$VAULT_MOUNT/$CONFIG_DIR/imported_${selected_host}.conf" | awk '{print $2}' | head -1)
    
    if [ -n "$identity_file" ]; then
        # Expansion du chemin
        identity_file="${identity_file/#\~/$HOME}"
        
        if [ -f "$identity_file" ]; then
            local key_name=$(basename "$identity_file")
            cp "$identity_file" "$VAULT_MOUNT/$SSH_DIR/"
            
            # Copie de la clé publique si elle existe
            if [ -f "${identity_file}.pub" ]; then
                cp "${identity_file}.pub" "$VAULT_MOUNT/$SSH_DIR/"
            fi
            
            # Mise à jour du chemin dans la configuration
            sed -i "s|IdentityFile.*|IdentityFile $VAULT_MOUNT/$SSH_DIR/$key_name|" "$VAULT_MOUNT/$CONFIG_DIR/imported_${selected_host}.conf"
            
            log_success "Clé SSH importée: $key_name"
        fi
    fi
    
    log_success "Configuration SSH importée: $selected_host"
}

# Fonction pour définir les permissions appropriées
set_permissions() {
    if ! mountpoint -q "$VAULT_MOUNT"; then
        log_error "L'environnement doit être ouvert"
        exit 1
    fi
    
    log_info "Configuration des permissions..."
    
    # Permissions pour le fichier coffre
    chmod 600 "$VAULT_FILE"
    
    # Permissions pour les répertoires
    chmod 700 "$VAULT_MOUNT"
    chmod 700 "$VAULT_MOUNT/$GPG_DIR"
    chmod 700 "$VAULT_MOUNT/$SSH_DIR"
    chmod 755 "$VAULT_MOUNT/$CONFIG_DIR"
    
    # Permissions pour les clés SSH
    find "$VAULT_MOUNT/$SSH_DIR" -type f -name "*" ! -name "*.pub" -exec chmod 600 {} \;
    find "$VAULT_MOUNT/$SSH_DIR" -type f -name "*.pub" -exec chmod 644 {} \;
    
    # Permissions pour les clés GPG
    find "$VAULT_MOUNT/$GPG_DIR" -type f -name "*private*" -exec chmod 600 {} \;
    find "$VAULT_MOUNT/$GPG_DIR" -type f -name "*public*" -exec chmod 644 {} \;
    
    # Attributs immutables pour les fichiers critiques
    if command -v chattr &> /dev/null; then
        sudo chattr +i "$VAULT_FILE" 2>/dev/null || true
    fi
    
    log_success "Permissions configurées"
}

# Fonction d'aide
show_help() {
    cat << EOF
Script d'Environnement Sécurisé - Aide

USAGE:
    $0 [COMMANDE] [OPTIONS]

COMMANDES:
    install     Installe l'environnement sécurisé
    open        Ouvre l'environnement sécurisé
    close       Ferme l'environnement sécurisé
    status      Affiche le statut de l'environnement
    
    create-gpg  Crée une paire de clés GPG
    import-gpg  Importe les clés GPG depuis le coffre
    export-gpg  Exporte les clés GPG vers le coffre
    
    import-ssh  Importe les configurations SSH existantes
    permissions Configure les permissions
    
    help        Affiche cette aide

EXEMPLES:
    $0 install                 # Installation complète
    $0 open                    # Ouverture du coffre
    $0 create-gpg              # Création de clés GPG
    $0 import-ssh              # Import des configs SSH
    $0 close                   # Fermeture du coffre

FICHIERS:
    Coffre: $VAULT_FILE
    Point de montage: $VAULT_MOUNT
    Alias: ~/.secure_aliases

SÉCURITÉ:
    - Coffre chiffré LUKS avec mot de passe
    - Clés privées avec permissions restrictives
    - Répertoire GPG isolé
    - Configuration SSH sécurisée

EOF
}

# Fonction principale
main() {
    # Vérification des dépendances
    check_dependencies
    
    case "${1:-help}" in
        "install")
            create_vault
            ;;
        "open")
            open_vault
            ;;
        "close")
            close_vault
            ;;
        "status")
            if mountpoint -q "$VAULT_MOUNT"; then
                log_success "Environnement ouvert: $VAULT_MOUNT"
            else
                log_info "Environnement fermé"
            fi
            ;;
        "create-gpg")
            create_gpg_key
            ;;
        "import-gpg")
            import_gpg_from_vault
            ;;
        "export-gpg")
            export_gpg_to_vault
            ;;
        "import-ssh")
            import_ssh_config
            ;;
        "permissions")
            set_permissions
            ;;
        "help"|"--help"|"-h")
            show_help
            ;;
        *)
            log_error "Commande inconnue: $1"
            show_help
            exit 1
            ;;
    esac
}

# Gestion des signaux pour fermeture propre
trap 'log_warning "Interruption détectée, fermeture en cours..."; close_vault 2>/dev/null || true; exit 1' INT TERM

# Exécution du script
main "$@"