#!/usr/bin/env bash
# Gestor de firewall para Linux basado en ufw
# Requiere: bash, ufw, systemd o service, tar
# Ejecutar como root: sudo ./gestor_firewall.sh
#
# Uso rápido:
#   Interactivo:
#       sudo ./gestor_firewall.sh
#
#   No interactivo:
#       sudo ./gestor_firewall.sh --init           # Inicializar firewall con política segura
#       sudo ./gestor_firewall.sh --status         # Ver estado actual de ufw
#       sudo ./gestor_firewall.sh --backup         # Backup automático
#       sudo ./gestor_firewall.sh --restore        # Restaurar backup (asistido)
#       sudo ./gestor_firewall.sh --dry-run --init # Simular inicialización (sin cambios)
#       sudo ./gestor_firewall.sh --help           # Mostrar ayuda

set -Euo pipefail
IFS=$'\n\t'
umask 077
shopt -s nullglob

# -------------------- Constantes globales --------------------

readonly CONFIG_FILE="/etc/firewall-manager.conf"
readonly BACKUP_DIR="/var/backups/firewall-manager"
readonly VERSION="1.0"

PM=""
DRY_RUN=0   # 0 = normal, 1 = no aplica cambios (simulación)

# -------------------- Colores / formato ----------------------

if [[ -t 1 ]]; then
    readonly C_RED="\e[31m"
    readonly C_GREEN="\e[32m"
    readonly C_YELLOW="\e[33m"
    readonly C_BLUE="\e[34m"
    readonly C_BOLD="\e[1m"
    readonly C_RESET="\e[0m"
else
    readonly C_RED=""
    readonly C_GREEN=""
    readonly C_YELLOW=""
    readonly C_BLUE=""
    readonly C_BOLD=""
    readonly C_RESET=""
fi

log_info()   { printf "%b[INFO]%b %s\n"  "$C_BLUE"  "$C_RESET" "$*"; }
log_ok()     { printf "%b[OK]%b   %s\n"  "$C_GREEN" "$C_RESET" "$*"; }
log_warn()   { printf "%b[WARN]%b %s\n"  "$C_YELLOW" "$C_RESET" "$*"; }
log_error()  { printf "%b[ERROR]%b %s\n" "$C_RED"  "$C_RESET" "$*" >&2; }
log_header() {
    printf "\n%b==============================%b\n" "$C_BOLD" "$C_RESET"
    printf "%b  %s%b\n" "$C_BOLD" "$*" "$C_RESET"
    printf "%b==============================%b\n\n" "$C_BOLD" "$C_RESET"
}
dry_log() {
    printf "%b[DRY-RUN]%b %s\n" "$C_YELLOW" "$C_RESET" "$*"
}

pause() {
    echo
    read -rp "Pulsa ENTER para continuar..." _
}

# Ctrl+C limpio
trap 'echo; log_warn "Ejecución interrumpida por el usuario."; exit 130' INT

ask_yes_no() {
    # Uso: ask_yes_no "Pregunta (si/no) [no]:" "no"
    local prompt="$1"
    local default="${2:-no}"
    local answer

    read -rp "$prompt " answer
    answer=${answer:-$default}

    case "$answer" in
        si|SI|Si|s|S) return 0 ;;
        no|NO|No|n|N) return 1 ;;
        *)
            log_warn "Respuesta no reconocida, usando valor por defecto: $default"
            [[ "$default" == "si" ]]
            ;;
    esac
}

# -------------------- Utilidades básicas --------------------

check_root() {
    if [[ "$(id -u)" -ne 0 ]]; then
        log_error "Este script debe ejecutarse como root (sudo)."
        exit 1
    fi
}

print_help() {
    cat <<EOF
Firewall_Kit v${VERSION}

Uso:
  $(basename "$0")                        -> Modo interactivo (menú)
  $(basename "$0") --init                 -> Inicializar firewall con política segura
  $(basename "$0") --status               -> Mostrar estado / reglas ufw
  $(basename "$0") --backup               -> Crear backup automático
  $(basename "$0") --restore              -> Restaurar configuración desde backup
  $(basename "$0") --dry-run --init       -> Simular inicialización (sin cambios)
  $(basename "$0") --help                 -> Mostrar esta ayuda

Opciones globales:
  --dry-run   Activa modo simulación (no se aplica ningún cambio real).

Archivos usados:
  Configuración interna:  ${CONFIG_FILE}
  Directorio de backups:  ${BACKUP_DIR}

EOF
}

load_config() {
    # Valores por defecto
    SSH_PORT=22
    LAN_NET="0.0.0.0/0"

    if [[ -f "$CONFIG_FILE" ]]; then
        # shellcheck disable=SC1090
        . "$CONFIG_FILE"
    else
        # Intentar detectar puerto SSH real de sshd_config
        if [[ -f /etc/ssh/sshd_config ]]; then
            local detected
            detected=$(grep -E '^[[:space:]]*Port[[:space:]]+[0-9]+' /etc/ssh/sshd_config 2>/dev/null || true)
            detected=$(echo "$detected" | head -n1 | awk '{print $2}')
            if [[ -n "${detected:-}" ]]; then
                SSH_PORT="$detected"
            fi
        fi
        save_config
    fi
}

save_config() {
    mkdir -p "$(dirname "$CONFIG_FILE")"
    cat > "$CONFIG_FILE" <<EOF
# Configuración del gestor de firewall
SSH_PORT=${SSH_PORT}
LAN_NET="${LAN_NET}"
EOF
}

detect_package_manager() {
    if command -v apt >/dev/null 2>&1; then
        PM="apt"
    elif command -v dnf >/dev/null 2>&1; then
        PM="dnf"
    elif command -v yum >/dev/null 2>&1; then
        PM="yum"
    elif command -v zypper >/dev/null 2>&1; then
        PM="zypper"
    else
        PM=""
    fi
}

install_ufw_if_needed() {
    if command -v ufw >/dev/null 2>&1; then
        return 0
    fi

    log_warn "ufw no está instalado. Intentando instalar..."
    detect_package_manager
    if [[ -z "$PM" ]]; then
        log_error "No se detectó un gestor de paquetes compatible. Instala ufw manualmente."
        exit 1
    fi

    case "$PM" in
        apt)
            apt update -y && apt install -y ufw
            ;;
        dnf|yum)
            "$PM" install -y ufw
            ;;
        zypper)
            zypper install -y ufw
            ;;
        *)
            log_error "Gestor de paquetes no soportado: $PM"
            exit 1
            ;;
    esac
    log_ok "ufw instalado correctamente."
}

backup_file_if_exists() {
    local file="$1"
    if [[ -f "$file" ]]; then
        mkdir -p "$BACKUP_DIR/individual"
        local ts
        ts=$(date +%F_%H-%M-%S)
        if (( DRY_RUN )); then
            dry_log "Se copiaría $file a $BACKUP_DIR/individual/$(basename "$file").bak.$ts"
        else
            cp "$file" "$BACKUP_DIR/individual/$(basename "$file").bak.$ts"
            log_ok "Backup de $file en $BACKUP_DIR/individual"
        fi
    fi
}

restart_ssh_service() {
    if (( DRY_RUN )); then
        dry_log "Se reiniciaría el servicio SSH (ssh/sshd, systemctl/service)."
        return 0
    fi

    log_info "Reiniciando servicio SSH..."

    if command -v systemctl >/dev/null 2>&1; then
        if systemctl restart ssh 2>/dev/null; then
            return 0
        fi
        if systemctl restart sshd 2>/dev/null; then
            return 0
        fi
    fi

    if command -v service >/dev/null 2>&1; then
        if service ssh restart 2>/dev/null; then
            return 0
        fi
        if service sshd restart 2>/dev/null; then
            return 0
        fi
    fi

    log_error "No se pudo reiniciar el servicio SSH automáticamente. Revísalo manualmente."
    return 1
}

# Wrapper para comandos ufw que modifican el estado
ufw_apply() {
    if (( DRY_RUN )); then
        dry_log "ufw $*"
        return 0
    fi
    ufw "$@"
}

# Validación simple de CIDR (IPv4)
validate_cidr() {
    local input="$1"
    local ip mask o1 o2 o3 o4

    # Permitir "0.0.0.0/0" explícitamente
    if [[ "$input" == "0.0.0.0/0" ]]; then
        return 0
    fi

    ip=${input%/*}
    mask=${input#*/}
    if [[ "$mask" == "$input" ]]; then
        mask=""   # sin /, solo IP
    fi

    IFS=. read -r o1 o2 o3 o4 <<< "$ip" || return 1
    for o in "$o1" "$o2" "$o3" "$o4"; do
        [[ "$o" =~ ^[0-9]+$ ]] || return 1
        (( o >= 0 && o <= 255 )) || return 1
    done

    if [[ -n "$mask" ]]; then
        [[ "$mask" =~ ^[0-9]+$ ]] || return 1
        (( mask >= 0 && mask <= 32 )) || return 1
    fi

    return 0
}

# -------------------- Funciones de firewall --------------------

warn_if_ssh_session() {
    if [[ -n "${SSH_CONNECTION:-}" ]]; then
        local remote_ip
        remote_ip=${SSH_CONNECTION%% *}
        log_warn "Estás ejecutando esto desde una sesión SSH remota (origen: ${remote_ip})."
        log_warn "Ten MUCHO cuidado al cambiar reglas o puertos SSH."
    fi
}

init_firewall() {
    load_config
    install_ufw_if_needed

    log_header "Inicialización del firewall"
    warn_if_ssh_session

    if (( DRY_RUN )); then
        dry_log "Modo simulación: no se crearán backups automáticos ni se modificará ufw."
    else
        if ask_yes_no "¿Quieres crear un backup automático antes de reinicializar ufw? (si/no) [si]:" "si"; then
            backup_auto_internal "pre_init"
        fi
    fi

    log_warn "Esto reiniciará la configuración de ufw (reset)."
    if ! ask_yes_no "¿Seguro que quieres continuar? (si/no) [no]:" "no"; then
        log_info "Operación cancelada."
        pause
        return
    fi

    # Simulación o ejecución real
    ufw_apply --force reset
    ufw_apply default deny incoming
    ufw_apply default allow outgoing

    if [[ "$LAN_NET" == "0.0.0.0/0" ]]; then
        ufw_apply allow "${SSH_PORT}/tcp" comment "SSH"
    else
        ufw_apply allow from "$LAN_NET" to any port "$SSH_PORT" proto tcp comment "SSH-LAN"
    fi

    ufw_apply --force enable

    if (( DRY_RUN )); then
        dry_log "Se mostraría 'ufw status verbose' con la nueva configuración."
    else
        echo
        log_ok "Firewall inicializado."
        ufw status verbose
    fi
    pause
}

listar_puertos() {
    install_ufw_if_needed
    log_header "Puertos permitidos"
    ufw status numbered
    pause
}

anadir_puerto() {
    install_ufw_if_needed
    log_header "Añadir puerto permitido"

    read -rp "Introduce el puerto a permitir (ej: 80, 443): " port
    if ! [[ "$port" =~ ^[0-9]+$ ]] || (( port < 1 || port > 65535 )); then
        log_error "Puerto no válido."
        pause
        return
    fi

    read -rp "Protocolo (tcp/udp/both) [tcp]: " proto
    proto=${proto:-tcp}

    case "$proto" in
        tcp|udp|both) ;;
        *)
            log_error "Protocolo no válido."
            pause
            return
            ;;
    esac

    read -rp "Origen (IP/CIDR) opcional, deja vacío para 'cualquiera': " src
    read -rp "Comentario (opcional para ufw): " comment
    local comment_arg=()
    if [[ -n "${comment:-}" ]]; then
        comment_arg=(comment "$comment")
    fi

    if [[ -z "${src:-}" ]]; then
        if [[ "$proto" == "both" ]]; then
            ufw_apply allow "$port" "${comment_arg[@]}"
        else
            ufw_apply allow "$port/$proto" "${comment_arg[@]}"
        fi
    else
        # No validamos aquí porque ufw admite nombres, grupos, etc.
        if [[ "$proto" == "both" ]]; then
            ufw_apply allow from "$src" to any port "$port" "${comment_arg[@]}"
        else
            ufw_apply allow from "$src" to any port "$port" proto "$proto" "${comment_arg[@]}"
        fi
    fi

    log_ok "Regla procesada."
    if (( DRY_RUN )); then
        dry_log "No se muestran reglas porque no se ha aplicado ningún cambio real."
    else
        ufw status numbered
    fi
    pause
}

eliminar_puerto() {
    install_ufw_if_needed
    log_header "Eliminar puerto permitido"
    ufw status numbered
    echo
    read -rp "Introduce el número de regla a eliminar (tal y como sale en 'status numbered'): " num
    if ! [[ "$num" =~ ^[0-9]+$ ]]; then
        log_error "Número no válido."
        pause
        return
    fi

    if (( DRY_RUN )); then
        dry_log "Se ejecutaría: ufw delete $num"
    else
        ufw delete "$num"
        log_ok "Regla eliminada."
    fi
    pause
}

cambiar_puerto_ssh() {
    load_config
    install_ufw_if_needed

    log_header "Cambiar puerto SSH"
    warn_if_ssh_session

    echo "Puerto SSH actual (según config interna): $SSH_PORT"
    read -rp "Introduce el NUEVO puerto SSH (ej: 2222): " new_port

    if ! [[ "$new_port" =~ ^[0-9]+$ ]] || (( new_port < 1 || new_port > 65535 )); then
        log_error "Puerto no válido."
        pause
        return
    fi

    echo
    log_warn "Cambiar el puerto SSH puede dejarte sin acceso remoto si algo sale mal."
    echo "Asegúrate de tener una sesión abierta o acceso físico."
    if ! ask_yes_no "¿Continuar? (si/no) [no]:" "no"; then
        log_info "Operación cancelada."
        pause
        return
    fi

    local ssh_conf="/etc/ssh/sshd_config"
    local old_ssh_port="$SSH_PORT"

    # Abrir primero el nuevo puerto en ufw
    ufw_apply allow "${new_port}/tcp" comment "SSH-NUEVO"

    # Editar sshd_config
    backup_file_if_exists "$ssh_conf"

    if (( DRY_RUN )); then
        dry_log "Se cambiaría/añadiría 'Port ${new_port}' en ${ssh_conf}."
    else
        if grep -qE '^[[:space:]]*Port[[:space:]]+[0-9]+' "$ssh_conf"; then
            sed -i -E "s/^[[:space:]]*Port[[:space:]]*[0-9]+/Port ${new_port}/" "$ssh_conf"
        else
            echo "Port ${new_port}" >> "$ssh_conf"
        fi
    fi

    restart_ssh_service || { pause; return; }

    if (( DRY_RUN )); then
        dry_log "No se actualiza el fichero de configuración interna (${CONFIG_FILE}) en DRY-RUN."
    else
        SSH_PORT="$new_port"
        save_config
    fi

    echo
    log_ok "Puerto SSH objetivo: $new_port (anterior: $old_ssh_port)."
    if (( DRY_RUN )); then
        dry_log "No se han aplicado cambios reales en firewall ni en sshd_config."
    else
        echo
        echo "Reglas ufw actuales:"
        ufw status numbered
        echo
        echo "Cuando verifiques que el nuevo puerto funciona,"
        echo "elimina las reglas que permitan el puerto antiguo ($old_ssh_port)."
    fi
    pause
}

cambiar_lan_permitida() {
    load_config
    install_ufw_if_needed

    log_header "Cambiar LAN permitida para SSH"
    echo "LAN actual permitida para SSH (según config interna): $LAN_NET"
    read -rp "Introduce la NUEVA LAN en formato CIDR (ej: 192.168.1.0/24) o 0.0.0.0/0 para todos: " new_lan

    if [[ -z "$new_lan" ]]; then
        log_error "LAN no válida."
        pause
        return
    fi

    if ! validate_cidr "$new_lan"; then
        log_error "Formato CIDR no válido."
        pause
        return
    fi

    if [[ "$new_lan" == "0.0.0.0/0" ]]; then
        log_warn "Vas a permitir SSH desde TODAS las IPs (0.0.0.0/0)."
    fi

    log_info "Añadiendo nueva regla en ufw para SSH desde $new_lan ..."
    if [[ "$new_lan" == "0.0.0.0/0" ]]; then
        ufw_apply allow "${SSH_PORT}/tcp" comment "SSH"
    else
        ufw_apply allow from "$new_lan" to any port "$SSH_PORT" proto tcp comment "SSH-LAN"
    fi

    if (( DRY_RUN )); then
        dry_log "No se actualiza la configuración interna (${CONFIG_FILE}) en DRY-RUN."
    else
        LAN_NET="$new_lan"
        save_config
    fi

    echo
    log_ok "LAN permitida establecida a: $new_lan (antes: $LAN_NET)."
    if (( DRY_RUN )); then
        dry_log "No se muestran reglas porque no se ha aplicado ningún cambio real."
    else
        echo "Revisa las reglas antiguas de SSH en ufw y elimina las que ya no quieras mantener:"
        echo
        ufw status numbered
    fi
    pause
}

ver_estado_reglas() {
    install_ufw_if_needed
    log_header "Estado del firewall"
    ufw status verbose
    pause
}

# -------------------- Backup y restauración --------------------

backup_auto_internal() {
    # Uso interno opcional con sufijo
    local suffix="${1:-auto}"
    mkdir -p "$BACKUP_DIR"
    local file="$BACKUP_DIR/firewall_backup_${suffix}_$(date +%F_%H-%M-%S).tar.gz"

    if (( DRY_RUN )); then
        dry_log "Se crearía backup en: $file (incluyendo /etc/ufw, /etc/ssh/sshd_config y ${CONFIG_FILE})."
        return 0
    fi

    log_info "Creando backup en: $file"
    if tar czf "$file" /etc/ufw /etc/ssh/sshd_config "$CONFIG_FILE" 2>/dev/null; then
        log_ok "Backup creado."
    else
        log_error "Error al crear el backup."
    fi
}

backup_auto() {
    log_header "Backup automático"
    backup_auto_internal "manual_auto"
    pause
}

backup_manual() {
    mkdir -p "$BACKUP_DIR"
    log_header "Backup manual"
    read -rp "Nombre del backup (sin espacios, opcional .tar.gz): " name
    if [[ -z "$name" ]]; then
        log_error "Nombre no válido."
        pause
        return
    fi

    if [[ "$name" != *.tar.gz ]]; then
        name="${name}.tar.gz"
    fi

    local file="$BACKUP_DIR/$name"
    if (( DRY_RUN )); then
        dry_log "Se crearía backup en: $file (incluyendo /etc/ufw, /etc/ssh/sshd_config y ${CONFIG_FILE})."
    else
        log_info "Creando backup manual en: $file"
        if tar czf "$file" /etc/ufw /etc/ssh/sshd_config "$CONFIG_FILE" 2>/dev/null; then
            log_ok "Backup creado."
        else
            log_error "Error al crear el backup."
        fi
    fi
    pause
}

restaurar_backup() {
    mkdir -p "$BACKUP_DIR"
    log_header "Restaurar configuración desde backup"
    echo "Backups disponibles en $BACKUP_DIR:"
    echo

    local backups=("$BACKUP_DIR"/*.tar.gz)

    if [[ ${#backups[@]} -eq 0 ]]; then
        log_warn "No se encontraron backups."
        pause
        return
    fi

    local i=1
    for b in "${backups[@]}"; do
        local ts
        ts=$(date -r "$b" "+%F %T" 2>/dev/null || echo "desconocida")
        echo "[$i] $(basename "$b")   (modificado: $ts)"
        ((i++))
    done

    echo
    read -rp "Selecciona el número de backup a restaurar: " sel

    if ! [[ "$sel" =~ ^[0-9]+$ ]] || (( sel < 1 || sel >= i )); then
        log_error "Selección no válida."
        pause
        return
    fi

    local chosen="${backups[sel-1]}"
    echo
    log_warn "Esto sobrescribirá la configuración actual de /etc/ufw, /etc/ssh/sshd_config y ${CONFIG_FILE}."
    if ! ask_yes_no "¿Seguro que quieres restaurar '$chosen'? (si/no) [no]:" "no"; then
        log_info "Operación cancelada."
        pause
        return
    fi

    if (( DRY_RUN )); then
        dry_log "Se restauraría el backup: $chosen (tar xzf -C /)."
        dry_log "Se ejecutaría 'ufw reload' y se reiniciaría SSH."
        pause
        return
    fi

    if tar xzf "$chosen" -C /; then
        log_ok "Configuración restaurada desde backup."
    else
        log_error "Error al restaurar el backup."
        pause
        return
    fi

    log_info "Recargando ufw y reiniciando SSH..."
    ufw reload 2>/dev/null || true
    restart_ssh_service || true

    # Recargar posibles cambios en el puerto
    load_config

    log_ok "Restauración completada."
    pause
}

# -------------------- Menú principal --------------------

menu_principal() {
    while true; do
        clear 2>/dev/null || true
        echo -e "${C_BOLD}===============================${C_RESET}"
        echo -e "${C_BOLD}   Gestor de Firewall (ufw)    ${C_RESET}"
        echo -e "${C_BOLD}===============================${C_RESET}"
        load_config
        echo "Versión script:     $VERSION"
        echo "Puerto SSH actual:  $SSH_PORT"
        echo "LAN SSH permitida:  $LAN_NET"
        echo "Backups en:         $BACKUP_DIR"
        echo "Modo DRY-RUN:       $([[ $DRY_RUN -eq 1 ]] && echo 'ACTIVADO' || echo 'desactivado')"
        if [[ -n "${SSH_CONNECTION:-}" ]]; then
            local remote_ip
            remote_ip=${SSH_CONNECTION%% *}
            echo "Sesión actual:      SSH desde ${remote_ip}"
        fi
        echo "-------------------------------"
        echo "1) Inicializar firewall"
        echo "2) Listar puertos permitidos"
        echo "3) Añadir puerto permitido"
        echo "4) Eliminar puerto permitido"
        echo "5) Cambiar puerto SSH"
        echo "6) Cambiar LAN permitida (SSH)"
        echo "7) Ver estado / reglas"
        echo "8) Exportar configuración (backup automático)"
        echo "9) Restaurar configuración desde backup"
        echo "10) Backup manual"
        echo "11) Alternar modo DRY-RUN"
        echo "0) Salir"
        echo "-------------------------------"
        read -rp "Elige una opción: " opcion

        case "$opcion" in
            1) init_firewall ;;
            2) listar_puertos ;;
            3) anadir_puerto ;;
            4) eliminar_puerto ;;
            5) cambiar_puerto_ssh ;;
            6) cambiar_lan_permitida ;;
            7) ver_estado_reglas ;;
            8) backup_auto ;;
            9) restaurar_backup ;;
            10) backup_manual ;;
            11)
                if (( DRY_RUN )); then
                    DRY_RUN=0
                    log_info "Modo DRY-RUN DESACTIVADO (los cambios se aplicarán realmente)."
                else
                    DRY_RUN=1
                    log_warn "Modo DRY-RUN ACTIVADO (no se aplicará ningún cambio real)."
                fi
                pause
                ;;
            0)
                echo
                log_info "Saliendo..."
                exit 0
                ;;
            *)
                log_warn "Opción no válida."
                pause
                ;;
        esac
    done
}

# -------------------- Main --------------------

main() {
    check_root

    local action="menu"

    # Parseo simple de argumentos, permitiendo --dry-run + una acción
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --dry-run)
                DRY_RUN=1
                ;;
            --help|-h)
                action="help"
                ;;
            --init)
                action="init"
                ;;
            --status)
                action="status"
                ;;
            --backup)
                action="backup"
                ;;
            --restore)
                action="restore"
                ;;
            *)
                log_error "Opción de línea de comandos no reconocida: $1"
                echo
                print_help
                exit 1
                ;;
        esac
        shift
    done

    load_config

    case "$action" in
        help)
            print_help
            ;;
        init)
            init_firewall
            ;;
        status)
            ver_estado_reglas
            ;;
        backup)
            backup_auto
            ;;
        restore)
            restaurar_backup
            ;;
        menu)
            menu_principal
            ;;
        *)
            print_help
            exit 1
            ;;
    esac
}

main "$@"
