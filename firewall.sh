#!/usr/bin/env bash
#
# Firewall_Kit — gestor de firewall para Linux basado en ufw
#
# Requiere: bash >= 4.2, ufw, tar, coreutils, grep, sed y awk.
# Opcional: ss (iproute2) para verificar puertos, flock, logger,
#           systemd-run y semanage (SELinux).
#
# Uso rápido (como root):
#   sudo ./firewall.sh                        # Menú interactivo
#   sudo ./firewall.sh --yes --init           # Inicializar sin preguntas
#   sudo ./firewall.sh --add 443/tcp          # Abrir un puerto
#   sudo ./firewall.sh --ssh-port 2222        # Cambiar el puerto SSH
#   sudo ./firewall.sh --dry-run --init       # Simular sin aplicar cambios
#   sudo ./firewall.sh --help                 # Todas las opciones

set -uo pipefail
umask 077
shopt -s nullglob

# -------------------- Constantes globales --------------------

readonly VERSION="2.0"

# FK_ROOT permite ejecutar el script contra un árbol de ficheros alternativo
# (solo para tests). En uso normal está vacío y se usan las rutas del sistema.
readonly FK_ROOT="${FK_ROOT:-}"
readonly CONFIG_FILE="${FK_ROOT}/etc/firewall-manager.conf"
readonly BACKUP_DIR="${FK_ROOT}/var/backups/firewall-manager"
readonly SSHD_CONFIG="${FK_ROOT}/etc/ssh/sshd_config"
readonly SSHD_CONFIG_DIR="${FK_ROOT}/etc/ssh/sshd_config.d"
readonly UFW_CONF="${FK_ROOT}/etc/ufw/ufw.conf"
readonly RUN_DIR="${FK_ROOT}/run/firewall-kit"

# Rutas (relativas a /) que se guardan en los backups
readonly -a BACKUP_PATHS=(etc/ufw etc/ssh/sshd_config etc/ssh/sshd_config.d etc/firewall-manager.conf)

readonly MANAGED_BEGIN="# BEGIN Firewall_Kit"
readonly MANAGED_END="# END Firewall_Kit"
readonly PORT_COMMENT_PREFIX="#[Firewall_Kit] "

SELF="$(readlink -f "${BASH_SOURCE[0]}")"
readonly SELF

# -------------------- Estado y opciones --------------------

# Configuración persistente (ver load_config / save_config)
SSH_PORT=22
LAN_NET="0.0.0.0/0"
SSH_LIMIT="si"
BACKUP_KEEP=20
ROLLBACK_TIMEOUT=60

# Opciones de ejecución
DRY_RUN=0             # 1 = simulación, no se aplica ningún cambio
ASSUME_YES=0          # 1 = responder "si" a las confirmaciones (--yes)
USE_COLOR=1
CLI_ROLLBACK_TIMEOUT=""
IN_MENU=0

# Estado interno
ACTION=""
ACTION_ARG=""
ADD_FROM=""
ADD_ACTION=""
ADD_COMMENT=""
PM=""
LAST_BACKUP=""
GUARD_TOKEN=""
GUARD_UNIT=""
SESSION_CLIENT_IP=""
SESSION_SERVER_PORT=""
PORT_SPEC=""
RULE_PROTO=""
RULES=()
BACKUPS=()
SSH_RULE_ARGS=()
R_ROUTE=0 R_ACTION="" R_DIR="in" R_IFACE="" R_FROM="any" R_TO="any" R_DPORT="" R_PROTO="" R_DAPP=""

# -------------------- Colores / mensajes ----------------------

C_RED="" C_GREEN="" C_YELLOW="" C_BLUE="" C_BOLD="" C_RESET=""

setup_colors() {
    if (( USE_COLOR )) && [[ -t 1 && -z "${NO_COLOR:-}" ]]; then
        C_RED=$'\e[31m'
        C_GREEN=$'\e[32m'
        C_YELLOW=$'\e[33m'
        C_BLUE=$'\e[34m'
        C_BOLD=$'\e[1m'
        C_RESET=$'\e[0m'
    fi
}

log_info()  { printf '%s[INFO]%s  %s\n' "$C_BLUE" "$C_RESET" "$*"; }
log_ok()    { printf '%s[OK]%s    %s\n' "$C_GREEN" "$C_RESET" "$*"; }
log_warn()  { printf '%s[WARN]%s  %s\n' "$C_YELLOW" "$C_RESET" "$*" >&2; }
log_error() { printf '%s[ERROR]%s %s\n' "$C_RED" "$C_RESET" "$*" >&2; }
dry_log()   { printf '%s[DRY-RUN]%s %s\n' "$C_YELLOW" "$C_RESET" "$*"; }
log_header() {
    printf '\n%s==============================%s\n' "$C_BOLD" "$C_RESET"
    printf '%s  %s%s\n' "$C_BOLD" "$*" "$C_RESET"
    printf '%s==============================%s\n\n' "$C_BOLD" "$C_RESET"
}

die() {
    log_error "$*"
    exit 1
}

usage_error() {
    log_error "$*"
    echo "Usa --help para ver las opciones disponibles." >&2
    exit 1
}

# Registro de auditoría en syslog (journalctl -t firewall-kit)
audit() {
    (( DRY_RUN )) && return 0
    if command -v logger >/dev/null 2>&1; then
        logger -t firewall-kit -- "$*" 2>/dev/null || true
    fi
    return 0
}

on_interrupt() {
    echo
    log_warn "Ejecución interrumpida por el usuario."
    if [[ -n "$GUARD_TOKEN" ]]; then
        log_warn "La reversión automática sigue armada: si no se confirma, se restaurará el estado anterior."
    fi
    exit 130
}
trap on_interrupt INT

# -------------------- Entrada del usuario --------------------

# Lee una línea en la variable $1. Si la entrada se cierra (EOF) termina el
# script: así se evita el bucle infinito del menú de la v1.1 sin stdin.
read_input() {
    local __var="$1" __prompt="$2" __value
    if ! read -r -p "$__prompt " __value; then
        echo
        die "Entrada cerrada (EOF). Para uso no interactivo consulta --help (opción --yes)."
    fi
    printf -v "$__var" '%s' "$__value"
}

is_yes() {
    case "${1:-}" in
        [sS]|[sS][iI]|[sS]í|[sS]Í|[yY]|[yY][eE][sS]) return 0 ;;
        *) return 1 ;;
    esac
}

is_no() {
    case "${1:-}" in
        [nN]|[nN][oO]) return 0 ;;
        *) return 1 ;;
    esac
}

# Uso: ask_yes_no "Pregunta (si/no) [no]:" "no"
ask_yes_no() {
    local prompt="$1" default="${2:-no}" answer
    if (( ASSUME_YES )); then
        printf '%s si (--yes)\n' "$prompt"
        return 0
    fi
    while true; do
        read_input answer "$prompt"
        answer="${answer:-$default}"
        if is_yes "$answer"; then return 0; fi
        if is_no "$answer"; then return 1; fi
        log_warn "Respuesta no reconocida: escribe 'si' o 'no'."
    done
}

pause() {
    (( IN_MENU )) || return 0
    echo
    read -r -p "Pulsa ENTER para continuar..." _ || true
}

# -------------------- Utilidades básicas --------------------

check_root() {
    [[ -n "$FK_ROOT" ]] && return 0   # entorno de tests
    if [[ "$(id -u)" -ne 0 ]]; then
        die "Este script debe ejecutarse como root (sudo)."
    fi
}

have_systemd() {
    [[ -d "${FK_ROOT}/run/systemd/system" ]] && command -v systemctl >/dev/null 2>&1
}

in_list() {
    local needle="$1" item
    shift
    for item in "$@"; do
        [[ "$item" == "$needle" ]] && return 0
    done
    return 1
}

acquire_lock() {
    command -v flock >/dev/null 2>&1 || return 0
    mkdir -p "$RUN_DIR" 2>/dev/null || return 0
    exec 9>"$RUN_DIR/lock" || return 0
    flock -n 9 || die "Ya hay otra instancia de Firewall_Kit en ejecución."
}

print_help() {
    local me
    me="$(basename "$0")"
    cat <<EOF
Firewall_Kit v${VERSION} — gestor de firewall para Linux basado en ufw

Uso:
  ${me}                         Menú interactivo
  ${me} ACCIÓN [opciones]       Modo línea de comandos

Acciones:
  --init                       Inicializar ufw: entrante DENEGADO, saliente
                               PERMITIDO y SSH permitido (borra las reglas actuales)
  --status                     Estado detallado de ufw
  --list                       Listar las reglas numeradas
  --add PUERTO[/PROTO]         Añadir regla. Ej: 443/tcp, 53, 6000:6007/udp
      --from ORIGEN            IP o CIDR de origen (IPv4 o IPv6). Por defecto: cualquiera
      --action ACCIÓN          allow (por defecto), limit, deny o reject
      --comment TEXTO          Comentario de la regla
  --delete N                   Eliminar la regla N (numeración de --list)
  --ssh-port PUERTO            Cambiar el puerto de SSH de forma segura
  --lan CIDR                   Permitir SSH solo desde una red IPv4 ('any' = todas)
  --ssh-limit si|no            Activar/desactivar 'ufw limit' en las reglas SSH
  --backup [NOMBRE]            Crear backup (automático o con nombre)
  --list-backups               Listar backups disponibles
  --restore [ARCHIVO]          Restaurar un backup (sin ARCHIVO: selección interactiva)
  -h, --help                   Mostrar esta ayuda
  -V, --version                Mostrar la versión

Opciones globales:
  -y, --yes                    Responder 'si' a las confirmaciones (uso no interactivo).
                               Las operaciones que dejarían sin acceso SSH a la sesión
                               actual se abortan igualmente.
  --dry-run                    Simular: muestra los cambios sin aplicar ninguno
  --rollback-timeout SEG       Segundos para confirmar cambios arriesgados cuando se
                               trabaja por SSH; si no se confirman, se revierten
                               (0 = desactivar; por defecto ${ROLLBACK_TIMEOUT})
  --no-color                   Desactivar colores (también se respeta NO_COLOR)

Ejemplos:
  sudo ${me} --yes --init
  sudo ${me} --add 443/tcp --comment "HTTPS"
  sudo ${me} --add 5432/tcp --from 10.0.0.0/8 --comment "PostgreSQL"
  sudo ${me} --lan 192.168.1.0/24
  sudo ${me} --dry-run --ssh-port 2222

Archivos:
  Configuración:          ${CONFIG_FILE}
  Directorio de backups:  ${BACKUP_DIR}
  Registro de auditoría:  syslog (journalctl -t firewall-kit)

Código de salida: 0 = correcto, 1 = error u operación cancelada.
EOF
}

# -------------------- Validación --------------------

# Puerto decimal 1-65535. Se interpreta siempre en base 10: en la v1.1 un
# valor como "08080" o "070000" se evaluaba como octal y saltaba la validación.
valid_port() {
    [[ "${1:-}" =~ ^[0-9]{1,5}$ ]] && (( 10#$1 >= 1 && 10#$1 <= 65535 ))
}

norm_port() {
    printf '%d' "$((10#$1))"
}

# Acepta "80" o un rango "6000:6007"; deja el resultado normalizado en PORT_SPEC
parse_port_spec() {
    local spec="$1" a b
    PORT_SPEC=""
    if [[ "$spec" =~ ^([0-9]{1,5}):([0-9]{1,5})$ ]]; then
        a="${BASH_REMATCH[1]}"
        b="${BASH_REMATCH[2]}"
        valid_port "$a" && valid_port "$b" || return 1
        a=$(norm_port "$a")
        b=$(norm_port "$b")
        (( a < b )) || return 1
        PORT_SPEC="${a}:${b}"
    elif valid_port "$spec"; then
        PORT_SPEC=$(norm_port "$spec")
    else
        return 1
    fi
}

# Acepta "443", "443/tcp" o "6000:6007/udp"; deja PORT_SPEC y RULE_PROTO
parse_rule_target() {
    local target="$1"
    RULE_PROTO=""
    if [[ "$target" == */* ]]; then
        RULE_PROTO="${target#*/}"
        target="${target%%/*}"
        case "$RULE_PROTO" in
            tcp|udp) ;;
            *) return 1 ;;
        esac
    fi
    parse_port_spec "$target"
}

valid_ipv4() {
    local octet
    [[ "${1:-}" =~ ^([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})$ ]] || return 1
    for octet in "${BASH_REMATCH[@]:1}"; do
        (( 10#$octet <= 255 )) || return 1
    done
}

ipv4_to_int() {
    local a b c d
    IFS=. read -r a b c d <<< "$1"
    printf '%d' "$(( (10#$a << 24) | (10#$b << 16) | (10#$c << 8) | 10#$d ))"
}

int_to_ipv4() {
    local n="$1"
    printf '%d.%d.%d.%d' "$(( (n >> 24) & 255 ))" "$(( (n >> 16) & 255 ))" "$(( (n >> 8) & 255 ))" "$(( n & 255 ))"
}

ipv4_mask() {
    local bits="$1"
    if (( bits == 0 )); then
        printf '0'
    else
        printf '%d' "$(( (0xFFFFFFFF << (32 - bits)) & 0xFFFFFFFF ))"
    fi
}

# Normaliza una red IPv4: "any" -> 0.0.0.0/0, "1.2.3.4" -> 1.2.3.4/32,
# "10.1.2.3/16" -> 10.1.0.0/16. Devuelve 1 si el formato no es válido
# (por ejemplo "1.2.3.4/", que la v1.1 aceptaba).
normalize_ipv4_cidr() {
    local input="${1:-}" ip bits net
    [[ "$input" == "any" ]] && input="0.0.0.0/0"
    if [[ "$input" == */* ]]; then
        ip="${input%/*}"
        bits="${input#*/}"
        [[ "$bits" =~ ^[0-9]{1,2}$ ]] && (( 10#$bits <= 32 )) || return 1
        bits=$((10#$bits))
    else
        ip="$input"
        bits=32
    fi
    valid_ipv4 "$ip" || return 1
    net=$(( $(ipv4_to_int "$ip") & $(ipv4_mask "$bits") ))
    printf '%s/%d\n' "$(int_to_ipv4 "$net")" "$bits"
}

# ¿Pertenece la IP $1 a la red normalizada $2?
ipv4_in_cidr() {
    local ip="$1" cidr="$2" bits mask
    valid_ipv4 "$ip" || return 1
    bits="${cidr#*/}"
    mask=$(ipv4_mask "$bits")
    (( ($(ipv4_to_int "$ip") & mask) == ($(ipv4_to_int "${cidr%/*}") & mask) ))
}

# Validación de direcciones IPv6 (con prefijo opcional), sin IPv4 embebida
valid_ipv6() {
    local input="${1:-}" addr bits marked doubles group count=0
    local -a parts=()
    addr="${input%/*}"
    if [[ "$input" == */* ]]; then
        bits="${input##*/}"
        [[ "$bits" =~ ^[0-9]{1,3}$ ]] && (( 10#$bits <= 128 )) || return 1
    fi
    [[ "$addr" =~ ^[0-9A-Fa-f:]+$ && "$addr" == *:* && "$addr" != *:::* ]] || return 1
    marked="${addr//::/@}"
    doubles="${marked//[^@]/}"
    (( ${#doubles} <= 1 )) || return 1
    [[ "$marked" != :* && "$marked" != *: ]] || return 1
    IFS=: read -r -a parts <<< "${marked//@/:}"
    for group in ${parts[@]+"${parts[@]}"}; do
        [[ -z "$group" ]] && continue
        [[ "$group" =~ ^[0-9A-Fa-f]{1,4}$ ]] || return 1
        count=$((count + 1))
    done
    if (( ${#doubles} == 1 )); then
        (( count <= 7 ))
    else
        (( count == 8 ))
    fi
}

# Origen de una regla en el formato que usa ufw ("any", IP o CIDR)
normalize_source() {
    local src="${1:-}" net
    if [[ -z "$src" || "$src" == "any" ]]; then
        printf 'any'
    elif net=$(normalize_ipv4_cidr "$src"); then
        ufw_addr "$net"
    elif valid_ipv6 "$src"; then
        printf '%s' "$src"
    else
        return 1
    fi
}

# ufw muestra las /32 sin prefijo y 0.0.0.0/0 como "any"
ufw_addr() {
    case "$1" in
        0.0.0.0/0) printf 'any' ;;
        */32) printf '%s' "${1%/32}" ;;
        *) printf '%s' "$1" ;;
    esac
}

# ufw rechaza las comillas simples en los comentarios ("Invalid syntax")
valid_comment() {
    local comment="${1-}"
    (( ${#comment} <= 64 )) || return 1
    case "$comment" in
        *"'"*|*'"'*|*\\*) return 1 ;;
    esac
    [[ ! "$comment" =~ [[:cntrl:]] ]]
}

# -------------------- Configuración --------------------

load_config() {
    SSH_PORT=""
    LAN_NET="0.0.0.0/0"
    SSH_LIMIT="si"
    BACKUP_KEEP=20
    ROLLBACK_TIMEOUT=60

    local need_save=0 line key value net
    local re_line='^[[:space:]]*([A-Z_]+)[[:space:]]*=[[:space:]]*(.*)$'
    local re_dq='^"(.*)"$' re_sq="^'(.*)'$"

    if [[ -f "$CONFIG_FILE" ]]; then
        if [[ -n "$(find "$CONFIG_FILE" -perm /022 2>/dev/null)" ]]; then
            log_warn "$CONFIG_FILE es modificable por otros usuarios: revisa sus permisos (chmod 600)."
        fi
        # La configuración se interpreta como datos (clave=valor), nunca se
        # ejecuta con 'source' como hacía la v1.1.
        while IFS= read -r line || [[ -n "$line" ]]; do
            [[ "$line" =~ $re_line ]] || continue
            key="${BASH_REMATCH[1]}"
            value="${BASH_REMATCH[2]}"
            value="${value%%#*}"
            value="${value%"${value##*[![:space:]]}"}"
            if [[ "$value" =~ $re_dq || "$value" =~ $re_sq ]]; then
                value="${BASH_REMATCH[1]}"
            fi
            case "$key" in
                SSH_PORT)
                    if valid_port "$value"; then
                        SSH_PORT=$(norm_port "$value")
                    else
                        log_warn "SSH_PORT no válido en $CONFIG_FILE: '$value' (se ignora)."
                    fi
                    ;;
                LAN_NET)
                    if net=$(normalize_ipv4_cidr "$value"); then
                        LAN_NET="$net"
                    else
                        log_warn "LAN_NET no válida en $CONFIG_FILE: '$value' (se usa 0.0.0.0/0)."
                    fi
                    ;;
                SSH_LIMIT)
                    case "$value" in
                        si|no) SSH_LIMIT="$value" ;;
                        *) log_warn "SSH_LIMIT no válido en $CONFIG_FILE: '$value' (se usa 'si')." ;;
                    esac
                    ;;
                BACKUP_KEEP)
                    if [[ "$value" =~ ^[0-9]{1,4}$ ]]; then
                        BACKUP_KEEP=$((10#$value))
                    else
                        log_warn "BACKUP_KEEP no válido en $CONFIG_FILE: '$value' (se usa 20)."
                    fi
                    ;;
                ROLLBACK_TIMEOUT)
                    if [[ "$value" =~ ^[0-9]{1,4}$ ]]; then
                        ROLLBACK_TIMEOUT=$((10#$value))
                    else
                        log_warn "ROLLBACK_TIMEOUT no válido en $CONFIG_FILE: '$value' (se usa 60)."
                    fi
                    ;;
            esac
        done < "$CONFIG_FILE"
    else
        need_save=1
    fi

    # El puerto guardado puede quedar desfasado si se cambió sshd a mano:
    # se contrasta con la configuración real de sshd.
    local -a detected=()
    mapfile -t detected < <(detect_ssh_ports)
    if [[ -z "$SSH_PORT" ]]; then
        SSH_PORT="${detected[0]:-22}"
        need_save=1
    elif (( ${#detected[@]} > 0 )) && ! in_list "$SSH_PORT" "${detected[@]}"; then
        log_warn "El puerto SSH guardado ($SSH_PORT) no coincide con sshd (${detected[*]}): se usa ${detected[0]}."
        SSH_PORT="${detected[0]}"
        need_save=1
    fi

    if (( need_save )); then
        save_config || true
    fi
}

save_config() {
    (( DRY_RUN )) && return 0
    local tmp
    mkdir -p "$(dirname "$CONFIG_FILE")" || return 1
    tmp=$(mktemp "${CONFIG_FILE}.XXXXXX") || return 1
    cat > "$tmp" <<EOF
# Configuración de Firewall_Kit (se reescribe automáticamente)
# Puerto SSH gestionado
SSH_PORT=${SSH_PORT}
# Red IPv4 (CIDR) desde la que se permite SSH; 0.0.0.0/0 = todas
LAN_NET="${LAN_NET}"
# Limitar intentos de conexión SSH con 'ufw limit' (si/no)
SSH_LIMIT="${SSH_LIMIT}"
# Backups automáticos que se conservan (0 = sin límite)
BACKUP_KEEP=${BACKUP_KEEP}
# Segundos para confirmar cambios arriesgados hechos por SSH antes de revertirlos (0 = desactivado)
ROLLBACK_TIMEOUT=${ROLLBACK_TIMEOUT}
EOF
    if chmod 600 "$tmp" && mv -f "$tmp" "$CONFIG_FILE"; then
        return 0
    fi
    rm -f "$tmp"
    log_error "No se pudo guardar $CONFIG_FILE."
    return 1
}

effective_rollback_timeout() {
    printf '%s' "${CLI_ROLLBACK_TIMEOUT:-$ROLLBACK_TIMEOUT}"
}

# -------------------- Paquetes / ufw --------------------

detect_package_manager() {
    if command -v apt-get >/dev/null 2>&1; then
        PM="apt"
    elif command -v dnf >/dev/null 2>&1; then
        PM="dnf"
    elif command -v yum >/dev/null 2>&1; then
        PM="yum"
    elif command -v zypper >/dev/null 2>&1; then
        PM="zypper"
    elif command -v pacman >/dev/null 2>&1; then
        PM="pacman"
    else
        PM=""
    fi
}

install_ufw() {
    local rc=1
    detect_package_manager
    case "$PM" in
        apt)
            apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y ufw
            rc=$?
            ;;
        dnf|yum)
            "$PM" install -y ufw
            rc=$?
            if (( rc != 0 )); then
                log_error "En RHEL/Rocky/Alma ufw está en EPEL: ejecuta '$PM install -y epel-release' y reintenta."
            fi
            ;;
        zypper)
            zypper --non-interactive install ufw
            rc=$?
            ;;
        pacman)
            pacman -S --noconfirm --needed ufw
            rc=$?
            ;;
        *)
            log_error "No se detectó un gestor de paquetes compatible. Instala ufw manualmente."
            return 1
            ;;
    esac
    if (( rc != 0 )) || ! command -v ufw >/dev/null 2>&1; then
        log_error "No se pudo instalar ufw."
        return 1
    fi
    log_ok "ufw instalado correctamente."
    audit "ufw instalado con $PM"
}

# Para operaciones que modifican: instala ufw si falta (preguntando antes)
ensure_ufw() {
    command -v ufw >/dev/null 2>&1 && return 0
    log_warn "ufw no está instalado."
    if (( DRY_RUN )); then
        dry_log "Se instalaría ufw con el gestor de paquetes del sistema."
        return 0
    fi
    ask_yes_no "¿Instalar ufw ahora? (si/no) [si]:" "si" || return 1
    install_ufw
}

# Para operaciones de solo lectura: nunca instala nada
require_ufw() {
    command -v ufw >/dev/null 2>&1 && return 0
    log_error "ufw no está instalado (la opción 'Inicializar firewall' lo instala)."
    return 1
}

ufw_is_active() {
    command -v ufw >/dev/null 2>&1 || return 1
    LC_ALL=C ufw status 2>/dev/null | grep -q '^Status: active'
}

ufw_state_text() {
    if ! command -v ufw >/dev/null 2>&1; then
        printf 'no instalado'
    elif ufw_is_active; then
        printf 'activo'
    else
        printf 'inactivo'
    fi
}

# Ejecuta un comando ufw que modifica el estado. Respeta DRY_RUN y devuelve
# error si ufw falla, aunque su código de salida sea 0 (ufw devuelve 0 en
# "Could not delete non-existent rule" y en algunos fallos de iptables).
ufw_run() {
    if (( DRY_RUN )); then
        dry_log "ufw $*"
        return 0
    fi
    local out rc
    out=$(LC_ALL=C ufw "$@" 2>&1)
    rc=$?
    [[ -n "$out" ]] && printf '%s\n' "$out"
    if (( rc != 0 )) || [[ "$out" == *ERROR* || "$out" == *"Could not delete non-existent rule"* ]]; then
        log_error "Falló: ufw $*"
        return 1
    fi
    audit "ufw $*"
    return 0
}

# Restablece el estado de ufw según /etc/ufw/ufw.conf (tras restaurar ficheros)
ufw_apply_state() {
    command -v ufw >/dev/null 2>&1 || return 0
    if grep -qE '^[[:space:]]*ENABLED=yes' "$UFW_CONF" 2>/dev/null; then
        if ufw_is_active; then
            ufw_run reload
        else
            ufw_run --force enable
        fi
    elif ufw_is_active; then
        ufw_run disable
    fi
}

# -------------------- Reglas de ufw --------------------

# Carga en RULES las reglas de usuario tal y como las muestra 'ufw show added'
# (funciona con el firewall activo o inactivo, y une las versiones IPv4/IPv6).
load_rules() {
    RULES=()
    command -v ufw >/dev/null 2>&1 || return 0
    local line
    while IFS= read -r line; do
        [[ "$line" == "ufw "* ]] && RULES+=("${line#ufw }")
    done < <(LC_ALL=C ufw show added 2>/dev/null)
}

print_rules() {
    load_rules
    if (( ${#RULES[@]} == 0 )); then
        echo "  (no hay reglas de usuario)"
        return 0
    fi
    local i
    for (( i = 0; i < ${#RULES[@]}; i++ )); do
        printf '  [%2d] ufw %s\n' "$((i + 1))" "${RULES[i]}"
    done
}

spec_without_comment() {
    local spec="$1" re="^(.*) comment '[^']*'$"
    if [[ "$spec" =~ $re ]]; then
        spec="${BASH_REMATCH[1]}"
    fi
    printf '%s' "$spec"
}

# Separa una regla en palabras respetando las comillas simples
# (perfiles de aplicación como 'Nginx Full').
split_spec() {
    local spec="$1" token="" quoted=0 char i
    for (( i = 0; i < ${#spec}; i++ )); do
        char="${spec:i:1}"
        if (( quoted )); then
            if [[ "$char" == "'" ]]; then quoted=0; else token+="$char"; fi
        elif [[ "$char" == "'" ]]; then
            quoted=1
        elif [[ "$char" == " " ]]; then
            [[ -n "$token" ]] && printf '%s\n' "$token"
            token=""
        else
            token+="$char"
        fi
    done
    [[ -n "$token" ]] && printf '%s\n' "$token"
    return 0
}

# Descompone una regla de 'ufw show added' en las variables R_*
spec_parse() {
    R_ROUTE=0 R_ACTION="" R_DIR="in" R_IFACE="" R_FROM="any" R_TO="any" R_DPORT="" R_PROTO="" R_DAPP=""
    local -a tokens=()
    mapfile -t tokens < <(split_spec "$(spec_without_comment "$1")")
    local n=${#tokens[@]} i=0 ctx=""
    (( n > 0 )) || return 1
    if [[ "${tokens[0]}" == "route" ]]; then
        R_ROUTE=1
        i=1
    fi
    R_ACTION="${tokens[i]:-}"
    i=$((i + 1))
    while (( i < n )); do
        case "${tokens[i]}" in
            in|out) R_DIR="${tokens[i]}" ;;
            on) i=$((i + 1)); R_IFACE="${tokens[i]:-}" ;;
            log|log-all) ;;
            from) i=$((i + 1)); R_FROM="${tokens[i]:-}"; ctx="from" ;;
            to) i=$((i + 1)); R_TO="${tokens[i]:-}"; ctx="to" ;;
            port)
                i=$((i + 1))
                [[ "$ctx" == "to" ]] && R_DPORT="${tokens[i]:-}"
                ;;
            app)
                i=$((i + 1))
                [[ "$ctx" == "to" ]] && R_DAPP="${tokens[i]:-}"
                ;;
            proto) i=$((i + 1)); R_PROTO="${tokens[i]:-}" ;;
            *)
                # Forma corta: "22/tcp", "80" o un perfil de aplicación
                if [[ "${tokens[i]}" =~ ^([0-9:,]+)(/(tcp|udp))?$ ]]; then
                    R_DPORT="${BASH_REMATCH[1]}"
                    R_PROTO="${BASH_REMATCH[3]}"
                else
                    R_DAPP="${tokens[i]}"
                fi
                ;;
        esac
        i=$((i + 1))
    done
    return 0
}

# ¿Es una regla que permite SSH (TCP) entrante en el puerto $2?
is_ssh_rule() {
    local spec="$1" port="$2"
    spec_parse "$spec" || return 1
    (( R_ROUTE == 0 )) && [[ "$R_DIR" == "in" ]] || return 1
    [[ "$R_ACTION" == "allow" || "$R_ACTION" == "limit" ]] || return 1
    if [[ "$R_DPORT" == "$port" && ( -z "$R_PROTO" || "$R_PROTO" == "tcp" ) ]]; then
        return 0
    fi
    [[ "$R_DAPP" == "OpenSSH" && "$port" == "22" ]]
}

ssh_action() {
    if [[ "$SSH_LIMIT" == "si" ]]; then printf 'limit'; else printf 'allow'; fi
}

# ¿Coincide exactamente con la regla SSH que corresponde a la configuración?
is_desired_ssh_rule() {
    local spec="$1" port="$2"
    spec_parse "$spec" || return 1
    (( R_ROUTE == 0 )) && [[ "$R_DIR" == "in" && -z "$R_IFACE" && "$R_TO" == "any" ]] || return 1
    [[ "$R_DPORT" == "$port" && "$R_PROTO" == "tcp" && -z "$R_DAPP" ]] || return 1
    [[ "$R_ACTION" == "$(ssh_action)" && "$R_FROM" == "$(ufw_addr "$LAN_NET")" ]]
}

# Argumentos de ufw para la regla SSH del puerto $1 (respeta LAN_NET y SSH_LIMIT)
ssh_rule_args() {
    local port="$1" action src
    action=$(ssh_action)
    src=$(ufw_addr "$LAN_NET")
    if [[ "$src" == "any" ]]; then
        SSH_RULE_ARGS=("$action" "${port}/tcp" comment "SSH")
    else
        SSH_RULE_ARGS=("$action" from "$src" to any port "$port" proto tcp comment "SSH-LAN")
    fi
}

ssh_rule_add() {
    ssh_rule_args "$1"
    ufw_run "${SSH_RULE_ARGS[@]}"
}

# Imprime las reglas SSH del puerto $1; con $2 = "undesired" solo las que no
# corresponden a la configuración actual (LAN / limit).
ssh_rules_matching() {
    local port="$1" mode="${2:-all}" rule
    load_rules
    for rule in ${RULES[@]+"${RULES[@]}"}; do
        is_ssh_rule "$rule" "$port" || continue
        if [[ "$mode" == "undesired" ]] && is_desired_ssh_rule "$rule" "$port"; then
            continue
        fi
        printf '%s\n' "$rule"
    done
}

delete_rule_spec() {
    local -a tokens=()
    mapfile -t tokens < <(split_spec "$(spec_without_comment "$1")")
    (( ${#tokens[@]} > 0 )) || return 1
    if [[ "${tokens[0]}" == "route" ]]; then
        ufw_run --force route delete "${tokens[@]:1}"
    else
        ufw_run --force delete "${tokens[@]}"
    fi
}

# Añade la regla SSH deseada para SSH_PORT y elimina el resto de reglas SSH
# de ese puerto (otra LAN, abiertas a todos, allow/limit distinto...).
apply_ssh_policy() {
    local rule rc=0
    local -a obsolete=()
    ssh_rule_add "$SSH_PORT" || return 1
    mapfile -t obsolete < <(ssh_rules_matching "$SSH_PORT" undesired)
    for rule in ${obsolete[@]+"${obsolete[@]}"}; do
        delete_rule_spec "$rule" || { log_warn "No se pudo eliminar: ufw $rule"; rc=1; }
    done
    return "$rc"
}

# -------------------- SSH --------------------

find_sshd() {
    local path
    path=$(command -v sshd 2>/dev/null) || path=""
    if [[ -z "$path" && -x /usr/sbin/sshd ]]; then
        path=/usr/sbin/sshd
    fi
    [[ -n "$path" ]] || return 1
    printf '%s' "$path"
}

# sshd -t / -T necesitan el directorio de separación de privilegios
ensure_privsep_dir() {
    [[ -z "$FK_ROOT" && ! -d /run/sshd ]] || return 0
    (( DRY_RUN )) && return 0
    mkdir -m 0755 /run/sshd 2>/dev/null || true
}

# Ficheros de sshd_config.d incluidos desde sshd_config
ssh_dropin_files() {
    [[ -f "$SSHD_CONFIG" ]] || return 0
    grep -qiE '^[[:space:]]*Include[[:space:]].*sshd_config\.d' "$SSHD_CONFIG" || return 0
    local file
    for file in "$SSHD_CONFIG_DIR"/*.conf; do
        [[ -f "$file" ]] && printf '%s\n' "$file"
    done
    return 0
}

parse_ssh_ports_from_files() {
    [[ -f "$SSHD_CONFIG" ]] || return 0
    local -a files=("$SSHD_CONFIG")
    local -a dropins=()
    mapfile -t dropins < <(ssh_dropin_files)
    files+=(${dropins[@]+"${dropins[@]}"})
    local ports
    ports=$(awk '{
            line = $0; sub(/^[ \t]+/, "", line)
            if (tolower(line) ~ /^port([ \t]|=)/) {
                split(line, f, /[ \t=]+/)
                if (f[2] ~ /^[0-9]+$/) print f[2] + 0
            }
        }' "${files[@]}" | sort -un)
    printf '%s\n' "${ports:-22}"
}

# Puertos en los que escucha (o escuchará) sshd según su configuración.
# Usa 'sshd -T', que resuelve los Include; si falla, analiza los ficheros.
# Nota: 'Port' es acumulativo, sshd escucha en todos los que aparezcan.
detect_ssh_ports() {
    local sshd out=""
    if sshd=$(find_sshd); then
        ensure_privsep_dir
        out=$("$sshd" -T -f "$SSHD_CONFIG" 2>/dev/null | awk '$1 == "port" && $2 ~ /^[0-9]+$/ { print $2 + 0 }' | sort -un)
    fi
    if [[ -z "$out" ]]; then
        out=$(parse_ssh_ports_from_files)
    fi
    if [[ -n "$out" ]]; then
        printf '%s\n' "$out"
    fi
    return 0
}

sshd_test() {
    local sshd out
    if ! sshd=$(find_sshd); then
        log_warn "No se encontró sshd: no se puede validar su configuración."
        return 0
    fi
    ensure_privsep_dir
    if out=$("$sshd" -t -f "$SSHD_CONFIG" 2>&1); then
        return 0
    fi
    log_error "La configuración de sshd no es válida (sshd -t):"
    printf '    %s\n' "$out" >&2
    return 1
}

ssh_config_fingerprint() {
    cat "$SSHD_CONFIG" "$SSHD_CONFIG_DIR"/*.conf 2>/dev/null | cksum
}

comment_port_lines() {
    local file="$1" tmp rc
    tmp=$(mktemp "${file}.fk.XXXXXX") || return 1
    awk -v pfx="$PORT_COMMENT_PREFIX" '{
            t = $0; sub(/^[ \t]+/, "", t)
            if (tolower(t) ~ /^port([ \t]|=)/) print pfx $0; else print
        }' "$file" > "$tmp" && cat "$tmp" > "$file"
    rc=$?
    rm -f "$tmp"
    return "$rc"
}

# Fija el puerto de sshd en un bloque gestionado al principio de sshd_config
# (nunca dentro de un bloque Match, que es donde acababa el 'Port' que la v1.1
# añadía al final del fichero) y comenta las demás directivas Port.
ssh_write_port() {
    local port="$1" file tmp rc
    if (( DRY_RUN )); then
        dry_log "Se fijaría 'Port $port' en un bloque gestionado al inicio de $SSHD_CONFIG y se comentarían los demás 'Port'."
        return 0
    fi
    [[ -f "$SSHD_CONFIG" ]] || { log_error "No existe $SSHD_CONFIG."; return 1; }

    local -a dropins=()
    mapfile -t dropins < <(ssh_dropin_files)
    for file in ${dropins[@]+"${dropins[@]}"}; do
        if grep -qiE '^[[:space:]]*Port([[:space:]]|=)' "$file"; then
            log_warn "Se comenta la directiva 'Port' en $file."
            comment_port_lines "$file" || return 1
        fi
    done

    tmp=$(mktemp "${SSHD_CONFIG}.fk.XXXXXX") || return 1
    {
        printf '%s\n' "$MANAGED_BEGIN" "# Bloque gestionado por Firewall_Kit (no editar a mano)" "Port $port" "$MANAGED_END"
        awk -v b="$MANAGED_BEGIN" -v e="$MANAGED_END" -v pfx="$PORT_COMMENT_PREFIX" '
            $0 == b { skip = 1; next }
            skip { if ($0 == e) skip = 0; next }
            {
                t = $0; sub(/^[ \t]+/, "", t)
                if (tolower(t) ~ /^port([ \t]|=)/) print pfx $0; else print
            }' "$SSHD_CONFIG"
    } > "$tmp" && cat "$tmp" > "$SSHD_CONFIG"
    rc=$?
    rm -f "$tmp"
    (( rc == 0 )) && audit "sshd: Port $port"
    return "$rc"
}

restart_ssh_service() {
    if (( DRY_RUN )); then
        dry_log "Se reiniciaría el servicio SSH."
        return 0
    fi
    log_info "Reiniciando servicio SSH..."
    local unit
    if have_systemd; then
        if systemctl is-active --quiet ssh.socket 2>/dev/null; then
            # Ubuntu 22.10+ arranca sshd por socket: el puerto lo fija ssh.socket,
            # que se regenera desde sshd_config con daemon-reload.
            log_info "Activación por socket detectada: daemon-reload + restart ssh.socket"
            if systemctl daemon-reload && systemctl restart ssh.socket; then
                audit "SSH reiniciado (ssh.socket)"
                return 0
            fi
        else
            for unit in ssh sshd; do
                if systemctl cat "${unit}.service" >/dev/null 2>&1 && systemctl restart "${unit}.service"; then
                    audit "SSH reiniciado (${unit}.service)"
                    return 0
                fi
            done
        fi
    fi
    if command -v service >/dev/null 2>&1; then
        for unit in ssh sshd; do
            if service "$unit" restart >/dev/null 2>&1; then
                audit "SSH reiniciado (service $unit)"
                return 0
            fi
        done
    fi
    log_error "No se pudo reiniciar el servicio SSH automáticamente. Revísalo manualmente."
    return 1
}

port_listening() {
    local out
    out=$(ss -ltn "( sport = :$1 )" 2>/dev/null) || return 1
    (( $(printf '%s\n' "$out" | grep -c .) > 1 ))
}

# 0 = escucha, 1 = no escucha, 2 = no se puede comprobar (falta ss)
wait_port_listening() {
    local port="$1" i
    command -v ss >/dev/null 2>&1 || return 2
    for (( i = 0; i < 10; i++ )); do
        port_listening "$port" && return 0
        sleep 0.5
    done
    return 1
}

selinux_allow_ssh_port() {
    local port="$1" mode
    command -v getenforce >/dev/null 2>&1 || return 0
    mode=$(getenforce 2>/dev/null)
    [[ "$mode" == "Enforcing" || "$mode" == "Permissive" ]] || return 0
    if ! command -v semanage >/dev/null 2>&1; then
        if [[ "$mode" == "Enforcing" ]]; then
            log_error "SELinux está en modo Enforcing y falta 'semanage' (policycoreutils-python-utils): sshd no podría usar el puerto $port."
            return 1
        fi
        log_warn "SELinux en modo Permissive y sin 'semanage': etiqueta el puerto $port antes de pasar a Enforcing."
        return 0
    fi
    if (( DRY_RUN )); then
        dry_log "semanage port -a -t ssh_port_t -p tcp $port"
        return 0
    fi
    if semanage port -a -t ssh_port_t -p tcp "$port" 2>/dev/null || semanage port -m -t ssh_port_t -p tcp "$port"; then
        log_ok "SELinux: puerto $port etiquetado como ssh_port_t."
        return 0
    fi
    log_error "No se pudo etiquetar el puerto $port para SSH en SELinux."
    return 1
}

# Obtiene la IP del cliente y el puerto de la sesión SSH actual. sudo borra
# SSH_CONNECTION del entorno (env_reset), así que si no está se busca en el
# entorno de los procesos padre.
detect_ssh_session() {
    SESSION_CLIENT_IP=""
    SESSION_SERVER_PORT=""
    local conn="${SSH_CONNECTION:-}" pid="$$" ppid i
    if [[ -z "$conn" && -z "$FK_ROOT" ]]; then
        for (( i = 0; i < 64; i++ )); do
            ppid=$(awk '/^PPid:/ { print $2 }' "/proc/$pid/status" 2>/dev/null)
            if ! [[ "$ppid" =~ ^[0-9]+$ ]] || (( ppid <= 1 )); then
                break
            fi
            pid="$ppid"
            conn=$(tr '\0' '\n' < "/proc/$pid/environ" 2>/dev/null | sed -n 's/^SSH_CONNECTION=//p' | head -n 1)
            [[ -n "$conn" ]] && break
        done
    fi
    [[ -n "$conn" ]] || return 1
    local -a fields=()
    read -r -a fields <<< "$conn"
    SESSION_CLIENT_IP="${fields[0]:-}"
    SESSION_CLIENT_IP="${SESSION_CLIENT_IP#::ffff:}"
    SESSION_SERVER_PORT="${fields[3]:-}"
    return 0
}

warn_if_ssh_session() {
    [[ -n "$SESSION_CLIENT_IP" ]] || return 0
    log_warn "Estás ejecutando esto desde una sesión SSH remota (origen: ${SESSION_CLIENT_IP}, puerto ${SESSION_SERVER_PORT:-?})."
    log_warn "Ten MUCHO cuidado al cambiar reglas o puertos SSH."
}

# ¿Seguirá permitida la sesión SSH actual si SSH se restringe a la red $1?
session_allowed_by_lan() {
    [[ -n "$SESSION_CLIENT_IP" ]] || return 0
    [[ "$1" == "0.0.0.0/0" ]] && return 0
    ipv4_in_cidr "$SESSION_CLIENT_IP" "$1"
}

confirm_lan_lockout() {
    session_allowed_by_lan "$1" && return 0
    log_warn "Tu sesión SSH actual viene de ${SESSION_CLIENT_IP}, que NO pertenece a $1."
    log_warn "Las nuevas conexiones SSH desde esa IP quedarán bloqueadas."
    if (( ASSUME_YES )); then
        log_error "Abortado por seguridad: --yes no confirma operaciones que te dejarían sin acceso."
        return 1
    fi
    ask_yes_no "¿Seguro que quieres continuar? (si/no) [no]:" "no"
}

# -------------------- Reversión automática --------------------
#
# Antes de un cambio arriesgado se crea un backup y, si se trabaja por SSH,
# se arma un proceso independiente de la sesión (servicio transitorio de
# systemd o proceso en segundo plano) que restaura ese backup si el usuario
# no confirma a tiempo. Así, si un cambio corta la conexión, incluso a mitad
# de aplicarse, el servidor vuelve solo al estado anterior.
#
# El fichero del token guarda la ruta del backup (línea 1) y la hora límite
# en segundos desde epoch (línea 2). Confirmar = borrar el token.

guard_write_token() {
    printf '%s\n%s\n' "$1" "$2" > "$RUN_DIR/$GUARD_TOKEN"
}

rollback_guard_start() {
    local backup="$1" timeout token
    GUARD_TOKEN=""
    GUARD_UNIT=""
    timeout=$(effective_rollback_timeout)
    (( DRY_RUN == 0 && timeout > 0 )) || return 0
    [[ -n "$SESSION_CLIENT_IP" && -n "$backup" ]] || return 0
    if (( ASSUME_YES )) || [[ ! -t 0 ]]; then
        log_warn "Modo no interactivo: no se activa la reversión automática."
        return 0
    fi
    mkdir -p "$RUN_DIR" || return 0
    token="rb-$(date +%s)-$$-$RANDOM"
    GUARD_TOKEN="$token"
    # Margen inicial amplio: cubre el tiempo de aplicar los cambios. Se ajusta
    # al pedir la confirmación (rollback_guard_confirm).
    if ! guard_write_token "$backup" "$(( $(date +%s) + timeout + 120 ))"; then
        GUARD_TOKEN=""
        return 0
    fi
    if have_systemd && command -v systemd-run >/dev/null 2>&1 &&
        systemd-run --quiet --collect --unit="firewall-kit-$token" \
            "$BASH" "$SELF" --internal-rollback "$token" >/dev/null 2>&1; then
        GUARD_UNIT="firewall-kit-$token"
    elif command -v setsid >/dev/null 2>&1; then
        setsid nohup "$BASH" "$SELF" --internal-rollback "$token" </dev/null >/dev/null 2>&1 9>&- &
    else
        nohup "$BASH" "$SELF" --internal-rollback "$token" </dev/null >/dev/null 2>&1 9>&- &
        disown 2>/dev/null || true
    fi
    log_info "Reversión automática armada (se desactiva al confirmar los cambios)."
}

rollback_guard_cancel() {
    [[ -n "$GUARD_TOKEN" ]] || return 0
    rm -f "$RUN_DIR/$GUARD_TOKEN"
    if [[ -n "$GUARD_UNIT" ]]; then
        systemctl stop "${GUARD_UNIT}.service" >/dev/null 2>&1 || true
    fi
    GUARD_TOKEN=""
    GUARD_UNIT=""
}

# Pide confirmación; si no llega a tiempo o la respuesta es "no", revierte.
# Devuelve 0 si los cambios se mantienen.
rollback_guard_confirm() {
    [[ -n "$GUARD_TOKEN" ]] || return 0
    local hint="${1:-}" timeout answer="" backup
    timeout=$(effective_rollback_timeout)
    backup=$(head -n 1 "$RUN_DIR/$GUARD_TOKEN" 2>/dev/null)
    # El proceso de reversión esperará hasta que acabe este plazo (+ margen)
    guard_write_token "$backup" "$(( $(date +%s) + timeout + 15 ))" 2>/dev/null || true
    echo
    log_warn "Comprueba AHORA que puedes entrar abriendo una NUEVA sesión SSH${hint:+ (puerto $hint)}."
    log_warn "Si no confirmas en ${timeout}s (o se corta esta sesión), los cambios se revertirán solos."
    if read -r -t "$timeout" -p "¿Mantener los cambios? (si/no): " answer && is_yes "$answer"; then
        rollback_guard_cancel
        log_ok "Cambios confirmados."
        return 0
    fi
    echo
    rollback_guard_cancel
    log_warn "Cambios no confirmados: restaurando el estado anterior..."
    audit "Cambios no confirmados: se restaura $backup"
    if [[ -n "$backup" ]] && restore_backup_file "$backup"; then
        log_ok "Estado anterior restaurado."
    else
        log_error "No se pudo restaurar automáticamente. Backup: ${backup:-desconocido}"
    fi
    return 1
}

# Proceso independiente lanzado por rollback_guard_start: espera a la hora
# límite del token y, si sigue sin confirmarse, restaura el backup.
run_rollback_guard() {
    local token="$1" file deadline now backup
    [[ "$token" =~ ^rb-[0-9]+-[0-9]+-[0-9]+$ ]] || exit 1
    file="$RUN_DIR/$token"
    # Se revisa el token cada poco: la confirmación lo borra y la hora límite
    # se ajusta cuando empieza la cuenta atrás de la confirmación.
    while [[ -f "$file" ]]; do
        deadline=$(sed -n 2p "$file" 2>/dev/null)
        [[ "$deadline" =~ ^[0-9]+$ ]] || deadline=0
        now=$(date +%s)
        (( now >= deadline )) && break
        sleep "$(( deadline - now < 2 ? deadline - now : 2 ))"
    done
    [[ -f "$file" ]] || return 0   # confirmado o ya revertido
    backup=$(head -n 1 "$file")
    rm -f "$file"
    if command -v flock >/dev/null 2>&1 && mkdir -p "$RUN_DIR" && exec 9>"$RUN_DIR/lock"; then
        flock -w 30 9 || true
    fi
    audit "Reversión automática: restaurando $backup (no se confirmó a tiempo)"
    load_config
    restore_backup_file "$backup"
}

# -------------------- Backups --------------------

rotate_backups() {
    (( BACKUP_KEEP > 0 )) || return 0
    local -a files=("$BACKUP_DIR"/firewall_backup_*.tar.gz)
    (( ${#files[@]} > BACKUP_KEEP )) || return 0
    mapfile -t files < <(ls -1t -- "${files[@]}")
    local i
    for (( i = BACKUP_KEEP; i < ${#files[@]}; i++ )); do
        rm -f -- "${files[i]}"
    done
}

# Crea un backup. $1 = sufijo para un nombre automático o nombre completo
# (*.tar.gz). Con $2 = "norotate" no se borran backups antiguos.
# Deja la ruta en LAST_BACKUP.
create_backup() {
    local label="$1" rotate="${2:-rotate}" file base n=1 tmp path
    LAST_BACKUP=""
    if [[ "$label" == *.tar.gz ]]; then
        file="$BACKUP_DIR/$label"
    else
        base="$BACKUP_DIR/firewall_backup_${label}_$(date +%F_%H-%M-%S)"
        file="${base}.tar.gz"
        while [[ -e "$file" ]]; do
            file="${base}_${n}.tar.gz"
            n=$((n + 1))
        done
    fi

    local -a paths=()
    for path in "${BACKUP_PATHS[@]}"; do
        [[ -e "${FK_ROOT}/${path}" ]] && paths+=("$path")
    done
    if (( ${#paths[@]} == 0 )); then
        log_error "No hay ficheros de configuración que respaldar."
        return 1
    fi

    if (( DRY_RUN )); then
        dry_log "Se crearía el backup $file (${paths[*]})."
        LAST_BACKUP="$file"
        return 0
    fi

    if ! { mkdir -p "$BACKUP_DIR" && chmod 700 "$BACKUP_DIR"; }; then
        log_error "No se pudo crear $BACKUP_DIR."
        return 1
    fi
    tmp="${file}.partial"
    # Se escribe en un fichero temporal: un fallo nunca deja un backup a medias
    if tar -C "${FK_ROOT:-/}" -czf "$tmp" "${paths[@]}" && mv -f "$tmp" "$file"; then
        log_ok "Backup creado: $file"
        LAST_BACKUP="$file"
        [[ "$rotate" == "rotate" ]] && rotate_backups
        return 0
    fi
    rm -f "$tmp"
    log_error "Error al crear el backup $file."
    return 1
}

load_backups() {
    BACKUPS=()
    local -a files=("$BACKUP_DIR"/*.tar.gz)
    (( ${#files[@]} > 0 )) || return 0
    mapfile -t BACKUPS < <(ls -1t -- "${files[@]}")
}

print_backups() {
    load_backups
    if (( ${#BACKUPS[@]} == 0 )); then
        echo "  (no hay backups en $BACKUP_DIR)"
        return 0
    fi
    local i ts
    for (( i = 0; i < ${#BACKUPS[@]}; i++ )); do
        ts=$(date -r "${BACKUPS[i]}" "+%F %T" 2>/dev/null || echo "desconocida")
        printf '  [%2d] %s   (%s)\n' "$((i + 1))" "$(basename "${BACKUPS[i]}")" "$ts"
    done
}

# Solo se aceptan backups con las rutas esperadas: evita que un .tar.gz
# manipulado escriba en cualquier parte del sistema al extraerse en /.
validate_archive() {
    local file="$1" listing name
    if ! listing=$(tar -tzf "$file" 2>/dev/null) || [[ -z "$listing" ]]; then
        log_error "No es un backup .tar.gz válido: $file"
        return 1
    fi
    while IFS= read -r name; do
        name="${name#./}"
        case "/${name}/" in
            */../*)
                log_error "Ruta no permitida en el backup: $name"
                return 1
                ;;
        esac
        case "$name" in
            etc/|etc/ssh/|etc/ufw|etc/ufw/|etc/ufw/*|etc/ssh/sshd_config|etc/ssh/sshd_config.d|etc/ssh/sshd_config.d/|etc/ssh/sshd_config.d/*|etc/firewall-manager.conf) ;;
            *)
                log_error "Ruta no permitida en el backup: $name"
                return 1
                ;;
        esac
    done <<< "$listing"
    if tar -tvzf "$file" 2>/dev/null | cut -c1 | grep -q '[lhbcp]'; then
        log_error "El backup contiene enlaces o ficheros especiales: no se restaura."
        return 1
    fi
    return 0
}

# Extrae un backup y aplica el estado: recarga ufw y, si cambió la
# configuración de sshd, la valida y reinicia SSH.
restore_backup_file() {
    local file="$1" before after ssh_changed=0
    validate_archive "$file" || return 1
    before=$(ssh_config_fingerprint)
    if ! tar -xzf "$file" -C "${FK_ROOT:-/}" --no-overwrite-dir; then
        log_error "Error al extraer $file."
        return 1
    fi
    log_ok "Ficheros restaurados desde $(basename "$file")."
    after=$(ssh_config_fingerprint)
    [[ "$before" != "$after" ]] && ssh_changed=1
    if (( ssh_changed )) && find_sshd >/dev/null; then
        sshd_test || return 1
    fi
    ufw_apply_state || log_warn "No se pudo recargar ufw."
    if (( ssh_changed )) && find_sshd >/dev/null; then
        restart_ssh_service || log_warn "Reinicia SSH manualmente para aplicar su configuración."
    fi
    load_config
    audit "Restaurado el backup $file"
    return 0
}

# -------------------- Acciones --------------------

check_conflicts() {
    if have_systemd && systemctl is-active --quiet firewalld 2>/dev/null; then
        log_warn "firewalld está activo: usarlo junto a ufw provoca reglas en conflicto."
        log_warn "Desactívalo antes (systemctl disable --now firewalld) o gestiona el firewall solo con firewalld."
        ask_yes_no "¿Continuar de todos modos? (si/no) [no]:" "no" || return 1
    fi
    if command -v docker >/dev/null 2>&1; then
        log_warn "Docker detectado: los puertos publicados por contenedores (-p) no pasan por las reglas de ufw."
    fi
    return 0
}

restore_after_failure() {
    rollback_guard_cancel
    log_error "Se produjo un error: restaurando el estado anterior..."
    (( DRY_RUN )) && return 0
    if [[ -n "$1" ]] && restore_backup_file "$1"; then
        log_ok "Estado anterior restaurado."
    else
        log_error "No se pudo restaurar automáticamente. Backup: ${1:-ninguno}"
    fi
}

init_firewall() {
    log_header "Inicialización del firewall"
    ensure_ufw || return 1
    warn_if_ssh_session
    check_conflicts || { log_info "Operación cancelada."; return 1; }

    # Puertos SSH a permitir: el configurado, los que usa sshd y el de la
    # sesión actual, para no cortar el acceso aunque la config esté desfasada.
    local -a ports=("$SSH_PORT") detected=()
    local port backup
    mapfile -t detected < <(detect_ssh_ports)
    for port in ${detected[@]+"${detected[@]}"}; do
        in_list "$port" "${ports[@]}" || ports+=("$port")
    done
    if [[ -n "$SESSION_SERVER_PORT" ]] && valid_port "$SESSION_SERVER_PORT" && ! in_list "$SESSION_SERVER_PORT" "${ports[@]}"; then
        log_warn "Tu sesión actual entra por el puerto $SESSION_SERVER_PORT: también se permitirá."
        ports+=("$SESSION_SERVER_PORT")
    fi
    confirm_lan_lockout "$LAN_NET" || { log_info "Operación cancelada."; return 1; }

    echo "Nueva política: entrante DENEGADO, saliente PERMITIDO."
    echo "SSH permitido en el puerto ${ports[*]} desde ${LAN_NET} ($([[ "$SSH_LIMIT" == "si" ]] && echo "con" || echo "sin") limitación de intentos)."
    load_rules
    if (( ${#RULES[@]} > 0 )); then
        log_warn "Se borrarán las ${#RULES[@]} reglas actuales:"
        print_rules
    fi
    if ! ask_yes_no "¿Seguro que quieres reinicializar ufw? (si/no) [no]:" "no"; then
        log_info "Operación cancelada."
        return 1
    fi

    create_backup "pre_init" || { log_error "Sin backup no se continúa."; return 1; }
    backup="$LAST_BACKUP"
    rollback_guard_start "$backup"

    # Cada paso se comprueba: en la v1.1 el firewall se activaba aunque la
    # regla SSH hubiera fallado, dejando el servidor inaccesible.
    if ! { ufw_run --force reset && ufw_run default deny incoming && ufw_run default allow outgoing; }; then
        restore_after_failure "$backup"
        return 1
    fi
    for port in "${ports[@]}"; do
        if ! ssh_rule_add "$port"; then
            restore_after_failure "$backup"
            return 1
        fi
    done
    if ! ufw_run --force enable; then
        restore_after_failure "$backup"
        return 1
    fi

    if (( DRY_RUN )); then
        dry_log "No se ha aplicado ningún cambio."
        return 0
    fi
    echo
    log_ok "Firewall inicializado."
    ufw status verbose
    rollback_guard_confirm "${ports[*]}"
}

listar_reglas() {
    log_header "Reglas de ufw"
    require_ufw || return 1
    echo "Estado: $(ufw_state_text)"
    echo
    print_rules
}

anadir_regla() {
    local target="${1:-}" src="${2-}" action="${3:-}" comment="${4-}" interactive=0
    log_header "Añadir regla"
    ensure_ufw || return 1

    if [[ -z "$target" ]]; then
        interactive=1
        read_input target "Puerto o rango (ej: 80, 443/tcp, 6000:6007):"
    fi
    if ! parse_rule_target "$target"; then
        log_error "Puerto o rango no válido: '$target' (1-65535, rango INICIO:FIN, protocolo tcp/udp)."
        return 1
    fi
    if [[ -z "$RULE_PROTO" ]]; then
        if (( interactive )); then
            read_input RULE_PROTO "Protocolo (tcp/udp/both) [tcp]:"
            RULE_PROTO="${RULE_PROTO:-tcp}"
        else
            RULE_PROTO="both"
        fi
    fi
    case "$RULE_PROTO" in
        tcp|udp|both) ;;
        *) log_error "Protocolo no válido: '$RULE_PROTO'."; return 1 ;;
    esac
    if (( interactive )); then
        read_input action "Acción (allow/limit/deny/reject) [allow]:"
        read_input src "Origen IP/CIDR (IPv4 o IPv6), vacío = cualquiera:"
        read_input comment "Comentario (opcional):"
    fi
    action="${action:-allow}"
    case "$action" in
        allow|limit|deny|reject) ;;
        *) log_error "Acción no válida: '$action' (allow, limit, deny o reject)."; return 1 ;;
    esac
    local src_addr
    if ! src_addr=$(normalize_source "$src"); then
        log_error "Origen no válido: '$src' (IPv4, IPv6 o CIDR; ufw no admite nombres de host)."
        return 1
    fi
    if ! valid_comment "$comment"; then
        log_error "Comentario no válido: máximo 64 caracteres, sin comillas ni barras invertidas."
        return 1
    fi
    if [[ "$action" == "deny" || "$action" == "reject" ]] && [[ "$PORT_SPEC" == "$SSH_PORT" ]]; then
        log_warn "Vas a bloquear el puerto SSH ($SSH_PORT)."
        if (( ASSUME_YES )); then
            log_error "Abortado por seguridad: --yes no confirma operaciones que te dejarían sin acceso."
            return 1
        fi
        ask_yes_no "¿Seguro? (si/no) [no]:" "no" || return 1
    fi

    # ufw exige protocolo en los rangos: "both" se divide en tcp y udp
    local -a protos=() args=()
    local proto rc=0
    if [[ "$RULE_PROTO" == "both" && "$PORT_SPEC" == *:* ]]; then
        protos=(tcp udp)
    else
        protos=("$RULE_PROTO")
    fi
    for proto in "${protos[@]}"; do
        args=("$action")
        if [[ "$src_addr" == "any" ]]; then
            if [[ "$proto" == "both" ]]; then args+=("$PORT_SPEC"); else args+=("${PORT_SPEC}/${proto}"); fi
        else
            args+=(from "$src_addr" to any port "$PORT_SPEC")
            [[ "$proto" == "both" ]] || args+=(proto "$proto")
        fi
        [[ -n "$comment" ]] && args+=(comment "$comment")
        ufw_run "${args[@]}" || rc=1
    done
    if (( rc == 0 )); then
        log_ok "Regla añadida."
    else
        log_error "No se pudo añadir la regla."
    fi
    return "$rc"
}

eliminar_regla() {
    local num="${1:-}" spec port backup ssh_related=0
    log_header "Eliminar regla"
    require_ufw || return 1
    load_rules
    if (( ${#RULES[@]} == 0 )); then
        log_warn "No hay reglas de usuario."
        return 1
    fi
    print_rules
    echo
    [[ -n "$num" ]] || read_input num "Número de regla a eliminar:"
    if ! [[ "$num" =~ ^[0-9]{1,4}$ ]] || (( 10#$num < 1 || 10#$num > ${#RULES[@]} )); then
        log_error "Número de regla no válido."
        return 1
    fi
    spec="${RULES[10#$num - 1]}"
    echo "Regla seleccionada: ufw $spec"

    local -a ssh_ports=("$SSH_PORT") detected=()
    mapfile -t detected < <(detect_ssh_ports)
    for port in ${detected[@]+"${detected[@]}"} ${SESSION_SERVER_PORT:+"$SESSION_SERVER_PORT"}; do
        in_list "$port" "${ssh_ports[@]}" || ssh_ports+=("$port")
    done
    for port in "${ssh_ports[@]}"; do
        is_ssh_rule "$spec" "$port" || continue
        ssh_related=1
        if ! ssh_rules_matching "$port" all | grep -qvxF -- "$spec"; then
            log_warn "Es la ÚLTIMA regla que permite SSH en el puerto $port: podrías quedarte sin acceso."
            if (( ASSUME_YES )); then
                log_error "Abortado por seguridad: --yes no confirma operaciones que te dejarían sin acceso."
                return 1
            fi
        fi
    done

    ask_yes_no "¿Eliminar esta regla? (si/no) [no]:" "no" || { log_info "Operación cancelada."; return 1; }
    create_backup "pre_delete" || return 1
    backup="$LAST_BACKUP"
    (( ssh_related )) && rollback_guard_start "$backup"
    if ! delete_rule_spec "$spec"; then
        rollback_guard_cancel
        return 1
    fi
    log_ok "Regla eliminada."
    rollback_guard_confirm || return 1
    return 0
}

cleanup_ssh_rules_for_ports() {
    (( $# > 0 )) || return 0
    local -a specs=()
    local port rule
    for port in "$@"; do
        while IFS= read -r rule; do
            [[ -n "$rule" ]] && specs+=("$rule")
        done < <(ssh_rules_matching "$port" all)
    done
    (( ${#specs[@]} > 0 )) || return 0
    echo
    log_info "Reglas ufw de los puertos SSH que ya no se usan ($*):"
    printf '    ufw %s\n' "${specs[@]}"
    if ! ask_yes_no "¿Eliminarlas ahora? (si/no) [si]:" "si"; then
        log_info "Se mantienen. Puedes borrarlas desde 'Eliminar regla'."
        return 0
    fi
    for rule in "${specs[@]}"; do
        delete_rule_spec "$rule" || log_warn "No se pudo eliminar: ufw $rule"
    done
    return 0
}

ssh_port_change_failed() {
    restore_after_failure "$1"
    return 1
}

cambiar_puerto_ssh() {
    local new_port="${1:-}" old_port="$SSH_PORT" backup port
    log_header "Cambiar puerto SSH"
    ensure_ufw || return 1
    if ! find_sshd >/dev/null; then
        log_error "No se encontró sshd (¿está instalado openssh-server?)."
        return 1
    fi
    warn_if_ssh_session

    local -a current=()
    mapfile -t current < <(detect_ssh_ports)
    echo "Puerto SSH configurado: $SSH_PORT   (sshd: ${current[*]:-desconocido})"
    [[ -n "$new_port" ]] || read_input new_port "Introduce el NUEVO puerto SSH (ej: 2222):"
    if ! valid_port "$new_port"; then
        log_error "Puerto no válido: '$new_port' (1-65535)."
        return 1
    fi
    new_port=$(norm_port "$new_port")
    if [[ "$new_port" == "$old_port" ]] && (( ${#current[@]} <= 1 )); then
        log_info "SSH ya usa el puerto $new_port."
        return 0
    fi
    if ! in_list "$new_port" ${current[@]+"${current[@]}"} && port_listening "$new_port"; then
        log_error "El puerto $new_port ya está en uso por otro servicio."
        return 1
    fi

    echo
    log_warn "Cambiar el puerto SSH puede dejarte sin acceso remoto si algo sale mal."
    echo "Pasos: abrir $new_port en ufw → cambiar sshd_config → validar (sshd -t) → reiniciar SSH → verificar que escucha."
    echo "Si algo falla en cualquier paso, se restaura el estado anterior."
    ask_yes_no "¿Continuar? (si/no) [no]:" "no" || { log_info "Operación cancelada."; return 1; }

    create_backup "pre_ssh_port" || return 1
    backup="$LAST_BACKUP"
    rollback_guard_start "$backup"

    # La regla del nuevo puerto respeta la LAN configurada (la v1.1 lo abría a todo Internet)
    ssh_rule_add "$new_port" || { ssh_port_change_failed "$backup"; return 1; }
    selinux_allow_ssh_port "$new_port" || { ssh_port_change_failed "$backup"; return 1; }
    ssh_write_port "$new_port" || { ssh_port_change_failed "$backup"; return 1; }
    if (( ! DRY_RUN )); then
        sshd_test || { ssh_port_change_failed "$backup"; return 1; }
    fi
    restart_ssh_service || { ssh_port_change_failed "$backup"; return 1; }
    if (( ! DRY_RUN )); then
        wait_port_listening "$new_port"
        case $? in
            0) log_ok "sshd escucha en el puerto $new_port." ;;
            2) log_warn "No se pudo verificar que sshd escuche en $new_port (falta 'ss')." ;;
            *)
                log_error "sshd no escucha en el puerto $new_port tras el reinicio."
                ssh_port_change_failed "$backup"
                return 1
                ;;
        esac
        SSH_PORT="$new_port"
        save_config
    fi
    log_ok "Puerto SSH: $new_port (anterior: $old_port)."
    rollback_guard_confirm "$new_port" || return 1

    # Reglas de los puertos que sshd ya no usa
    local -a now=() stale=()
    if (( DRY_RUN )); then
        now=("$new_port")
    else
        mapfile -t now < <(detect_ssh_ports)
    fi
    for port in "$old_port" ${current[@]+"${current[@]}"}; do
        in_list "$port" ${now[@]+"${now[@]}"} ${stale[@]+"${stale[@]}"} || stale+=("$port")
    done
    cleanup_ssh_rules_for_ports ${stale[@]+"${stale[@]}"}
    return 0
}

# Muestra y aplica la política SSH actual, guardando la configuración.
# $1 = valores anteriores de LAN_NET y SSH_LIMIT ("lan|limit") para deshacer.
apply_ssh_policy_interactive() {
    local previous="$1" rule backup
    local -a obsolete=()
    ssh_rule_args "$SSH_PORT"
    mapfile -t obsolete < <(ssh_rules_matching "$SSH_PORT" undesired)
    echo "Se aplicará:  ufw ${SSH_RULE_ARGS[*]}"
    if (( ${#obsolete[@]} > 0 )); then
        echo "Y se sustituirán o eliminarán estas reglas SSH del puerto $SSH_PORT:"
        for rule in "${obsolete[@]}"; do
            echo "    ufw $rule"
        done
    fi
    if ! ask_yes_no "¿Aplicar? (si/no) [no]:" "no" || ! create_backup "pre_ssh_policy"; then
        LAN_NET="${previous%%|*}"
        SSH_LIMIT="${previous##*|}"
        log_info "Operación cancelada."
        return 1
    fi
    backup="$LAST_BACKUP"
    rollback_guard_start "$backup"
    if ! apply_ssh_policy; then
        LAN_NET="${previous%%|*}"
        SSH_LIMIT="${previous##*|}"
        restore_after_failure "$backup"
        return 1
    fi
    save_config
    rollback_guard_confirm || return 1
    return 0
}

cambiar_lan_permitida() {
    local input="${1:-}" new_lan old_lan="$LAN_NET"
    log_header "Cambiar LAN permitida para SSH"
    ensure_ufw || return 1
    echo "LAN actual permitida para SSH: $LAN_NET"
    [[ -n "$input" ]] || read_input input "Nueva LAN en formato CIDR (ej: 192.168.1.0/24) o 'any' para todas:"
    if ! new_lan=$(normalize_ipv4_cidr "$input"); then
        log_error "Formato CIDR IPv4 no válido: '$input'."
        return 1
    fi
    if [[ "$new_lan" != "$input" && "$input" != "any" ]]; then
        log_info "Red normalizada: $new_lan"
    fi
    if [[ "$new_lan" == "0.0.0.0/0" ]]; then
        log_warn "Vas a permitir SSH desde TODAS las IPs."
    else
        log_info "Solo se permitirá SSH por IPv4 desde $new_lan; las reglas SSH abiertas a todos (también IPv6) se eliminarán."
    fi
    confirm_lan_lockout "$new_lan" || { log_info "Operación cancelada."; return 1; }

    LAN_NET="$new_lan"
    apply_ssh_policy_interactive "${old_lan}|${SSH_LIMIT}" || return 1
    # En la v1.1 este mensaje mostraba la LAN nueva también como "antes"
    log_ok "LAN permitida para SSH: $new_lan (antes: $old_lan)."
}

cambiar_limite_ssh() {
    local value="${1:-}" old="$SSH_LIMIT"
    log_header "Limitación de intentos SSH (ufw limit)"
    ensure_ufw || return 1
    if [[ -z "$value" ]]; then
        if [[ "$SSH_LIMIT" == "si" ]]; then value="no"; else value="si"; fi
    fi
    case "$value" in
        si|no) ;;
        *) log_error "Valor no válido: '$value' (si/no)."; return 1 ;;
    esac
    echo "'ufw limit' bloquea temporalmente una IP que abre 6 o más conexiones en 30 segundos."
    echo "Estado actual: $old  →  nuevo: $value"
    SSH_LIMIT="$value"
    apply_ssh_policy_interactive "${LAN_NET}|${old}" || return 1
    log_ok "Limitación de intentos SSH: $value."
}

ver_estado_reglas() {
    log_header "Estado del firewall"
    require_ufw || return 1
    ufw status verbose
    echo
    echo "Firewall_Kit: puerto SSH $SSH_PORT, LAN $LAN_NET, limitación SSH: $SSH_LIMIT"
}

backup_auto() {
    log_header "Backup automático"
    create_backup "auto"
}

backup_manual() {
    local name="${1:-}" file
    log_header "Backup manual"
    [[ -n "$name" ]] || read_input name "Nombre del backup (letras, números, . _ -):"
    name="${name%.tar.gz}"
    # Sin '/' ni '..': en la v1.1 un nombre como ../../x escribía fuera del directorio
    if ! [[ "$name" =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,99}$ ]] || [[ "$name" == *..* ]]; then
        log_error "Nombre no válido: usa letras, números, punto, guion y guion bajo."
        return 1
    fi
    if [[ "$name" == firewall_backup_* ]]; then
        log_error "El prefijo 'firewall_backup_' está reservado para los backups automáticos."
        return 1
    fi
    file="$BACKUP_DIR/${name}.tar.gz"
    if [[ -e "$file" ]] && ! ask_yes_no "Ya existe $file. ¿Sobrescribirlo? (si/no) [no]:" "no"; then
        log_info "Operación cancelada."
        return 1
    fi
    create_backup "${name}.tar.gz"
}

listar_backups() {
    log_header "Backups disponibles"
    print_backups
}

restaurar_backup() {
    local chosen="${1:-}" sel safety
    log_header "Restaurar configuración desde backup"
    if [[ -z "$chosen" ]]; then
        load_backups
        if (( ${#BACKUPS[@]} == 0 )); then
            log_warn "No se encontraron backups en $BACKUP_DIR."
            return 1
        fi
        print_backups
        echo
        read_input sel "Selecciona el número de backup a restaurar:"
        if ! [[ "$sel" =~ ^[0-9]{1,4}$ ]] || (( 10#$sel < 1 || 10#$sel > ${#BACKUPS[@]} )); then
            log_error "Selección no válida."
            return 1
        fi
        chosen="${BACKUPS[10#$sel - 1]}"
    elif [[ "$chosen" != */* && -f "$BACKUP_DIR/$chosen" ]]; then
        chosen="$BACKUP_DIR/$chosen"
    fi
    if [[ ! -f "$chosen" ]]; then
        log_error "No existe el backup: $chosen"
        return 1
    fi
    validate_archive "$chosen" || return 1

    echo "Contenido del backup:"
    tar -tzf "$chosen" | sed 's/^/    /' | head -n 20
    log_warn "Se sobrescribirán esos ficheros en el sistema."
    if ! ask_yes_no "¿Seguro que quieres restaurar '$(basename "$chosen")'? (si/no) [no]:" "no"; then
        log_info "Operación cancelada."
        return 1
    fi
    if (( DRY_RUN )); then
        dry_log "Se restauraría $chosen, se recargaría ufw y se reiniciaría SSH si cambia su configuración."
        return 0
    fi

    # Backup de seguridad del estado actual (sin rotar, para no borrar el elegido)
    if ! create_backup "pre_restore" norotate; then
        log_error "No se pudo crear el backup de seguridad: restauración cancelada."
        return 1
    fi
    safety="$LAST_BACKUP"
    rollback_guard_start "$safety"
    if ! restore_backup_file "$chosen"; then
        rollback_guard_cancel
        log_error "La restauración falló: volviendo al estado anterior..."
        restore_backup_file "$safety" || log_error "No se pudo volver al estado anterior. Backup de seguridad: $safety"
        return 1
    fi
    log_ok "Restauración completada."
    rotate_backups
    rollback_guard_confirm || return 1
    return 0
}

# -------------------- Menú principal --------------------

print_summary() {
    local ports
    ports=$(detect_ssh_ports | tr '\n' ' ')
    ports="${ports% }"
    echo "Versión script:     $VERSION"
    echo "Estado ufw:         $(ufw_state_text)"
    echo "Puerto SSH:         ${SSH_PORT}${ports:+   (sshd escucha en: $ports)}"
    echo "LAN SSH permitida:  ${LAN_NET}$([[ "$LAN_NET" == "0.0.0.0/0" ]] && echo " (todas)")"
    echo "Límite SSH (limit): $SSH_LIMIT"
    echo "Backups en:         $BACKUP_DIR"
    echo "Modo DRY-RUN:       $( (( DRY_RUN )) && echo "ACTIVADO" || echo "desactivado")"
    if [[ -n "$SESSION_CLIENT_IP" ]]; then
        echo "Sesión actual:      SSH desde ${SESSION_CLIENT_IP} (puerto ${SESSION_SERVER_PORT:-?})"
    fi
}

menu_principal() {
    IN_MENU=1
    local opcion
    while true; do
        [[ -t 1 ]] && clear
        printf '%s===============================%s\n' "$C_BOLD" "$C_RESET"
        printf '%s   Firewall_Kit (ufw)%s\n' "$C_BOLD" "$C_RESET"
        printf '%s===============================%s\n' "$C_BOLD" "$C_RESET"
        load_config
        print_summary
        echo "-------------------------------"
        echo "1) Inicializar firewall"
        echo "2) Listar reglas"
        echo "3) Añadir regla"
        echo "4) Eliminar regla"
        echo "5) Cambiar puerto SSH"
        echo "6) Cambiar LAN permitida (SSH)"
        echo "7) Ver estado detallado"
        echo "8) Backup automático"
        echo "9) Restaurar configuración desde backup"
        echo "10) Backup manual (con nombre)"
        echo "11) Alternar modo DRY-RUN"
        echo "12) Alternar limitación de intentos SSH (ufw limit)"
        echo "0) Salir"
        echo "-------------------------------"
        read_input opcion "Elige una opción:"

        case "$opcion" in
            1) init_firewall ;;
            2) listar_reglas ;;
            3) anadir_regla ;;
            4) eliminar_regla ;;
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
                ;;
            12) cambiar_limite_ssh ;;
            0)
                echo
                log_info "Saliendo..."
                exit 0
                ;;
            *) log_warn "Opción no válida." ;;
        esac
        pause
    done
}

# -------------------- Main --------------------

set_action() {
    if [[ -n "$ACTION" && "$ACTION" != "$1" ]]; then
        usage_error "Solo se puede indicar una acción por ejecución."
    fi
    ACTION="$1"
}

parse_args() {
    local add_opts=0
    while (( $# > 0 )); do
        case "$1" in
            --dry-run) DRY_RUN=1 ;;
            -y|--yes) ASSUME_YES=1 ;;
            --no-color) USE_COLOR=0 ;;
            --rollback-timeout)
                (( $# >= 2 )) || usage_error "Falta el valor de $1."
                [[ "$2" =~ ^[0-9]{1,4}$ ]] || usage_error "Valor no válido para $1: '$2'."
                CLI_ROLLBACK_TIMEOUT=$((10#$2))
                shift
                ;;
            -h|--help) set_action help ;;
            -V|--version) set_action version ;;
            --init) set_action init ;;
            --status) set_action status ;;
            --list) set_action list ;;
            --list-backups) set_action list-backups ;;
            --add|--delete|--ssh-port|--lan|--ssh-limit)
                (( $# >= 2 )) || usage_error "Falta el valor de $1."
                set_action "${1#--}"
                ACTION_ARG="$2"
                shift
                ;;
            --from|--action|--comment)
                (( $# >= 2 )) || usage_error "Falta el valor de $1."
                case "$1" in
                    --from) ADD_FROM="$2" ;;
                    --action) ADD_ACTION="$2" ;;
                    --comment) ADD_COMMENT="$2" ;;
                esac
                add_opts=1
                shift
                ;;
            --backup|--restore)
                set_action "${1#--}"
                if (( $# >= 2 )) && [[ "$2" != -* ]]; then
                    ACTION_ARG="$2"
                    shift
                fi
                ;;
            --internal-rollback)
                (( $# >= 2 )) || exit 1
                set_action internal-rollback
                ACTION_ARG="$2"
                shift
                ;;
            *) usage_error "Opción no reconocida: $1" ;;
        esac
        shift
    done
    if (( add_opts )) && [[ "$ACTION" != "add" ]]; then
        usage_error "--from, --action y --comment solo se usan junto con --add."
    fi
}

main() {
    parse_args "$@"
    setup_colors

    case "$ACTION" in
        help) print_help; exit 0 ;;
        version) echo "Firewall_Kit v${VERSION}"; exit 0 ;;
    esac

    check_root
    if [[ "$ACTION" == "internal-rollback" ]]; then
        run_rollback_guard "$ACTION_ARG"
        exit $?
    fi
    acquire_lock
    detect_ssh_session || true
    load_config

    local rc=0
    case "$ACTION" in
        "") menu_principal ;;
        init) init_firewall; rc=$? ;;
        status) ver_estado_reglas; rc=$? ;;
        list) listar_reglas; rc=$? ;;
        list-backups) listar_backups; rc=$? ;;
        add) anadir_regla "$ACTION_ARG" "$ADD_FROM" "$ADD_ACTION" "$ADD_COMMENT"; rc=$? ;;
        delete) eliminar_regla "$ACTION_ARG"; rc=$? ;;
        ssh-port) cambiar_puerto_ssh "$ACTION_ARG"; rc=$? ;;
        lan) cambiar_lan_permitida "$ACTION_ARG"; rc=$? ;;
        ssh-limit) cambiar_limite_ssh "$ACTION_ARG"; rc=$? ;;
        backup)
            if [[ -n "$ACTION_ARG" ]]; then backup_manual "$ACTION_ARG"; else backup_auto; fi
            rc=$?
            ;;
        restore) restaurar_backup "$ACTION_ARG"; rc=$? ;;
    esac
    exit "$rc"
}

# Permite cargar las funciones desde los tests sin ejecutar main
if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    main "$@"
fi
