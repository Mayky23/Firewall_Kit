# Utilidades comunes de los tests (bats).
#
# Cada test trabaja sobre un árbol de ficheros temporal (FK_ROOT) y usa las
# versiones falsas de ufw, sshd, systemctl y ss de tests/fake-bin, así que
# nunca toca el firewall ni la configuración SSH reales.

REPO_ROOT="$(cd "${BATS_TEST_DIRNAME}/.." && pwd)"
SCRIPT="${REPO_ROOT}/firewall.sh"

setup_env() {
    export FK_ROOT="${BATS_TEST_TMPDIR}/root"
    mkdir -p "$FK_ROOT/etc/ssh/sshd_config.d" "$FK_ROOT/etc/ufw" "$FK_ROOT/run/systemd/system"
    cat > "$FK_ROOT/etc/ssh/sshd_config" <<'EOF'
Include /etc/ssh/sshd_config.d/*.conf
#Port 22
PermitRootLogin no
Match User backup
    ForceCommand internal-sftp
EOF
    echo "ENABLED=no" > "$FK_ROOT/etc/ufw/ufw.conf"
    : > "$FK_ROOT/etc/ufw/user.rules"
    echo 22 > "$FK_ROOT/listening"
    export PATH="${REPO_ROOT}/tests/fake-bin:${PATH}"
    unset SSH_CONNECTION NO_COLOR FAKE_UFW_FAIL_ON FAKE_SSHD_T_FAIL FAKE_NO_LISTEN FAKE_SSH_SOCKET
}

# Ejecuta el script completo
fk() {
    bash "$SCRIPT" "$@"
}

# Carga las funciones del script sin ejecutar main
load_functions() {
    # shellcheck source=../firewall.sh
    source "$SCRIPT"
    set +u
}

rules() {
    bash "$SCRIPT" --list | sed -n 's/^  \[ *[0-9]*\] ufw //p'
}

config_value() {
    sed -n "s/^$1=//p" "$FK_ROOT/etc/firewall-manager.conf" | tr -d '"'
}

backup_count() {
    local files=("$FK_ROOT"/var/backups/firewall-manager/*.tar.gz)
    echo "${#files[@]}"
}

# Crea un .tar.gz con miembros arbitrarios (para probar backups manipulados)
make_archive() {
    local out="$1"
    shift
    python3 - "$out" "$@" <<'EOF'
import io, sys, tarfile
out, specs = sys.argv[1], sys.argv[2:]
with tarfile.open(out, "w:gz") as tar:
    for spec in specs:
        if "->" in spec:
            name, target = spec.split("->", 1)
            info = tarfile.TarInfo(name)
            info.type = tarfile.SYMTYPE
            info.linkname = target
            tar.addfile(info)
        else:
            data = b"contenido\n"
            info = tarfile.TarInfo(spec)
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
EOF
}
