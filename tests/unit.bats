#!/usr/bin/env bats
# Tests de las funciones internas de firewall.sh

load test_helper

setup() {
    setup_env
    load_functions
}

@test "valid_port: rango 1-65535 en base 10" {
    valid_port 1
    valid_port 22
    valid_port 65535
    valid_port 08080
    [ "$(norm_port 08080)" = "8080" ]
    for bad in 0 65536 070000 099999 abc "" "22 " -1 123456; do
        run valid_port "$bad"
        [ "$status" -ne 0 ]
    done
}

@test "parse_port_spec y parse_rule_target" {
    parse_port_spec 6000:6007
    [ "$PORT_SPEC" = "6000:6007" ]
    parse_rule_target 0443/tcp
    [ "$PORT_SPEC" = "443" ]
    [ "$RULE_PROTO" = "tcp" ]
    parse_rule_target 53
    [ "$PORT_SPEC" = "53" ]
    [ -z "$RULE_PROTO" ]
    for bad in 7000:6000 1:70000 443/icmp 80/ ":80" "80:"; do
        run parse_rule_target "$bad"
        [ "$status" -ne 0 ]
    done
}

@test "normalize_ipv4_cidr normaliza y rechaza formatos incorrectos" {
    [ "$(normalize_ipv4_cidr 10.1.2.3/16)" = "10.1.0.0/16" ]
    [ "$(normalize_ipv4_cidr any)" = "0.0.0.0/0" ]
    [ "$(normalize_ipv4_cidr 0.0.0.0/0)" = "0.0.0.0/0" ]
    [ "$(normalize_ipv4_cidr 192.168.1.5)" = "192.168.1.5/32" ]
    [ "$(normalize_ipv4_cidr 08.1.1.1/24)" = "8.1.1.0/24" ]
    for bad in 1.2.3.4/ 1.2.3.4/33 256.1.1.1 1.2.3 1.2.3.4/24/5 "" abc 1.2.3.4.5; do
        run normalize_ipv4_cidr "$bad"
        [ "$status" -ne 0 ]
    done
}

@test "ipv4_in_cidr" {
    ipv4_in_cidr 192.168.1.40 192.168.1.0/24
    ipv4_in_cidr 8.8.8.8 0.0.0.0/0
    ipv4_in_cidr 10.0.0.5 10.0.0.5/32
    run ipv4_in_cidr 192.168.2.1 192.168.1.0/24
    [ "$status" -ne 0 ]
    run ipv4_in_cidr 2001:db8::1 192.168.1.0/24
    [ "$status" -ne 0 ]
}

@test "valid_ipv6" {
    valid_ipv6 2001:db8::/32
    valid_ipv6 ::1
    valid_ipv6 ::
    valid_ipv6 fe80::1
    valid_ipv6 1:2:3:4:5:6:7:8
    for bad in 1:2:3:4:5:6:7:8:9 1::2::3 2001:db8::/129 :1:: 12345:: g::1 1:2:3 1.2.3.4; do
        run valid_ipv6 "$bad"
        [ "$status" -ne 0 ]
    done
}

@test "normalize_source" {
    [ "$(normalize_source "")" = "any" ]
    [ "$(normalize_source any)" = "any" ]
    [ "$(normalize_source 10.0.0.5/32)" = "10.0.0.5" ]
    [ "$(normalize_source 10.1.2.3/16)" = "10.1.0.0/16" ]
    [ "$(normalize_source 2001:db8::/32)" = "2001:db8::/32" ]
    run normalize_source bad-host
    [ "$status" -ne 0 ]
}

@test "valid_comment rechaza comillas, barras invertidas y textos largos" {
    valid_comment "Acceso web ñ"
    valid_comment ""
    local long
    long=$(printf 'a%.0s' {1..65})
    for bad in "it's" 'a"b' 'a\b' "$long" $'a\nb'; do
        run valid_comment "$bad"
        [ "$status" -ne 0 ]
    done
}

@test "ask_yes_no acepta 'sí' con tilde y vuelve a preguntar si no entiende" {
    run ask_yes_no "¿Seguro?" no <<< "sí"
    [ "$status" -eq 0 ]
    run ask_yes_no "¿Seguro?" no <<< "S"
    [ "$status" -eq 0 ]
    run ask_yes_no "¿Seguro?" si <<< "no"
    [ "$status" -eq 1 ]
    run ask_yes_no "¿Seguro?" si <<< ""
    [ "$status" -eq 0 ]
    run ask_yes_no "¿Seguro?" no <<< $'quizas\nsi'
    [ "$status" -eq 0 ]
    [[ "$output" == *"no reconocida"* ]]
}

@test "read_input termina con error si la entrada se cierra (EOF)" {
    run read_input valor "Pregunta:" < /dev/null
    [ "$status" -eq 1 ]
    [[ "$output" == *"EOF"* ]]
}

@test "split_spec respeta las comillas de los perfiles de aplicación" {
    run split_spec "allow 'Nginx Full'"
    [ "${lines[0]}" = "allow" ]
    [ "${lines[1]}" = "Nginx Full" ]
}

@test "is_ssh_rule reconoce las reglas que permiten SSH" {
    is_ssh_rule "allow 22/tcp comment 'SSH'" 22
    is_ssh_rule "limit from 192.168.1.0/24 to any port 22 proto tcp comment 'SSH-LAN'" 22
    is_ssh_rule "allow from 10.0.0.5 to any port 22" 22
    is_ssh_rule "allow OpenSSH" 22
    is_ssh_rule "allow from 192.168.1.10 to 10.0.0.1 port 22 proto tcp" 22
    for bad in "allow 22/udp" "deny 22/tcp" "allow 2222/tcp" "allow out 22/tcp" "route allow 22/tcp" "allow OpenSSH"; do
        run is_ssh_rule "$bad" 2200
        [ "$status" -ne 0 ]
    done
    run is_ssh_rule "allow 22/udp" 22
    [ "$status" -ne 0 ]
}

@test "is_desired_ssh_rule depende de LAN_NET y SSH_LIMIT" {
    SSH_LIMIT=si
    LAN_NET=0.0.0.0/0
    is_desired_ssh_rule "limit 22/tcp comment 'SSH'" 22
    run is_desired_ssh_rule "allow 22/tcp" 22
    [ "$status" -ne 0 ]
    LAN_NET=192.168.1.0/24
    is_desired_ssh_rule "limit from 192.168.1.0/24 to any port 22 proto tcp comment 'SSH-LAN'" 22
    run is_desired_ssh_rule "limit 22/tcp" 22
    [ "$status" -ne 0 ]
    LAN_NET=10.0.0.5/32
    is_desired_ssh_rule "limit from 10.0.0.5 to any port 22 proto tcp" 22
    SSH_LIMIT=no
    is_desired_ssh_rule "allow from 10.0.0.5 to any port 22 proto tcp" 22
}

@test "load_config trata el fichero como datos y valida los valores" {
    cat > "$CONFIG_FILE" <<EOF
SSH_PORT="\$(touch ${BATS_TEST_TMPDIR}/pwned)"
LAN_NET="1.2.3.4/"
SSH_LIMIT=quizas
EOF
    load_config 2> "$BATS_TEST_TMPDIR/err"
    [ ! -e "$BATS_TEST_TMPDIR/pwned" ]
    [ "$SSH_PORT" = "22" ]
    [ "$LAN_NET" = "0.0.0.0/0" ]
    [ "$SSH_LIMIT" = "si" ]
    grep -q "SSH_PORT no válido" "$BATS_TEST_TMPDIR/err"
    grep -q "LAN_NET no válida" "$BATS_TEST_TMPDIR/err"
}

@test "load_config lee la configuración de la v1.1" {
    printf '# Configuración del gestor de firewall\nSSH_PORT=22\nLAN_NET="192.168.1.0/24"\n' > "$CONFIG_FILE"
    load_config
    [ "$SSH_PORT" = "22" ]
    [ "$LAN_NET" = "192.168.1.0/24" ]
}

@test "load_config corrige un puerto SSH desfasado respecto a sshd" {
    printf 'SSH_PORT=2200\n' > "$CONFIG_FILE"
    load_config 2> "$BATS_TEST_TMPDIR/err"
    [ "$SSH_PORT" = "22" ]
    grep -q "no coincide" "$BATS_TEST_TMPDIR/err"
    grep -qx 'SSH_PORT=22' "$CONFIG_FILE"
}

@test "detect_ssh_ports tiene en cuenta sshd_config.d (Port es acumulativo)" {
    run detect_ssh_ports
    [ "$output" = "22" ]
    echo "Port 2200" > "$SSHD_CONFIG_DIR/50-cloud.conf"
    run detect_ssh_ports
    [ "$output" = "2200" ]
    sed -i '2a Port 22' "$SSHD_CONFIG"
    run detect_ssh_ports
    [ "${lines[0]}" = "22" ]
    [ "${lines[1]}" = "2200" ]
}

@test "detect_ssh_ports analiza los ficheros si sshd -T no está disponible" {
    echo "Port 2200" > "$SSHD_CONFIG_DIR/50-cloud.conf"
    run parse_ssh_ports_from_files
    [ "$output" = "2200" ]
}

@test "ssh_write_port escribe Port al principio y nunca dentro de Match" {
    sed -i '2a Port 22' "$SSHD_CONFIG"
    echo "Port 2200" > "$SSHD_CONFIG_DIR/50-cloud.conf"
    ssh_write_port 2222
    [ "$(head -n 1 "$SSHD_CONFIG")" = "# BEGIN Firewall_Kit" ]
    grep -qx 'Port 2222' "$SSHD_CONFIG"
    grep -qxF '#[Firewall_Kit] Port 22' "$SSHD_CONFIG"
    grep -qxF '#[Firewall_Kit] Port 2200' "$SSHD_CONFIG_DIR/50-cloud.conf"
    [ "$(tail -n 1 "$SSHD_CONFIG")" = "    ForceCommand internal-sftp" ]
    sshd -t -f "$SSHD_CONFIG"
    [ "$(detect_ssh_ports)" = "2222" ]

    # Una segunda ejecución reemplaza el bloque en lugar de duplicarlo
    ssh_write_port 2223
    [ "$(grep -c '^# BEGIN Firewall_Kit' "$SSHD_CONFIG")" = "1" ]
    [ "$(grep -c '^Port ' "$SSHD_CONFIG")" = "1" ]
    [ "$(detect_ssh_ports)" = "2223" ]
}

@test "create_backup omite rutas inexistentes y no deja ficheros parciales" {
    rm -f "$SSHD_CONFIG"
    create_backup prueba
    [ -f "$LAST_BACKUP" ]
    tar -tzf "$LAST_BACKUP" | grep -q '^etc/ufw/'
    run tar -tzf "$LAST_BACKUP" etc/ssh/sshd_config
    [ "$status" -ne 0 ]
    local partial=("$BACKUP_DIR"/*.partial)
    [ "${#partial[@]}" -eq 0 ]
}

@test "rotate_backups conserva BACKUP_KEEP automáticos y no toca los manuales" {
    BACKUP_KEEP=3
    create_backup "manual.tar.gz"
    local i
    for i in 1 2 3 4 5; do
        create_backup auto
    done
    local autos=("$BACKUP_DIR"/firewall_backup_*.tar.gz)
    [ "${#autos[@]}" -eq 3 ]
    [ -f "$BACKUP_DIR/manual.tar.gz" ]
}

@test "validate_archive acepta backups de la v1.1" {
    make_archive "$BATS_TEST_TMPDIR/v11.tar.gz" etc/ufw/user.rules etc/ssh/sshd_config etc/firewall-manager.conf
    validate_archive "$BATS_TEST_TMPDIR/v11.tar.gz"
}

@test "validate_archive rechaza rutas peligrosas, no previstas y enlaces" {
    make_archive "$BATS_TEST_TMPDIR/a.tar.gz" "etc/ufw/../../root/.ssh/authorized_keys"
    make_archive "$BATS_TEST_TMPDIR/b.tar.gz" "/etc/passwd"
    make_archive "$BATS_TEST_TMPDIR/c.tar.gz" "etc/passwd"
    make_archive "$BATS_TEST_TMPDIR/d.tar.gz" "etc/ufw/user.rules->/etc/shadow"
    echo "no es un tar" > "$BATS_TEST_TMPDIR/e.tar.gz"
    for f in a b c d e; do
        run validate_archive "$BATS_TEST_TMPDIR/$f.tar.gz"
        [ "$status" -ne 0 ]
    done
}

@test "rollback_guard_confirm revierte los cambios si no se confirman" {
    create_backup pre_test
    local original
    original=$(cat "$SSHD_CONFIG")
    echo "Port 9999" >> "$SSHD_CONFIG"
    mkdir -p "$RUN_DIR"
    GUARD_TOKEN="rb-1-1-1"
    echo "$LAST_BACKUP" > "$RUN_DIR/$GUARD_TOKEN"
    ROLLBACK_TIMEOUT=5
    run rollback_guard_confirm <<< "no"
    [ "$status" -eq 1 ]
    [ "$(cat "$SSHD_CONFIG")" = "$original" ]
    [ ! -e "$RUN_DIR/rb-1-1-1" ]
}

@test "rollback_guard_confirm mantiene los cambios si se confirman" {
    create_backup pre_test
    echo "Port 9999" >> "$SSHD_CONFIG"
    mkdir -p "$RUN_DIR"
    GUARD_TOKEN="rb-1-1-1"
    echo "$LAST_BACKUP" > "$RUN_DIR/$GUARD_TOKEN"
    run rollback_guard_confirm <<< "si"
    [ "$status" -eq 0 ]
    grep -qx 'Port 9999' "$SSHD_CONFIG"
    [ ! -e "$RUN_DIR/rb-1-1-1" ]
}

@test "run_rollback_guard restaura si el cambio sigue sin confirmar" {
    create_backup pre_test
    local original
    original=$(cat "$SSHD_CONFIG")
    echo "Port 9999" >> "$SSHD_CONFIG"
    mkdir -p "$RUN_DIR"
    echo "$LAST_BACKUP" > "$RUN_DIR/rb-1-1-1"
    run run_rollback_guard rb-1-1-1 0
    [ "$status" -eq 0 ]
    [ "$(cat "$SSHD_CONFIG")" = "$original" ]
    [ ! -e "$RUN_DIR/rb-1-1-1" ]
}

@test "run_rollback_guard no hace nada si el cambio ya se confirmó" {
    echo "Port 9999" >> "$SSHD_CONFIG"
    run run_rollback_guard rb-1-1-1 0
    [ "$status" -eq 0 ]
    grep -qx 'Port 9999' "$SSHD_CONFIG"
}

@test "run_rollback_guard espera a la hora límite del token" {
    create_backup pre_test
    local original
    original=$(cat "$SSHD_CONFIG")
    echo "Port 9999" >> "$SSHD_CONFIG"
    mkdir -p "$RUN_DIR"
    printf '%s\n%s\n' "$LAST_BACKUP" "$(( $(date +%s) + 2 ))" > "$RUN_DIR/rb-1-1-1"
    run run_rollback_guard rb-1-1-1
    [ "$status" -eq 0 ]
    [ "$(cat "$SSHD_CONFIG")" = "$original" ]
}

@test "run_rollback_guard termina enseguida si se confirma mientras espera" {
    create_backup pre_test
    echo "Port 9999" >> "$SSHD_CONFIG"
    mkdir -p "$RUN_DIR"
    printf '%s\n%s\n' "$LAST_BACKUP" "$(( $(date +%s) + 60 ))" > "$RUN_DIR/rb-1-1-1"
    run_rollback_guard rb-1-1-1 &
    local pid=$!
    sleep 1
    rm -f "$RUN_DIR/rb-1-1-1"
    local i
    for i in 1 2 3 4 5; do
        kill -0 "$pid" 2>/dev/null || break
        sleep 1
    done
    run kill -0 "$pid"
    [ "$status" -ne 0 ]
    grep -qx 'Port 9999' "$SSHD_CONFIG"
}
