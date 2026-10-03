#!/usr/bin/env bats
# Tests de integración: ejecutan firewall.sh completo con las herramientas
# falsas de tests/fake-bin.

load test_helper

setup() {
    setup_env
}

@test "--help y --version funcionan sin crear la configuración" {
    run fk --help
    [ "$status" -eq 0 ]
    [[ "$output" == *"--ssh-port"* ]]
    run fk --version
    [ "$status" -eq 0 ]
    [ "$output" = "Firewall_Kit v2.0" ]
    [ ! -e "$FK_ROOT/etc/firewall-manager.conf" ]
}

@test "opciones incorrectas terminan con error" {
    run fk --no-existe
    [ "$status" -eq 1 ]
    run fk --init --status
    [ "$status" -eq 1 ]
    run fk --comment hola
    [ "$status" -eq 1 ]
    run fk --add
    [ "$status" -eq 1 ]
}

@test "el menú termina si la entrada se cierra (en la v1.1 era un bucle infinito)" {
    run timeout 10 bash "$SCRIPT" < /dev/null
    [ "$status" -eq 1 ]
    [[ "$output" == *"EOF"* ]]
}

@test "--init sin --yes y sin terminal no cambia nada" {
    run fk --init < /dev/null
    [ "$status" -eq 1 ]
    run grep -q reset "$FK_ROOT/ufw.log"
    [ "$status" -ne 0 ]
    grep -qx 'ENABLED=no' "$FK_ROOT/etc/ufw/ufw.conf"
}

@test "--yes --init aplica la política segura con SSH limitado" {
    run fk --yes --init
    [ "$status" -eq 0 ]
    [ "$(rules)" = "limit 22/tcp comment 'SSH'" ]
    grep -qx 'ENABLED=yes' "$FK_ROOT/etc/ufw/ufw.conf"
    grep -q 'default deny incoming' "$FK_ROOT/ufw.log"
    grep -q 'default allow outgoing' "$FK_ROOT/ufw.log"
    [ "$(backup_count)" -eq 1 ]
}

@test "--init permite también el puerto de la sesión SSH actual" {
    export SSH_CONNECTION="192.168.1.40 50000 10.0.0.1 2200"
    run fk --yes --init
    [ "$status" -eq 0 ]
    run rules
    [[ "$output" == *"limit 22/tcp comment 'SSH'"* ]]
    [[ "$output" == *"limit 2200/tcp comment 'SSH'"* ]]
}

@test "--init aborta con --yes si la IP de la sesión queda fuera de la LAN" {
    printf 'LAN_NET="192.168.1.0/24"\n' > "$FK_ROOT/etc/firewall-manager.conf"
    export SSH_CONNECTION="8.8.8.8 50000 10.0.0.1 22"
    run fk --yes --init
    [ "$status" -eq 1 ]
    [[ "$output" == *"Abortado por seguridad"* ]]
    run grep -q reset "$FK_ROOT/ufw.log"
    [ "$status" -ne 0 ]
}

@test "si falla la regla SSH, --init no activa el firewall y restaura el estado" {
    fk --add 80/tcp
    export FAKE_UFW_FAIL_ON="limit"
    run fk --yes --init
    [ "$status" -eq 1 ]
    grep -qx 'ENABLED=no' "$FK_ROOT/etc/ufw/ufw.conf"
    run grep -c -- '--force enable' "$FK_ROOT/ufw.log"
    [ "$output" = "0" ]
    unset FAKE_UFW_FAIL_ON
    [ "$(rules)" = "allow 80/tcp" ]
}

@test "--dry-run no modifica nada" {
    run fk --dry-run --yes --init
    [ "$status" -eq 0 ]
    [[ "$output" == *"[DRY-RUN] ufw --force reset"* ]]
    [ ! -e "$FK_ROOT/etc/firewall-manager.conf" ]
    [ ! -d "$FK_ROOT/var/backups/firewall-manager" ]
    run grep -cvE '^(status|show added)' "$FK_ROOT/ufw.log"
    [ "$output" = "0" ]
}

@test "--add valida puertos, rangos, origen y comentario" {
    run fk --add 08080/tcp
    [ "$status" -eq 0 ]
    run fk --add 070000
    [ "$status" -eq 1 ]
    run fk --add 6000:6007 --from 10.1.2.3/16 --comment "rango"
    [ "$status" -eq 0 ]
    run fk --add 443/tcp --action limit --comment "HTTPS"
    [ "$status" -eq 0 ]
    run fk --add 53 --from 2001:db8::/32
    [ "$status" -eq 0 ]
    run fk --add 80 --comment "it's"
    [ "$status" -eq 1 ]
    run fk --add 80 --from servidor.local
    [ "$status" -eq 1 ]
    run fk --add 80 --action permitir
    [ "$status" -eq 1 ]
    run rules
    [ "${lines[0]}" = "allow 8080/tcp" ]
    [ "${lines[1]}" = "allow from 10.1.0.0/16 to any port 6000:6007 proto tcp comment 'rango'" ]
    [ "${lines[2]}" = "allow from 10.1.0.0/16 to any port 6000:6007 proto udp comment 'rango'" ]
    [ "${lines[3]}" = "limit 443/tcp comment 'HTTPS'" ]
    [ "${lines[4]}" = "allow from 2001:db8::/32 to any port 53" ]
    [ "${#lines[@]}" -eq 5 ]
}

@test "--add deny en el puerto SSH se rechaza con --yes" {
    run fk --yes --add 22/tcp --action deny
    [ "$status" -eq 1 ]
    [ -z "$(rules)" ]
}

@test "--lan restringe SSH y elimina la regla abierta anterior" {
    fk --yes --init
    run fk --yes --lan 192.168.1.5/24
    [ "$status" -eq 0 ]
    [[ "$output" == *"(antes: 0.0.0.0/0)"* ]]
    [ "$(rules)" = "limit from 192.168.1.0/24 to any port 22 proto tcp comment 'SSH-LAN'" ]
    [ "$(config_value LAN_NET)" = "192.168.1.0/24" ]

    run fk --yes --lan any
    [ "$status" -eq 0 ]
    [ "$(rules)" = "limit 22/tcp comment 'SSH'" ]
}

@test "--lan rechaza un CIDR mal formado" {
    run fk --yes --lan 1.2.3.4/
    [ "$status" -eq 1 ]
    [ "$(config_value LAN_NET)" = "0.0.0.0/0" ]
}

@test "--ssh-limit cambia entre limit y allow" {
    fk --yes --init
    run fk --yes --ssh-limit no
    [ "$status" -eq 0 ]
    [ "$(rules)" = "allow 22/tcp comment 'SSH'" ]
    [ "$(config_value SSH_LIMIT)" = "no" ]
    run fk --yes --ssh-limit tal-vez
    [ "$status" -eq 1 ]
}

@test "--ssh-port cambia sshd, verifica que escucha y limpia el puerto antiguo" {
    fk --yes --init
    fk --yes --lan 192.168.1.0/24
    run fk --yes --ssh-port 2222
    [ "$status" -eq 0 ]
    [ "$(head -n 1 "$FK_ROOT/etc/ssh/sshd_config")" = "# BEGIN Firewall_Kit" ]
    grep -qx 'Port 2222' "$FK_ROOT/etc/ssh/sshd_config"
    [ "$(tail -n 1 "$FK_ROOT/etc/ssh/sshd_config")" = "    ForceCommand internal-sftp" ]
    # La regla del nuevo puerto respeta la LAN (la v1.1 lo abría a todos)
    [ "$(rules)" = "limit from 192.168.1.0/24 to any port 2222 proto tcp comment 'SSH-LAN'" ]
    [ "$(config_value SSH_PORT)" = "2222" ]
    grep -q 'restart ssh.service' "$FK_ROOT/systemctl.log"
}

@test "--ssh-port usa daemon-reload + ssh.socket con activación por socket" {
    export FAKE_SSH_SOCKET=1
    run fk --yes --ssh-port 2222
    [ "$status" -eq 0 ]
    grep -q 'daemon-reload' "$FK_ROOT/systemctl.log"
    grep -q 'restart ssh.socket' "$FK_ROOT/systemctl.log"
}

@test "--ssh-port revierte todo si sshd no escucha en el nuevo puerto" {
    fk --yes --init
    cp "$FK_ROOT/etc/ssh/sshd_config" "$BATS_TEST_TMPDIR/original"
    export FAKE_NO_LISTEN=1
    run fk --yes --ssh-port 2222
    [ "$status" -eq 1 ]
    [[ "$output" == *"no escucha"* ]]
    cmp "$BATS_TEST_TMPDIR/original" "$FK_ROOT/etc/ssh/sshd_config"
    [ "$(rules)" = "limit 22/tcp comment 'SSH'" ]
    [ "$(config_value SSH_PORT)" = "22" ]
}

@test "--ssh-port revierte todo si sshd -t falla" {
    fk --yes --init
    cp "$FK_ROOT/etc/ssh/sshd_config" "$BATS_TEST_TMPDIR/original"
    export FAKE_SSHD_T_FAIL=1
    run fk --yes --ssh-port 2222
    [ "$status" -eq 1 ]
    cmp "$BATS_TEST_TMPDIR/original" "$FK_ROOT/etc/ssh/sshd_config"
    [ "$(rules)" = "limit 22/tcp comment 'SSH'" ]
}

@test "--ssh-port rechaza valores octales o fuera de rango" {
    for bad in 070000 0 65536 abc; do
        run fk --yes --ssh-port "$bad"
        [ "$status" -eq 1 ]
    done
    run grep -c '^Port' "$FK_ROOT/etc/ssh/sshd_config"
    [ "$output" = "0" ]
}

@test "--delete elimina reglas y protege la última regla SSH" {
    fk --yes --init
    fk --add 80/tcp
    run fk --yes --delete 1
    [ "$status" -eq 1 ]
    [[ "$output" == *"ÚLTIMA regla"* ]]
    run fk --yes --delete 2
    [ "$status" -eq 0 ]
    [ "$(rules)" = "limit 22/tcp comment 'SSH'" ]
    run fk --yes --delete 9
    [ "$status" -eq 1 ]
}

@test "--backup crea backups automáticos y con nombre validado" {
    run fk --backup
    [ "$status" -eq 0 ]
    run fk --backup mi-backup
    [ "$status" -eq 0 ]
    [ -f "$FK_ROOT/var/backups/firewall-manager/mi-backup.tar.gz" ]
    run fk --backup ../../escape
    [ "$status" -eq 1 ]
    run fk --backup firewall_backup_x
    [ "$status" -eq 1 ]
    [ ! -e "$FK_ROOT/escape.tar.gz" ]
    [ "$(backup_count)" -eq 2 ]
}

@test "--backup funciona aunque no exista sshd_config" {
    rm -f "$FK_ROOT/etc/ssh/sshd_config"
    run fk --backup
    [ "$status" -eq 0 ]
    [ "$(backup_count)" -eq 1 ]
}

@test "--restore restaura un backup y guarda antes el estado actual" {
    fk --yes --init
    fk --backup base
    fk --add 80/tcp
    run fk --yes --restore base.tar.gz
    [ "$status" -eq 0 ]
    [ "$(rules)" = "limit 22/tcp comment 'SSH'" ]
    run fk --list-backups
    [[ "$output" == *"firewall_backup_pre_restore_"* ]]
}

@test "--restore rechaza backups manipulados" {
    mkdir -p "$FK_ROOT/var/backups/firewall-manager"
    make_archive "$FK_ROOT/var/backups/firewall-manager/evil.tar.gz" "etc/ufw/../../etc/cron.d/x"
    run fk --yes --restore evil.tar.gz
    [ "$status" -eq 1 ]
    [ ! -e "$FK_ROOT/etc/cron.d/x" ]
}
