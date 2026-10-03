# Changelog

## 2.0

### Errores corregidos

- **Bloqueo de SSH en `--init`**: el firewall se activaba aunque la regla SSH hubiera fallado. Ahora cada paso se comprueba y, si falla, se restaura el estado anterior.
- **Validación numérica en octal**: valores como `08080` saltaban la validación y `070000` se aceptaba como puerto SSH (sshd no arrancaba). Además, `08080` dejaba ufw inservible ("problem running iptables"). Ahora los números se interpretan siempre en base 10.
- **`Port` dentro de un bloque `Match`**: el puerto se añadía al final de `sshd_config`. Ahora se escribe en un bloque gestionado al principio, se valida con `sshd -t` y se deshace si falla.
- **Cambio de puerto sin efecto en Ubuntu 22.10+/24.04** (activación por `ssh.socket`): ahora se ejecuta `systemctl daemon-reload` + `systemctl restart ssh.socket` y se comprueba que sshd escucha en el puerto nuevo.
- **Puerto SSH desfasado**: solo se detectaba la primera vez. Ahora se contrasta con `sshd -T` en cada ejecución, y `--init` permite siempre el puerto de la sesión actual.
- **CIDR mal validado**: `1.2.3.4/` se aceptaba y se guardaba.
- **El nuevo puerto SSH se abría a todo Internet** aunque SSH estuviera restringido a una LAN.
- **Cambiar la LAN no restringía nada**: la regla abierta anterior seguía activa. Ahora se elimina.
- El mensaje de cambio de LAN mostraba la red nueva también como "antes".
- **Detección de sesión SSH rota con `sudo`**, que borra `SSH_CONNECTION`: ahora se busca en los procesos padre.
- **Recorrido de rutas en el backup manual** (`../../x`) y sobrescritura sin preguntar.
- **Restauración insegura**: se extraía cualquier ruta del `.tar.gz` en `/`. Ahora se valida el contenido, se guarda antes el estado actual y se comprueba la configuración de sshd.
- La configuración se cargaba con `source` como root. Ahora se lee como datos y se valida.
- Mensajes de éxito falsos al añadir o eliminar reglas e instalar ufw cuando la operación fallaba (ufw devuelve 0 en "Could not delete non-existent rule").
- La confirmación de `ufw delete` en inglés (`y|n`) cancelaba la operación si se respondía "s".
- **Bucle infinito del menú** cuando la entrada estaba cerrada (EOF).
- El "modo no interactivo" pedía confirmaciones y `pause`: ahora existe `--yes` y no hay pausas fuera del menú.
- DRY-RUN creaba la configuración y directorios e instalaba ufw de verdad.
- Los backups fallidos dejaban `.tar.gz` incompletos que luego aparecían para restaurar.
- Fallo con arrays vacíos y `set -u` en bash 4.2/4.3 (CentOS 7) al añadir un puerto sin comentario.
- Las respuestas con espacios o "sí" con tilde no se reconocían.
- `--help` exigía root y creaba la configuración.
- `--status` instalaba paquetes.

### Mejoras

- Reversión automática de los cambios arriesgados hechos por SSH si no se confirman a tiempo o se corta la conexión.
- Limitación de intentos SSH con `ufw limit` (configurable, opción de menú 12 y `--ssh-limit`).
- Línea de comandos completa: `--add`, `--from`, `--action`, `--comment`, `--delete`, `--list`, `--ssh-port`, `--lan`, `--ssh-limit`, `--backup [NOMBRE]`, `--list-backups`, `--restore [ARCHIVO]`, `--yes`, `--rollback-timeout`, `--no-color`, `--version`.
- Rangos de puertos, acciones `limit`/`deny`/`reject` y orígenes IPv6.
- Reglas listadas y borradas con `ufw show added`: funciona con ufw activo o inactivo y borra a la vez las versiones IPv4/IPv6.
- Soporte de SELinux (`semanage`) y de `sshd_config.d`.
- Avisos de conflicto con firewalld y de Docker.
- Backups automáticos antes de cada cambio arriesgado, rotación (`BACKUP_KEEP`) y listado ordenado por fecha.
- Bloqueo contra ejecuciones simultáneas (`flock`) y auditoría en syslog.
- Soporte de pacman y uso de `apt-get` en lugar de `apt`.
- Tests automatizados (bats) y CI con ShellCheck.
- `firewall.sh` se guarda en git como ejecutable.
