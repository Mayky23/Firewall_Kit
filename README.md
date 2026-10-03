# Firewall_Kit 🔥🛡️

**Firewall_Kit** es un gestor de firewall para Linux basado en **ufw**, escrito en **Bash**, que permite **configurar, administrar y asegurar** el firewall del sistema desde un **menú interactivo** o desde la **línea de comandos** (apto para scripts y automatización).

Está pensado para **administradores de sistemas** y servidores Linux gestionados por SSH, donde un error en el firewall puede dejarte sin acceso. Por eso cada cambio arriesgado se valida, se respalda y se puede revertir automáticamente.

---

## 🚀 Características

- Inicialización segura del firewall (deny incoming / allow outgoing) sin cortar tu sesión SSH actual
- Gestión de reglas **ufw**: puertos, rangos, protocolos, origen IPv4/IPv6, acciones `allow`, `limit`, `deny` y `reject`
- Cambio seguro del **puerto SSH**: valida con `sshd -t`, comprueba que sshd escucha en el puerto nuevo y deshace todo si algo falla
- Compatible con la **activación por socket de Ubuntu 22.10+/24.04** (`ssh.socket`), con `sshd_config.d` y con **SELinux**
- Restricción de acceso SSH a una **LAN / CIDR** (elimina las reglas que la dejaban sin efecto)
- **Limitación de intentos SSH** con `ufw limit` contra ataques de fuerza bruta
- **Reversión automática**: si trabajas por SSH y no confirmas un cambio (o se corta la conexión), el servidor vuelve solo al estado anterior
- **Backups automáticos** antes de cada cambio arriesgado, backups con nombre, rotación y restauración validada
- **Modo DRY-RUN** (simulación sin aplicar ningún cambio)
- Registro de auditoría en syslog (`journalctl -t firewall-kit`)
- Detección de conflictos con `firewalld` y aviso de Docker (sus puertos publicados se saltan ufw)
- Instalación automática de `ufw` con apt, dnf, yum, zypper o pacman

---

## 📦 Requisitos

- Linux con `bash` 4.2 o superior (probado con bash 5.2)
- `ufw` (se instala automáticamente si falta, preguntando antes)
- `tar`, `coreutils`, `grep`, `sed` y `awk`
- `systemd` o `service`
- Ejecutar como **root**

Opcionales (recomendados):

- `ss` (paquete `iproute2`): verificar que sshd escucha en el puerto nuevo
- `flock`: impedir dos ejecuciones simultáneas
- `systemd-run`: temporizador de la reversión automática
- `semanage` (paquete `policycoreutils-python-utils`): obligatorio para cambiar el puerto SSH con SELinux en modo Enforcing

> En RHEL / Rocky / Alma, `ufw` está en **EPEL** (`dnf install -y epel-release`). No uses ufw y firewalld a la vez.

---

## 📂 Archivos y rutas usadas

| Tipo | Ruta |
|-----|-----|
| Configuración interna | `/etc/firewall-manager.conf` |
| Backups | `/var/backups/firewall-manager/` |
| Bloque gestionado del puerto SSH | Inicio de `/etc/ssh/sshd_config` (`# BEGIN Firewall_Kit`) |
| Estado temporal (bloqueo, reversión) | `/run/firewall-kit/` |
| Script | `firewall.sh` |

### Configuración (`/etc/firewall-manager.conf`)

Se crea automáticamente. Se lee como datos (`CLAVE=valor`), nunca se ejecuta.

| Clave | Por defecto | Descripción |
|-------|-------------|-------------|
| `SSH_PORT` | Detectado de sshd | Puerto SSH gestionado. Si no coincide con sshd, se corrige solo |
| `LAN_NET` | `0.0.0.0/0` | Red IPv4 (CIDR) desde la que se permite SSH |
| `SSH_LIMIT` | `si` | Usar `ufw limit` en las reglas SSH (`si`/`no`) |
| `BACKUP_KEEP` | `20` | Backups automáticos que se conservan (`0` = todos) |
| `ROLLBACK_TIMEOUT` | `60` | Segundos para confirmar un cambio hecho por SSH antes de revertirlo (`0` = desactivado) |

---

## ⚙️ Instalación

```bash
git clone https://github.com/Mayky23/Firewall_Kit
cd Firewall_Kit
chmod +x firewall.sh
```

---

## ▶️ Uso

### 🔹 Modo interactivo (recomendado)

```bash
sudo ./firewall.sh
```

```text
===============================
   Firewall_Kit (ufw)
===============================
Versión script:     2.0
Estado ufw:         activo
Puerto SSH:         22   (sshd escucha en: 22)
LAN SSH permitida:  0.0.0.0/0 (todas)
Límite SSH (limit): si
Backups en:         /var/backups/firewall-manager
Modo DRY-RUN:       desactivado
Sesión actual:      SSH desde 192.168.3.40 (puerto 22)
-------------------------------
1) Inicializar firewall
2) Listar reglas
3) Añadir regla
4) Eliminar regla
5) Cambiar puerto SSH
6) Cambiar LAN permitida (SSH)
7) Ver estado detallado
8) Backup automático
9) Restaurar configuración desde backup
10) Backup manual (con nombre)
11) Alternar modo DRY-RUN
12) Alternar limitación de intentos SSH (ufw limit)
0) Salir
-------------------------------
Elige una opción:
```

### 🔹 Línea de comandos

```bash
sudo ./firewall.sh --init                    # Inicializar (pide confirmación)
sudo ./firewall.sh --yes --init              # Inicializar sin preguntas
sudo ./firewall.sh --status                  # Estado detallado
sudo ./firewall.sh --list                    # Reglas numeradas
sudo ./firewall.sh --add 443/tcp --comment "HTTPS"
sudo ./firewall.sh --add 5432/tcp --from 10.0.0.0/8 --comment "PostgreSQL"
sudo ./firewall.sh --add 6000:6007/udp --action deny
sudo ./firewall.sh --delete 3                # Número según --list
sudo ./firewall.sh --ssh-port 2222
sudo ./firewall.sh --lan 192.168.1.0/24      # 'any' para permitir todas
sudo ./firewall.sh --ssh-limit no
sudo ./firewall.sh --backup                  # Backup automático
sudo ./firewall.sh --backup antes-de-migrar  # Backup con nombre
sudo ./firewall.sh --list-backups
sudo ./firewall.sh --restore                 # Selección interactiva
sudo ./firewall.sh --restore antes-de-migrar.tar.gz
```

Opciones globales:

| Opción | Descripción |
|--------|-------------|
| `-y`, `--yes` | Responder "si" a las confirmaciones. Las operaciones que dejarían sin acceso SSH a la sesión actual se abortan igualmente |
| `--dry-run` | Simular: muestra los cambios sin aplicar ninguno |
| `--rollback-timeout SEG` | Segundos para confirmar cambios hechos por SSH (`0` = desactivar) |
| `--no-color` | Sin colores (también se respeta la variable `NO_COLOR`) |

Código de salida: `0` si todo fue bien y `1` si hubo un error o se canceló la operación.

### 🔹 Modo simulación (DRY-RUN)

```bash
sudo ./firewall.sh --dry-run --init
sudo ./firewall.sh --dry-run --ssh-port 2222
```

No modifica ningún fichero, regla ni servicio: solo muestra lo que se haría.

---

## 🔐 Gestión de SSH

- Detecta los puertos reales de sshd con `sshd -T` (incluye `sshd_config.d`) y avisa si la configuración guardada está desfasada
- Detecta la sesión SSH actual aunque se use `sudo` (que borra `SSH_CONNECTION`)
- `--init` permite siempre el puerto por el que entra tu sesión y se niega a continuar con `--yes` si tu IP quedaría fuera de la LAN permitida
- Al cambiar el puerto:
  1. Crea un backup
  2. Abre el nuevo puerto en ufw respetando la LAN y la limitación configuradas
  3. Etiqueta el puerto en SELinux si hace falta
  4. Escribe `Port` en un bloque gestionado al principio de `sshd_config` (nunca dentro de un bloque `Match`) y comenta las demás directivas `Port`
  5. Valida con `sshd -t`, reinicia SSH (`ssh.socket` en Ubuntu 22.10+) y comprueba con `ss` que escucha en el puerto nuevo
  6. Si cualquier paso falla, restaura el estado anterior
  7. Tras confirmar, ofrece borrar las reglas del puerto antiguo

### Reversión automática

Cuando trabajas por SSH en modo interactivo, después de inicializar, cambiar el puerto, cambiar la LAN, borrar una regla SSH o restaurar un backup, el script pide que abras **una nueva sesión SSH** y confirmes. Si no confirmas a tiempo, respondes "no" o la conexión se corta, un proceso independiente (temporizador de systemd o proceso en segundo plano) restaura el backup tomado justo antes del cambio.

---

## 💾 Backups

Incluyen, si existen:

- `/etc/ufw`
- `/etc/ssh/sshd_config` y `/etc/ssh/sshd_config.d`
- `/etc/firewall-manager.conf`

Se crean automáticamente antes de inicializar, cambiar el puerto SSH, cambiar la LAN o la limitación, borrar reglas y restaurar. Al restaurar, el script:

- comprueba que el backup solo contiene esas rutas (sin `..`, rutas absolutas ni enlaces)
- guarda antes el estado actual
- valida la configuración de sshd y vuelve atrás si no es válida
- recarga ufw y reinicia SSH solo si su configuración cambió

Los backups de la versión 1.x son compatibles.

---

## 🧪 Tests

```bash
sudo apt-get install -y bats shellcheck
shellcheck firewall.sh tests/fake-bin/*
bats tests/
```

Los tests usan versiones falsas de `ufw`, `sshd`, `systemctl` y `ss` (`tests/fake-bin`) sobre un árbol de ficheros temporal, así que no tocan el firewall real y no necesitan root.

---

## 📖 Ayuda

```bash
./firewall.sh --help
```

Consulta el historial de cambios en [CHANGELOG.md](CHANGELOG.md).
