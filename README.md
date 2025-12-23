# Firewall_Kit 🔥🛡️

**Firewall_Kit** es un gestor de firewall para Linux basado en **ufw**, escrito en **Bash**, que permite **configurar, administrar y asegurar** el firewall del sistema de forma **segura, interactiva y automatizable**.

Está pensado para **administradores de sistemas**, servidores Linux y entornos donde la seguridad y los backups son críticos.

---

## 🚀 Características

- Inicialización segura del firewall (deny incoming / allow outgoing)
- Gestión completa de reglas **ufw**
- Cambio seguro del **puerto SSH**
- Restricción de acceso SSH por **LAN / CIDR**
- Modo **interactivo (menú)** y **no interactivo (CLI)**
- **Backups automáticos y manuales**
- Restauración asistida desde backups
- **Modo DRY-RUN** (simulación sin aplicar cambios)
- Detección automática del gestor de paquetes
- Colores y mensajes claros para terminal
- Protección frente a errores comunes (`set -euo pipefail`)

---

## 📦 Requisitos

- Linux
- `bash`
- `ufw`
- `tar`
- `systemd` o `service`
- Ejecutar como **root**

> El script instala `ufw` automáticamente si no está presente (cuando es posible).

---

## 📂 Archivos y rutas usadas

| Tipo | Ruta |
|-----|-----|
| Configuración interna | `/etc/firewall-manager.conf` |
| Backups | `/var/backups/firewall-manager/` |
| Script | `firewall.sh` |

---

## ⚙️ Instalación

```bash
git clone <repositorio>
cd Firewall_Kit
chmod +x firewall.sh
```

---

## ▶️ Uso

### 🔹 Modo interactivo (recomendado)

```bash
sudo ./firewall.sh
```

```bash
===============================
   Firewall_Kit (ufw)
===============================
Versión script:     1.1
Puerto SSH actual:  22
LAN SSH permitida:  0.0.0.0/0
Backups en:         /var/backups/firewall-manager
Modo DRY-RUN:       desactivado
Sesión actual:      SSH desde 192.168.3.40
-------------------------------
1) Inicializar firewall
2) Listar puertos permitidos
3) Añadir puerto permitido
4) Eliminar puerto permitido
5) Cambiar puerto SSH
6) Cambiar LAN permitida (SSH)
7) Ver estado / reglas
8) Exportar configuración (backup automático)
9) Restaurar configuración desde backup
10) Backup manual
11) Alternar modo DRY-RUN
0) Salir
-------------------------------
Elige una opción:
```

### 🔹 Modo no interactivo (CLI)

```bash
sudo ./firewall.sh --init
sudo ./firewall.sh --status
sudo ./firewall.sh --backup
sudo ./firewall.sh --restore
```

### 🔹 Modo simulación (DRY-RUN)

```bash
sudo ./firewall.sh --dry-run --init
```

---

## 🔐 Gestión de SSH

- Detecta el puerto SSH actual automáticamente
- Abre el nuevo puerto antes de cerrar el anterior
- Hace backup de `/etc/ssh/sshd_config`
- Advierte si se ejecuta desde una sesión SSH remota

---

## 💾 Backups

Incluyen:
- `/etc/ufw`
- `/etc/ssh/sshd_config`
- `/etc/firewall-manager.conf`

---

## 📖 Ayuda

```bash
sudo ./firewall.sh --help
```

