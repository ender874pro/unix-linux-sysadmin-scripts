# Scripts de Administración y Monitoreo (Unix / Linux)

Repositorio con scripts desarrollados para la automatización de tareas, supervisión de seguridad y diagnóstico en entornos empresariales **Unix (Oracle Solaris 11)** y **Linux (Rocky Linux 9 / Red Hat)**.

## 📂 Contenido del Repositorio

### 1. `pf_firewall_monitor.ksh` (Unix / Oracle Solaris 11)
Script en KornShell (`ksh`) diseñado para ejecutarse como servicio en segundo plano y auditar en tiempo real los paquetes bloqueados por **Packet Filter (PF)**.

* **Funcionamiento:** Escucha el tráfico de la interfaz virtual `pflog0` mediante `tcpdump` sin búfer (`stdbuf -oL`), filtra los eventos de bloqueo (`block`) y los acumula en un registro temporal.
* **Control de alertas:** Envía un resumen consolidado vía `mailx` cada 5 minutos (`INTERVAL=300`), evitando la saturación del servidor de correo ante ráfagas de tráfico.
* **Gestión de procesos:** Incluye captura de señal `TERM` (`trap`) para garantizar una detención limpia del demonio.

---

### 2. `nftables_firewall_monitor.sh` (Linux / Rocky Linux 9 / RHEL)
Adaptación moderna en `Bash` para distribuciones empresariales Linux basadas en **systemd** y **nftables**.

* **Funcionamiento:** Supervisa el flujo en vivo del registro del sistema mediante `journalctl -f -n 0` buscando trazas específicas de conexiones bloqueadas (`nftables: blocked connection:`).
* **Notificación HTML:** Formatea los eventos acumulados en bloques `<pre>` y envía reportes consolidados por correo electrónico mediante `mailx` con cabecera `text/html` cada 5 minutos.
* **Gestión de procesos:** Manejo controlado de interrupciones (`TERM` e `INT`) para ejecución segura como unidad de `systemd`.


