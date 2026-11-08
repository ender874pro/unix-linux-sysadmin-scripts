# Scripts de Administración y Monitoreo (Unix / Linux)

Repositorio con scripts desarrollados para la automatización de tareas, supervisión de seguridad y diagnóstico en entornos empresariales Unix (Oracle Solaris) y Linux (Rocky Linux / Red Hat).

## 📂 Contenido Actual

### 1. `pf_firewall_monitor.ksh` (Monitoreo de Firewall PF en Unix/Solaris)
Script en KornShell (`ksh`) diseñado para ejecutarse como servicio en segundo plano y auditar en tiempo real los paquetes bloqueados por **Packet Filter (PF)**.

* **Funcionamiento:** Escucha el tráfico de la interfaz virtual `pflog0` mediante `tcpdump` sin búfer (`stdbuf -oL`), filtra los eventos de bloqueo (`block`) y los acumula en un registro temporal.
* **Control de alertas:** Envía un resumen consolidado vía `mailx` cada 5 minutos (`INTERVAL=300`), evitando la saturación del servidor de correo ante ráfagas de tráfico.
* **Gestión de procesos:** Incluye captura de señal `TERM` (`trap`) para garantizar una detención limpia del demonio.

