# Scripts de Administración y Monitoreo (Unix / Linux)

Repositorio con scripts desarrollados para la automatización de tareas, supervisión de seguridad y diagnóstico en entornos empresariales **Unix (Oracle Solaris 10/11)** y **Linux (Rocky Linux 9 / Red Hat)**.

---

## 📂 Contenido del Repositorio

### 1. Hardening y Monitoreo Basado en Tiempo (Unix / Oracle Solaris 10 - IPFilter)
Solución modular diseñada para la securización perimetral y detección de accesos no autorizados en entornos financieros legados bajo **IPFilter (IPF)**.

* **Arquitectura Modular (`/etc/ipf/`)**: Separación estricta de responsabilidades utilizando `ippool.conf` para la gestión de árboles de IPs autorizadas (`type = tree`) y `ipf.conf` para las reglas de filtrado e inspección de estado (`flags S/SA`).
* **Script de Alerta (`filtrar_ultimos_5m.ksh`)**: Script en KornShell (`ksh`) que analiza el búfer de Syslog (`/var/adm/messages`) buscando de forma reactiva las firmas de denegación (`" b "`) generadas en una ventana móvil de 5 minutos.
* **Automatización Eficiente**: Diseñado para ser orquestado de manera nativa mediante el demonio `cron`, evitando procesos persistentes innecesarios en el kernel.
* **Mitigación de Log Flooding**: Implementación documentada utilizando la rotación mediante `logadm` para prevenir el llenado de la partición `/var`.

### 2. `pf_firewall_monitor.ksh` (Unix / Oracle Solaris 11)
Script en KornShell (`ksh`) diseñado para ejecutarse como servicio en segundo plano y auditar en tiempo real los paquetes bloqueados por **Packet Filter (PF)** en arquitecturas modernas de Solaris.

* **Funcionamiento:** Escucha el tráfico de la interfaz virtual `pflog0` mediante `tcpdump` sin búfer (`stdbuf -oL`), filtra los eventos de bloqueo (`block`) y los acumula en un registro temporal.
* **Control de alertas:** Envía un resumen consolidado vía `mailx` cada 5 minutos (`INTERVAL=300`), evitando la saturación del servidor de correo ante ráfagas de tráfico.
* **Gestión de procesos:** Incluye captura de señal `TERM` (`trap`) para garantizar una detención limpia del demonio.

### 3. `nftables_firewall_monitor.sh` (Linux / Rocky Linux 9 / RHEL)
Adaptación moderna en `Bash` para distribuciones empresariales Linux basadas en **systemd** y **nftables**.

* **Funcionamiento:** Supervisa el flujo en vivo del registro del sistema mediante `journalctl -f -n 0` buscando trazas específicas de conexiones bloqueadas (`nftables: blocked connection:`).
* **Notificación HTML:** Formatea los eventos acumulados en bloques `<pre>` y envía reportes consolidados por correo electrónico mediante `mailx` con cabecera `text/html` cada 5 minutos.
* **Gestión de procesos:** Manejo controlado de interrupciones (`TERM` e `INT`) para ejecución segura como unidad de `systemd`.

---

## 🛠️ Guía de Operación: Entorno Oracle Solaris 10 (IPFilter)

Para mantener el rigor técnico, a continuación se detallan los procedimientos para desplegar la solución en Solaris 10 de manera segura.

### A. Configuración del Firewall Modular
1. Definir los grupos lógicos en `/etc/ipf/ippool.conf`:
   ```text
   table role = ipf type = tree number = 11 { 10.10.10.50/32 }; # Soporte Unix
   table role = ipf type = tree number = 12 { 10.10.50.172 };   # Clúster BD
   ```
2. Aplicar la política restrictiva (*Default-Deny*) con auditoría controlada en `/etc/ipf/ipf.conf`:
   ```text
   pass in quick proto tcp from pool/11 to any port = 22
   # Loguear únicamente el paquete inicial de inicio TCP (SYN) para mitigar Log Flooding
   block drop in log quick inet proto tcp all flags S/SA
   ```

### B. Enrutamiento de Syslog
Para canalizar las alertas de red hacia el archivo general del sistema, verificar la presencia de la facilidad `local0` en `/etc/syslog.conf` (separado obligatoriamente por caracteres de tabulación):
```text
local0.debug                                    /var/adm/messages
```
Reiniciar el servicio para aplicar los cambios:
```bash
svcadm restart system/system-log
```

### C. Despliegue del Script de Monitoreo (`filtrar_ultimos_5m.ksh`)
1. Asignar los permisos correctos de ejecución al script:
   ```bash
   chmod 755 /root/scripts/filtrar_ultimos_5m.ksh
   ```
2. Programar la automatización en el `crontab` de `root` para realizar la verificación en ráfagas recurrentes de 5 minutos:
   ```text
   */5 * * * * /root/scripts/filtrar_ultimos_5m.ksh > /dev/null 2>&1
   ```

---

## ⚠️ Buenas Prácticas de Producción Implementadas

* **Principio de Mínimo Privilegio**: Restricción estricta de movimientos laterales en base de datos y aislamiento total del tráfico transaccional.
* **Estrategias contra la saturación de disco (Log Flooding)**: 
  * Uso de inspección por banderas TCP (`flags S/SA`) para evitar escrituras masivas redundantes por ataques de fuerza bruta.
  * Requisito operativo de rotación automatizada mediante el comando nativo `logadm`:
    ```bash
    logadm -w /var/adm/messages -C 7 -a 'kill -HUP `cat /var/run/syslog.pid`' -s 10m
    ```



