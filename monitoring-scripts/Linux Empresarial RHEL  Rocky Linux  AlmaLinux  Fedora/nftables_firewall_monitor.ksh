#!/bin/bash
# ==============================================================================
# Script: nftables_firewall_monitor.sh
# Descripción: Monitoreo en tiempo real de conexiones bloqueadas por nftables
#              en Rocky Linux / RHEL 9 mediante lectura de journalctl.
#              Agrupa los eventos y envía alertas periódicas en formato HTML.
# Autor: Ender Zambrano
# ==============================================================================

# Manejar señal para detener el servicio limpiamente
trap "echo 'Servicio de monitoreo nftables detenido'; exit 0" TERM INT

# Variables de configuración
DEST="soporte-unix@ejemplo.com"
SUBJECT="Alerta: Bloqueos de nftables detectados en $(hostname)"
FROM="firewall-linux@laboratorio.com"
TMPFILE="/var/tmp/nftables_mail_alert.log"
INTERVAL=300  # Intervalo de envío en segundos (5 minutos)

# Limpia el archivo temporal al inicio
> "$TMPFILE"

# Tiempo del último envío
LAST_SEND=$(date +%s)

# Bucle principal: monitorea journalctl en tiempo real y envía cada INTERVAL segundos
journalctl -f -n 0 | while read -r line; do
    # Si hay coincidencia con el prefijo de bloqueo de nftables, la guarda en el temporal
    if [[ "$line" == *"nftables: blocked connection:"* ]]; then
        echo "$line" >> "$TMPFILE"
    fi

    # Comprueba si ha pasado el intervalo configurado
    NOW=$(date +%s)
    if (( NOW - LAST_SEND >= INTERVAL )); then
        if [[ -s "$TMPFILE" ]]; then
            {
                echo "<h3>Eventos de bloqueo detectados en $(hostname)</h3><pre>"
                cat "$TMPFILE"
                echo "</pre>"
            } | mailx -S "content-type=text/html" -s "$SUBJECT" -r "$FROM" "$DEST"
            > "$TMPFILE"
        fi
        LAST_SEND=$NOW
    fi
done
