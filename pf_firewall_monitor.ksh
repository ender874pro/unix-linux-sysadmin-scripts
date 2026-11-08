#!/usr/bin/ksh
# ==============================================================================
# Script: pf_firewall_monitor.ksh
# Descripción: Monitoreo en tiempo real de paquetes bloqueados por Packet Filter
#              (PF) en entornos Unix/Solaris mediante lectura de la interfaz pflog0.
#              Agrupa los eventos y envía alertas periódicas por correo.
# Autor: Ender Zambrano
# ==============================================================================

# Manejar señal para detener el servicio limpiamente
trap "echo 'Servicio detenido'; exit 0" TERM

# Variables de configuración
DEST="admin-seguridad@ejemplo.com"
SUBJECT="Alerta: Bloqueos de PF detectados en $(uname -n)"
FROM="firewallunix@laboratorio.com"
TMPFILE="/var/tmp/firewall_alert.log"
INTERVAL=300 # Intervalo de envío en segundos (5 minutos)

export PATH=/usr/bin:/bin:/usr/sbin:/sbin

# Inicializar archivo temporal y marca de tiempo
> "$TMPFILE"
LAST_SEND=$(perl -e 'print time')

# Ejecutar captura y filtrado de bloqueos en tiempo real
stdbuf -oL tcpdump -n -e -tttt -i pflog0 2>/dev/null | while read -r line; do
    # Filtrar únicamente paquetes bloqueados
    if echo "$line" | grep -q "block"; then
        echo "$line" >> "$TMPFILE"
    fi

    # Verificar si se cumplió el intervalo para enviar el reporte acumulado
    NOW=$(perl -e 'print time')
    if [ $((NOW - LAST_SEND)) -ge $INTERVAL ]; then
        if [ -s "$TMPFILE" ]; then
            awk '{print $0"\n"}' "$TMPFILE" | mailx -r "$FROM" -s "$SUBJECT" "$DEST"
            > "$TMPFILE"
        fi
        LAST_SEND=$NOW
    fi
done
