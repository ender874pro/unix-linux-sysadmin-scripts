#!/bin/ksh
## =====================================================================
## SCRIPT DE MONITOREO Y ALERTAS DE BLOQUEOS (IPFILTER) - SOLARIS 10
## Ruta: /root/scripts/filtrar_ultimos_5m.ksh
## =====================================================================

# Configuración de correo institucional (Anónimos / Genéricos)
DEST="soporteunix@laboratorio.com"
FROM="firewallunix@laboratorio.com"
SUBJECT="Alerta: Bloqueos ipfilter en $(uname -n) - $(date '+%b %d %H:%M')"

# Archivo temporal para guardar alertas
TMPFILE="/var/tmp/firewall_alert_$$.log"

# Parámetros
interval=5                # minutos atrás para filtrar
logfile="/var/adm/messages"
tail_lines=200            # cantidad de líneas donde buscar

# Obtener fecha y hora actuales (compatible Solaris 10)
current_month=$(/usr/bin/date | awk '{print $2}')
current_day=$(/usr/bin/date | awk '{print $3}')
current_hour=$(/usr/bin/date | awk '{print substr($4,1,2)}')
current_min=$(/usr/bin/date | awk '{print substr($4,4,2)}')

# Filtrar líneas y guardar en archivo temporal
grep " b " "$logfile" | tail -"$tail_lines" | nawk -v CM="$current_month" -v CD="$current_day" -v CH="$current_hour" -v CMN="$current_min" -v INT="$interval" '
BEGIN {
    MIN_5_AGO = CMN - INT
    HOUR_ADJ = CH
    if (MIN_5_AGO < 0) {
        MIN_5_AGO += 60
        HOUR_ADJ--
        if (HOUR_ADJ < 0) HOUR_ADJ = 23
    }
}
{
    mes = $1
    dia = $2 + 0
    hora = substr($3,1,2) + 0
    minuto = substr($3,4,2) + 0

    if (mes == CM && dia == CD) {
        if (MIN_5_AGO <= CMN) {
            if (hora == CH && minuto >= MIN_5_AGO && minuto <= CMN) {
                print ""
                print $0
            }
        } else {
            if ((hora == CH && minuto <= CMN) || (hora == HOUR_ADJ && minuto >= MIN_5_AGO)) {
                print ""
                print $0
            }
        }
    }
}
' > "$TMPFILE"

# Verificar si hubo alertas y enviar mail
if [ -s "$TMPFILE" ]; then
    # Se utiliza una única llamada robusta con la bandera -r para definir el remitente en Solaris 10
    mailx -r "$FROM" -s "$SUBJECT" "$DEST" < "$TMPFILE"
fi

# Limpiar archivo temporal
rm -f "$TMPFILE"
