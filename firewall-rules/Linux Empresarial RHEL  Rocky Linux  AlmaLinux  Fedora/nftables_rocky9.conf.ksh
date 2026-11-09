#!/usr/sbin/nft -f
# ==============================================================================
# Archivo: nftables_rocky9.conf
# Descripción: Política de firewall empresarial (Default Drop) para servidor
#              de aplicaciones (WebLogic / OAS) en Rocky Linux 9 / RHEL.
#              Incluye conjuntos dinámicos (sets) y registro de bloqueos
#              compatible con monitoreo automatizado.
# Autor: Ender Zambrano
# ==============================================================================

flush ruleset

table ip filter {

    # Definición de conjuntos dinámicos (Sets) para control de acceso por roles
    set soporte_unix {
        type ipv4_addr;
        flags dynamic;
    }

    set oas_admin {
        type ipv4_addr;
        flags dynamic;
    }

    set dev_team {
        type ipv4_addr;
        flags dynamic;
    }

    set apache_pool {
        type ipv4_addr;
        flags dynamic;
    }

    chain INPUT {
        type filter hook input priority 0; policy drop;

        # Permitir conexiones establecidas y relacionadas
        ct state established,related accept

        # Permitir tráfico en interfaz loopback
        iif lo accept
        ip saddr 127.0.0.1 ip daddr 127.0.0.1 accept

        # Permitir conexiones SSH según grupos autorizados
        ip saddr @soporte_unix ip daddr 10.10.10.41 tcp dport 22 accept
        ip saddr @oas_admin ip daddr 10.10.10.41 tcp dport 22 accept
        ip saddr @dev_team ip daddr 10.10.10.41 tcp dport 22 accept

        # Permitir tráfico DNS (UDP y TCP)
        udp dport 53 accept
        tcp dport 53 accept

        # Permitir monitoreo SNMP (UDP 161) desde servidor Nagios
        ip saddr 10.10.30.180 udp dport 161 accept
        icmp type echo-request accept

        # Permitir conexiones desde balanceadores / pool Apache hacia nodos de aplicación
        ip saddr @apache_pool ip daddr 10.10.10.41 tcp dport { 5001, 5501, 8001, 8501 } accept

        # Permitir conexiones de contexto OAS / Middleware
        ip saddr @oas_admin ip daddr 10.10.10.41 tcp dport { 80, 8280, 8330 } accept

        # Permitir acceso a consolas de administración y contenedores WebLogic/OAS
        ip saddr @oas_admin ip daddr 10.10.10.41 tcp dport { 5001, 5501, 6001, 6501, 7001, 7002, 7005, 7006, 7503, 7504, 8001, 8501 } accept

        # Permitir acceso al equipo de desarrollo a puertos de prueba con auditoría
        ip saddr @dev_team ip daddr 10.10.10.41 tcp dport 7002 accept
        ip saddr @dev_team ip daddr 10.10.10.41 tcp dport { 5501, 8501 } log prefix "Conexión aceptada: " accept

        # Permitir comunicación interna entre nodos del clúster (Nodo 1 <-> Nodo 2)
        ip saddr 10.10.10.40 ip daddr 10.10.10.41 accept

        # Registrar intentos de conexión bloqueados (traza monitoreada por script)
        ip daddr != 255.255.255.255 counter log prefix "nftables: blocked connection: " drop

        # Bloquear todo el resto del tráfico
        reject with icmp type port-unreachable
    }

    chain OUTPUT {
        type filter hook output priority 0; policy drop;

        # Permitir conexiones establecidas y relacionadas
        ct state established,related accept

        # Permitir tráfico en interfaz loopback y multicast clúster
        ip saddr 127.0.0.1 ip daddr 127.0.0.1 accept
        ip saddr 127.0.0.1 ip daddr 230.0.0.4 accept
        ip saddr 10.10.10.41 ip daddr 10.10.10.41 accept

        # Servicios básicos de infraestructura (SSH, DNS, NTP, ICMP)
        tcp dport 22 accept
        udp dport 53 accept
        tcp dport 53 accept
        udp dport 123 accept
        icmp type echo-request accept

        # Respuestas de monitoreo SNMP hacia Nagios
        ip saddr 10.10.30.180 udp dport 161 accept

        # Conexiones hacia bases de datos Oracle / DBMS empresariales
        ip saddr 10.10.10.41 ip daddr 10.10.20.161 tcp dport 1526 accept
        ip saddr 10.10.10.41 ip daddr 10.10.20.171 tcp dport 2023 accept
        ip saddr 10.10.10.41 ip daddr 10.10.20.171 tcp dport 2024 log prefix "Conexión aceptada: " accept
        ip saddr 10.10.10.41 ip daddr 10.10.20.33 tcp dport 2023 log prefix "Conexión aceptada: " accept
        ip saddr 10.10.10.41 ip daddr 10.10.20.35 tcp dport 1531 log prefix "Conexión aceptada: " accept
        ip saddr 10.10.10.41 ip daddr 10.10.20.170 tcp dport 2026 accept

        # Conexiones hacia servidores de aplicaciones secundarios (JBoss / Web)
        ip saddr 10.10.10.41 ip daddr 10.10.25.152 tcp dport 8090 log prefix "Conexión aceptada: " accept
        ip saddr 10.10.10.41 ip daddr 10.10.10.206 tcp dport 8090 log prefix "Conexión aceptada: " accept

        # Conexiones hacia Core Bancario / AS400 de pruebas
        ip saddr 10.10.10.41 ip daddr 10.10.27.67 tcp dport 9925 log prefix "Conexión aceptada: " accept
        ip saddr 10.10.10.41 ip daddr 10.20.2.100 tcp dport 9500 log prefix "Conexión aceptada: " accept

        # Conexiones hacia ambientes de desarrollo y servicios intranet
        ip saddr 10.10.10.41 ip daddr { 10.10.20.77, 10.10.10.35, 10.10.23.18, 10.10.13.24 } tcp dport 80 log prefix "Conexión aceptada: " accept
        ip saddr 10.10.10.41 ip daddr { 10.10.20.76, 10.10.20.78 } tcp dport 8280 log prefix "Conexión aceptada: " accept
        ip saddr 10.10.10.41 ip daddr 10.10.10.125 tcp dport 7781 log prefix "Conexión aceptada: " accept

        # Conexión hacia portal web corporativo y servicios externos HTTP/HTTPS
        ip saddr 10.10.10.41 ip daddr 10.10.30.177 tcp dport 443 log prefix "Conexión aceptada: " accept
        tcp dport { 80, 443 } accept

        # Comunicación con nodo par del clúster y servidor de respaldos (Backup)
        ip saddr 10.10.10.41 ip daddr 10.10.10.40 log prefix "Conexión aceptada: " accept
        ip saddr 10.10.10.41 ip daddr 10.10.40.17 accept

        # Salida hacia servidores de correo interno (SMTP) para alertas
        ip saddr 10.10.10.41 ip daddr { 10.10.35.88, 10.10.35.89 } tcp dport 25 log prefix "Conexión aceptada: " accept

        # Registrar intentos de conexión bloqueados
        ip daddr != 255.255.255.255 counter log prefix "nftables: blocked connection: " drop

        # Bloquear todo el resto del tráfico
        reject with icmp type port-unreachable
    }

    chain FORWARD {
        type filter hook forward priority 0; policy drop;

        # Permitir conexiones establecidas y relacionadas
        ct state established,related accept

        # Registrar intentos de conexión bloqueados
        ip daddr != 255.255.255.255 counter log prefix "nftables: blocked connection: " drop

        # Bloquear todo el resto del tráfico
        reject with icmp type port-unreachable
    }
}

# ==============================================================================
# Poblamiento de listas blancas (Elementos de los conjuntos dinámicos)
# ==============================================================================

# Pool de Administración Soporte Unix
add element ip filter soporte_unix { 10.10.50.11, 10.10.50.14, 10.10.50.15, 10.10.50.48 }

# Pool de Administración OAS / Middleware
add element ip filter oas_admin { 10.10.50.19, 10.10.50.37 }

# Pool de Equipo de Desarrollo / QA
add element ip filter dev_team { 10.20.2.25, 10.20.2.33, 10.20.2.35, 10.20.2.125 }

# Pool de Servidores Web / Balanceadores Apache
add element ip filter apache_pool { 10.10.10.36, 10.10.10.37 }
