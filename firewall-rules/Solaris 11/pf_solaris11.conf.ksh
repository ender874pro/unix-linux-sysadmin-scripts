# ==============================================================================
# Archivo: pf_solaris11.conf
# Descripción: Política de firewall optimizada para Packet Filter (PF) en
#              Oracle Solaris 11 (Entorno de Servidores de Aplicaciones).
#              Refactorizado mediante tablas y macros de puertos para reducir
#              redundancia y facilitar la auditoría vía pflog0.
# Autor: Ender Zambrano
# ==============================================================================

# Omitir filtrado en interfaz de bucle local (loopback)
set skip on lo0
set reassemble no

# ==============================================================================
# 1. Definición de Macros (Agrupación de Puertos y Servicios)
# ==============================================================================
ports_ajp     = "{ 8009, 8059, 8109, 8159, 8209 }"
ports_http    = "{ 8080, 8130, 8180, 8230, 8280 }"
ports_nagios  = "{ 161, 162, 16161 }"
ports_wildfly = "{ 9443, 9990 }"
ports_db_ext  = "{ 8051, 8053, 8059, 8061 }"

# ==============================================================================
# 2. Definición de Tablas Persistentes (Listas Blancas por Rol)
# ==============================================================================
table <soporte_unix>  persist { 10.10.50.11, 10.10.50.15, 10.10.50.48 }
table <oas_admin>     persist { 10.10.50.19, 10.10.50.37 }
table <dev_web>       persist { 10.20.2.27, 10.20.2.63, 10.20.2.64, 10.20.2.122, 10.20.2.154, 10.20.2.161, 10.20.2.162, 10.20.2.180, 10.20.2.189, 10.20.2.193 }
table <dev_coord>     persist { 10.20.5.89, 10.20.5.95 }
table <app_nodes>     persist { 10.10.10.83, 10.10.10.85 }
table <apache_pool>   persist { 10.10.10.27, 10.10.10.32, 10.10.10.33, 10.10.10.35, 10.10.10.36, 10.10.10.37, 10.10.10.38, 10.10.10.39 }
table <containers>    persist { 10.10.10.12, 10.10.10.13, 10.10.10.14, 10.10.10.15, 10.10.10.81, 10.10.10.82, 10.10.10.84, 10.10.10.86, 10.10.10.87, 10.10.10.88, 10.10.10.111, 10.10.10.112, 10.10.10.114, 10.10.10.115 }
table <db_oracle>     persist { 10.10.30.17, 10.10.30.24, 10.10.30.148, 10.10.30.172 }
table <deploy_tools>  persist { 10.10.40.60, 10.10.40.61 }

# ==============================================================================
# 3. Reglas de Tráfico Entrante (INBOUND)
# ==============================================================================

# DNS (UDP 53)
anchor "dns_filter" in quick inet proto udp from any to any port = 53 {
    pass in from any to any
    block drop in quick inet proto udp all
}

# Acceso administrativo SSH por roles autorizados (Administración y Auditoría de Logs)
pass in quick inet proto tcp from { <soporte_unix>, <oas_admin>, <dev_web>, <dev_coord> } to <app_nodes> port = 22 no state

# Monitoreo Nagios (SNMP UDP y chequeos HTTP de instancias)
pass in quick inet proto udp from 10.10.10.180 to any port $ports_nagios keep state (sloppy)
pass in quick proto tcp from 10.10.10.180 to <app_nodes> port $ports_http

# Herramienta de despliegue y pase a producción (CI/CD / Harvest)
pass in quick inet proto tcp from <deploy_tools> to <app_nodes> port = 56011 no state

# Tráfico Middleware AJP y HTTP desde Balanceadores Apache, Contenedores y Desarrollo
pass in quick inet proto tcp from { <apache_pool>, <containers>, <oas_admin>, <app_nodes> } to <app_nodes> port $ports_ajp no state
pass in quick inet proto tcp from { <apache_pool>, <containers>, <oas_admin>, <dev_web>, <dev_coord>, <app_nodes> } to <app_nodes> port $ports_http no state

# Consolas de administración WildFly / JBoss
pass in quick inet proto tcp from { <oas_admin>, <app_nodes> } to <app_nodes> port $ports_wildfly no state

# ==============================================================================
# 4. Reglas de Tráfico Saliente (OUTBOUND)
# ==============================================================================

# Respuestas de monitoreo SNMP hacia Nagios
pass out log quick inet proto udp from <app_nodes> to 10.10.10.180

# Conexiones hacia Bases de Datos (Oracle, Informix, DBMS empresariales)
pass out log (to pflog0) quick inet proto tcp from <app_nodes> to <db_oracle> port = 1521 no state
pass out log (to pflog0) quick inet proto tcp from <app_nodes> to 10.10.30.29 port = 2023 no state
pass out log (to pflog0) quick inet proto tcp from <app_nodes> to 10.10.30.110 port = 1522 no state
pass out log (to pflog0) quick inet proto tcp from <app_nodes> to 10.10.30.131 port = 1524 no state
pass out log (to pflog0) quick inet proto tcp from <app_nodes> to 10.10.35.151 port $ports_db_ext no state
pass out log (to pflog0) quick inet proto tcp from <app_nodes> to 10.10.35.42 port = 30000 no state
pass out log (to pflog0) quick inet proto tcp from <app_nodes> to 10.10.13.1 port { 20, 21 } no state

# Conexión hacia Core Bancario (IBM iSeries / AS400) y Servicios Móviles
pass out log (to pflog0) quick inet proto tcp from <app_nodes> to 10.10.45.133 port = 9925 no state
pass out log (to pflog0) quick inet proto tcp from <app_nodes> to 10.10.10.101 port { 8230, 8330 } no state

# Comunicación interna entre nodos del clúster, balanceadores y Multicast
pass out log (to pflog0) quick inet proto tcp from { <app_nodes>, <apache_pool> } to <app_nodes>
pass out log (to pflog0) quick inet proto udp from <app_nodes> to 230.0.1.2

# Conexión hacia servidor de respaldos empresariales (IBM Tivoli Storage Manager / TSM)
pass out quick inet proto tcp from 10.10.60.83 to 10.10.60.144 port = 1500 flags any keep state (sloppy)

# Servicios básicos salientes (DNS y NTP)
pass out quick inet proto udp from any to any port { 53, 123 } no state

# ==============================================================================
# 5. Políticas de Bloqueo por Defecto y Auditoría (Monitoreado por script)
# ==============================================================================
block drop in log (to pflog0) inet proto tcp all flags S/SA
block drop out log quick inet proto udp all
