## =====================================================================
## REGLAS DE FILTRADO IPFILTER (IPF) - SOLARIS 10
## Ruta: /etc/ipf/ipf.conf
## =====================================================================

## =====================================================================
## REGLAS: ACCESO A SOPORTE UNIX
## =====================================================================
# Acceso administrativo SSH por roles autorizados (Gestionado vía Pool 11)
pass in quick proto tcp from pool/11 to 192.0.2.100 port = 22

## =====================================================================
## REGLAS DE TRÁFICO ENTRANTE (INBOUND)
## =====================================================================

# DNS (UDP 53)
pass in quick inet proto udp from any to any port = 53
block drop in quick inet proto udp from any to any port = 53

## =====================================================================
## REGLAS: MONITOREO NAGIOS
## =====================================================================
# Monitoreo SNMP (UDP 161) y Chequeos HTTP (TCP 80, 443) desde el servidor Nagios
pass in quick inet proto udp from 10.10.10.180 to any port = 161 keep state
pass in quick proto tcp from 10.10.10.180 to pool/12 port = 80
pass in quick proto tcp from 10.10.10.180 to pool/12 port = 443

## ---------------------------------------------------------------------
## REGLAS: PASARELA DE PAGOS & WEB EXTERNA
## ---------------------------------------------------------------------

# Tráfico TCP hacia API de Proveedor Externo (Puertos Transaccionales)
pass in quick proto tcp from 10.10.20.208 to 192.0.2.100 port = 9700
pass in quick proto tcp from pool/18 to 192.0.2.100 port = 8430

pass out quick proto tcp from 10.10.20.208 to 192.0.2.100 port = 9700
pass out quick proto tcp from pool/18 to 192.0.2.100 port = 8430

# Interconexión con Plataforma Web Core
pass in quick proto tcp from pool/18 to 10.10.20.208 port = 8430
pass out quick proto tcp from pool/18 to 10.10.20.208 port = 8430

## ---------------------------------------------------------------------
## REGLAS: ACCESO A BASES DE DATOS (Servidores de Aplicaciones)
## ---------------------------------------------------------------------

# Acceso a clúster de Base de Datos Estándar (Puerto 1521)
pass out log quick proto tcp from 10.20.30.111 to pool/12 port = 1521
pass out log quick proto tcp from 10.20.30.112 to pool/12 port = 1521

# Acceso a Base de Datos de Canales Digitales (Puerto 2023)
pass out log quick proto tcp from 10.20.30.111 to 10.10.50.29 port = 2023
pass out log quick proto tcp from 10.20.30.112 to 10.10.50.29 port = 2023

# Acceso a Base de Datos de Compensación Financiera (Puerto 1522)
pass out log quick proto tcp from 10.20.30.111 to 10.10.50.110 port = 1522
pass out log quick proto tcp from 10.20.30.112 to 10.10.50.110 port = 1522

# Acceso a Base de Datos de Sistema de Auditoría (Puerto 1524)
pass out log quick proto tcp from 10.20.30.111 to 10.10.50.131 port = 1524
pass out log quick proto tcp from 10.20.30.112 to 10.10.50.131 port = 1524

# Acceso a Aplicación de Seguridad de Producción (Multi-puerto)
pass out log quick proto tcp from 10.20.30.111 to 10.10.60.151 port { 8051, 8053, 8059, 8061 }
pass out log quick proto tcp from 10.20.30.112 to 10.10.60.151 port { 8051, 8053, 8059, 8061 }

# Acceso a Servicio de Middleware Operativo (Puerto 30000)
pass out log quick proto tcp from 10.20.30.111 to 10.10.60.42 port = 30000
pass out log quick proto tcp from 10.20.30.112 to 10.10.60.42 port = 30000

# Acceso a APIs de Aplicación Móvil y Sistema de Referencias (Puerto 8330)
pass out log quick proto tcp from 10.20.30.111 to 10.10.20.101 port = 8330
pass out log quick proto tcp from 10.20.30.112 to 10.10.20.101 port = 8330

# Acceso a Servicio de Gestión de Contratos Digitales (Puerto 8230)
pass out log quick proto tcp from 10.20.30.111 to 10.10.20.101 port = 8230
pass out log quick proto tcp from 10.20.30.112 to 10.10.20.101 port = 8230

## =====================================================================
## POLÍTICAS DE BLOQUEO POR DEFECTO (Estrategia Default-Deny)
## =====================================================================
# Corrección: Se elimina '(to pflog0)' por ser incompatible con Solaris IPF.
# Los bloqueos se registran nativamente en el subsistema de logs 'ipmon'.

block drop in log quick inet proto tcp all flags S/SA
block drop out log quick inet proto udp all

