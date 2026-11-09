## =====================================================================
## CONFIGURACIÓN DE POOLS DE IP (IPPOOL) - SOLARIS 10
## Ruta etcipfippool.conf
## =====================================================================

# Pool 11 Soporte UNIX
table role = ipf type = tree number = 11 ´{
    10.10.50.11, 
    10.10.50.15,
    10.10.50.48
};

# Pool 12 Servidores de Bases de Datos Centrales
table role = ipf type = tree number = 12  { 
    10.10.50.172, 
    10.10.50.24, 
    10.10.50.148, 
    10.10.50.17 
};

# Pool 18 Pasarela de Pagos Externa
table role = ipf type = tree number = 18  { 
    10.10.50.6032, 
    10.10.30.10132, 
    10.10.20.17332, 
    10.20.10.3532 
};

# Pool 19 Plataforma Web Externa
table role = ipf type = tree number = 19  { 
    10.10.60.232, 
    10.10.40.2732, 
    10.10.40.2832, 
    10.20.10.3532 
};