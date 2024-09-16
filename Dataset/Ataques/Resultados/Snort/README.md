     +============================================+
     |███████╗███╗   ██╗ ██████╗ ██████╗ ████████╗|
     |██╔════╝████╗  ██║██╔═══██╗██╔══██╗╚══██╔══╝|
     |███████╗██╔██╗ ██║██║   ██║██████╔╝   ██║   |
     |╚════██║██║╚██╗██║██║   ██║██╔══██╗   ██║   |
     |███████║██║ ╚████║╚██████╔╝██║  ██║   ██║   |
     |╚══════╝╚═╝  ╚═══╝ ╚═════╝ ╚═╝  ╚═╝   ╚═╝   |
     +============================================+

El apartado de detecciones del IDS Snort sigue el siguiente esquema:

     --> CSV: en este subdirectorio se encuentran los CSV que recogen la información de las detecciones ofrecidas por Snort, filtrando los campos de mayor interés. Para cada ataque existen, al menos, dos archivos CSV. 
     El primero tiene el mismo nombre que el pcap asociado y contiene todas las alertas generadas. 
     El segundo, con el sufijo "TP" ha sufrido un filtrado automático de alertas en base a los SIDs de tráfico legítimo. 
     En algunos pcaps podrá encontrar un tercer archivo CSV asociado, con el sufijo "-Manual". 
     Para estos casos, se ha analizado manualmente cuáles de las alertas mostradas en el CSV sin filtrado se corresponden con TP, manteniéndolas y eliminando los FP. 
     Este CSV, por lo general, sólo se encontrará para ataques manejables de no mucho tamaño. 
     Como aclaración, si el análisis manual coincide con el automático no encontrará este archivo. En caso de duda puede acudir a la hoja "Detecciones" para comprobar qué ataques no han sido analizados manualmente. 
     Los CSVs siguen la siguiente estructura de columnas:
     
      -> PaqueteReglas: esta columna determina el paquete de reglas al que pertenece la alerta generada. Las opciones son Community (Talos Community), ETOpen, Talos (Talos Registered) y/o ETOpenOpt (ETOpen Optimizado)
      -> SID: SID de la alerta
      -> Detalles: nombre de la alerta, usado para identificar la naturaleza de la misma
      -> Seq: campo Seq de los logs de Snort. Este campo, reconocible como campo Secuencia (Sequence en inglés) sirve para identificar las secuencias flujo+paquete del paquete que genera la alerta.
      -> IPOrigen: dirección IP origen del paquete que genera la alerta
      -> IPDestino: dirección IP destino del paquete que genera la alerta
      -> PrtOrigen: puerto origen del paquete que genera la alerta
      -> PrtDestino: puerto destino del paquete que genera la alerta
      -> IDPaq: identificador de paquete, que identifica de forma unívoca un paquete. Conviene aclrar que el funcionamiento de este campo no viene documentado, y aunque a priori pueda parecer que cada paquete individual tiene un IDPaq distinto, en ciertos casos, si dos paquetes son idénticos, este campo podría repetirse, aunque se traten de paquetes separados.
      
     
     
     --> Logs: en este subdirectorio se encuentran los ficheros de texto (logs) que recogen las alertas devueltas por el IDS Snort para los distintos ataques implementados. 
     Estas alertas se encuentran agrupadas por el paquete de reglas al que pertenecen, pudiendo así establecer la asociación entre SIDs y RuleSets.
