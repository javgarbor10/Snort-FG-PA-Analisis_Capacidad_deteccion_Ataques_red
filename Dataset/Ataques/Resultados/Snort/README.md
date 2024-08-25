     _____                 _____ 
    ( ___ )---------------( ___ )
     |   |                 |   | 
     |   | ╔═╗╔╗╔╔═╗╦═╗╔╦╗ |   | 
     |   | ╚═╗║║║║ ║╠╦╝ ║  |   | 
     |   | ╚═╝╝╚╝╚═╝╩╚═ ╩  |   | 
     |___|                 |___| 
    (_____)---------------(_____)

El apartado de detecciones del IDS Snort sigue el siguiente esquema:

--> CSV: en este subdirectorio se encuentran los CSV que recogen la información de las detecciones ofrecidas por Snort, filtrando los campos de mayor interés. Para cada ataque existen, al menos, dos archivos CSV. El primero tiene el mismo nombre que el pcap asociado y contiene todas las alertas generadas. El segundo, con el sufijo "TP" ha sufrido un filtrado automático de alertas en base a los SIDs de tráfico legítimo. En algunos pcaps podrá encontrar un tercer archivo CSV asociado, con el sufijo "-Manual". Para estos casos, se ha analizado manualmente cuáles de las alertas mostradas en el CSV sin filtrado se corresponden con TP, manteniéndolas y eliminando los FP. Este CSV, por lo general, sólo se encontrará para ataques manejables de no mucho tamaño.

--> Logs: en este subdirectorio se encuentran los ficheros de texto (logs) que recogen las alertas devueltas por el IDS Snort para los distintos ataques implementados. 
Estas alertas se encuentran agrupadas por el paquete de reglas al que pertenecen, pudiendo así establecer la asociación entre SIDs y RuleSets.
