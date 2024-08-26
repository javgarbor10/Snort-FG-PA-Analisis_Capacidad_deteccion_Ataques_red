     +=========================================+
     |██╗  ██╗ ██████╗      ██╗ █████╗ ███████╗|
     |██║  ██║██╔═══██╗     ██║██╔══██╗██╔════╝|
     |███████║██║   ██║     ██║███████║███████╗|
     |██╔══██║██║   ██║██   ██║██╔══██║╚════██║|
     |██║  ██║╚██████╔╝╚█████╔╝██║  ██║███████║|
     |╚═╝  ╚═╝ ╚═════╝  ╚════╝ ╚═╝  ╚═╝╚══════╝|
     +=========================================+

En este directorio se alojan las hojas de cálculo que actúan a modo de Base de Datos, almacenando toda
la información de forma clara, concisa, ordenada y precisa, detallando la detección de cada técnica y relacionando
todos los conceptos entre sí, conformando el culmen del estudio.

A continuación se proporciona una guía para entender la información que se encuentra almacenada en estas hojas de cálculo.

------------ SECCIÓN A.1: VISTA GENERAL HOJA DETECCIONES ------------

Esta hoja concentra numerosos aspectos relacionados con el estudio, divididos en pestañas:
 -> (A) - Reglas Usadas: pestaña con un registro de versiones y agrupación de los paquetes de reglas, así como las versiones de los IDS
 -> (B) - Detecciones - Ataque: esta pestaña contiene dos aspectos de los ataques implementados
  --> Caracterización de pcaps: información variada acerca del ataque implementado, sin relación con los IDS
  --> Resultados de Detecciones: resultados devueltos por los distintos IDS para cada uno de los ataques
 -> (C) - Detecciones - Tráfico Legítimo: similar a la pestaña (B), pero aplicada a las capturas de tráfico legítimo

------------ SECCIÓN A.2: COLUMNAS PESTAÑA (B) HOJA DETECCIONES ------------

Para entender los datos insertados en la pestaña de ataques de la hoja de detecciones, se adjunta una lista de las columnas con su definición.
 -> Táctica: táctica a la que pertenece el ataque
 -> Otras Tácticas: resto de tácticas a las que también pertenece el ataque
 -> ID Táctica: ID de la táctica a la que pertenece el ataque
 -> Técnica: técnica a la que pertenece el ataque
 -> ID Técnica: ID de la técnica a la que pertenece el ataque
 -> Subtécnica: subtécnica a la que pertenece el ataque (puede no tener subtécnica asociada)
 -> ID Subtécnica: ID de la subtécnica a la que pertenece el ataque (puede no tener subtécnica asociada)
 -> Ataque: resumen breve del objetivo del ataque
 -> Herramienta: herramienta/s empleadas para la implementación del ataque
 -> Fichero Pcap: nombre del fichero PCAP que recoge los paquetes generados durante la implementación del ataque
 -> Nº Total de Flujos: número total de flujos en el fichero pcap. Calculado haciendo uso de la herramienta tranalyzer, descartando aquellos flujos que no tienen una Cabecera asociada (descartando así la mayoría de flujos de capa <L3)
 -> Nº de Flujos con Ataque/s: número de flujos que contienen paquetes vinculados al ataque implementado
 -> Nº de Mensajes de Red con Ataque/s: número de mensajes/paquetes que contienen al ataque implementado o parte de él.
 -> Nº de Ataques (Instancias) Totales: número total de instancias de ataque principales y colaterales. Una instancia es la unidad mínima de un ataque, pudiéndose tratar, por ejemplo, de un comando, una inyección SQL o un escaneo a un puerto concreto
 -> Nº de Ataques (Instancias) Principales: número de instancias de ataque en la captura de paquetes
 -> Nº de Ataques (Instancias) Colaterales: número de instancias en la captura de paquetes que constituyen amenaza y pueden generar alertas pero no están relacionadas con el propio ataque en sí.
 -> Detectable por Patrones: SI o NO en función de si el ataque puede o podría ser detectado por patrones por un IDS
 -> Mecanismo de Detección: define el mecanismo usado o que podría usarse para detectar satisfactoriamente el ataque
 -> Detalles de Implementación de Ataque: descripción más extensa del proceso de implementación del ataque. Opcional
 -> Proceso de Generación del Pcap: contiene una referencia donde poder consultar detalladamente el proceso de generación del pcap
 -> Validación de Pcap: contiene una referencia donde poder consultar detalladamente la validación del pcap, analizando los paquetes y comprobando que el ataque verdaderamente se encuentra correctamente capturado
 -> Análisis de Detecciones de Pcap (Snort): contiene una referencia donde poder consultar detalladamente el análisis de detecciones del pcap para el IDS Snort
 -> Formato PCAPNG: ✔ o ✘ en función de si la captura del ataque tiene formato .pcapng
 -> Detectabilidad: SI o NO (con matices) dependiendo de si el ataque es detectable por un IDS
 -> Ataques Colaterales: ✔ o ✘ en función de si la captura de paquetes contiene ataques colaterales
 -> 



 
