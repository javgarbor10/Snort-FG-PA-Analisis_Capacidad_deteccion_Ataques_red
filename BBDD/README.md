     +================================+
     |██████╗ ██████╗ ██████╗ ██████╗ |
     |██╔══██╗██╔══██╗██╔══██╗██╔══██╗|
     |██████╔╝██████╔╝██║  ██║██║  ██║|
     |██╔══██╗██╔══██╗██║  ██║██║  ██║|
     |██████╔╝██████╔╝██████╔╝██████╔╝|
     |╚═════╝ ╚═════╝ ╚═════╝ ╚═════╝ |
     +================================+

Este directorio es alternativo al directorio "Hojas". En lugar de proporcionar hojas
de cálculo para la representación de los datos se ofrecen ficheros csv y scripts sql
que permiten reconstruir una base de datos de forma local con la que manejar toda la información
del estudio, además de scripts que facilitan el manejo de los elementos.

A continuación se proporciona una guía de los elementos disponibles en este directorio así como los pasos para la replicación de la BBDD

     ------- SECCIÓN A: FICHEROS INVOLUCRADOS -------
     
     1 - Scripts SQL (Directorio "/SQL")
      --> tablas.sql: contiene la definición de la estructura de las tablas
      --> views.sql: contiene la definición de la estructura de las vistas
      --> datos.sql: contiene la inserción de los datos en las tablas (IMPORTANTE - ajustar manualmente los directorios 
     2 - CSVs (Directorio "/CSV")
      --> alertas_ataque_fortigate.csv, alertas_ataque_snort.csv, alertas_ataque_paloalto.csv 
      --> caracterizacion_pcaps_ataque.csv, caracterizacion_pcaps_legitimo.csv 
      --> deteccion_snort.csv, deteccion_fortigate.csv, deteccion_paloalto.csv
      --> alertas_legitimo_snort.csv
      --> Adicionalmente dispone de los ficheros Excel originales a partir de los cuales se extraen los CSV finales. Ocasionalmente podría experimentar errores de formato según condiciones de sistema operativo, tecnología de BBDD empleada, etc., por lo que se recomienda tener estos ficheros en caso de problema. Con el uso de los scripts puede obtener los CSV a partir de estos ficheros en formato Excel.
     3 - Scripts (Directorio "/Scripts")
      --> csv_comas.py: en ciertos sistemas operativos, los ficheros CSV tienen un formato de separación de celdas basada en punto y coma, en vez de coma. Para evitar errores sintácticos y separaciones no deseadas este script convierte un csv con separación de punto y coma en uno con separación de comas
      --> transformaAlertasFG.py: este script se encarga de adaptar el formato de las alertas generadas por FortiGate en la hoja "Detecciones" al formato de las tablas de la BBDD
      --> trasnformaAlertasv2.py: este script se encarga de adaptar el formato de las alertas generadas por Snort en la hoja "Detecciones" al formato de las tablas de la BBDD
               
     ------- SECCIÓN B: IMPLEMENTACIÓN CON HyperSQL y GUI HyperSQL Database Manager Swing ------
               
     1º) Descarga de ficheros (preferiblemente en la carpeta /lib del directorio de instalación de hsqldb)
     2º) Puesta en marcha del servidor en la carpeta /lib con comando "java -cp hsqldb.jar org.hsqldb.server.Server --database.0 file:tfg  --dbname.0 tfg"
     3º) Arranque de la interfáz gráfica (GUI) con el comando "java -cp hsqldb.jar org.hsqldb.util.DatabaseManagerSwing"
     4º) Conexión a la BBDD. Dirección hsql://localhost/tfg
     5º) Preparación de las tablas. Carga del script "tablas.sql" y ejecución. 
     6º) Inserción de los datos. Carga del script "datos.sql" y ejecución.
     7º) Indagación libre: la BBDD debería estar completamente activa y operativa en este punto. Puede realizar todas las consultas que precise para recoger los datos.

     Puede acceder a los siguientes enlaces para indagar en el funcionamiento concreto de la BBDD:
     - Puesta en Marcha y Prueba: https://youtu.be/4IGI93Z41Z8
     - Estructura: https://youtu.be/IHG9tnVEfLU

