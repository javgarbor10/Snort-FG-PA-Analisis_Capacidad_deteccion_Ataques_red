     _____              _____ 
    ( ___ )------------( ___ )
     |   |              |   | 
     |   | ╔╗ ╔╗ ╔╦╗╔╦╗ |   | 
     |   | ╠╩╗╠╩╗ ║║ ║║ |   | 
     |   | ╚═╝╚═╝═╩╝═╩╝ |   | 
     |___|              |___| 
    (_____)------------(_____)

Este directorio es alternativo al directorio "Hojas". En lugar de proporcionar hojas
de cálculo para la representación de los datos se ofrecen ficheros csv y scripts sql
que permiten reconstruir una base de datos local con la que manejar toda la información
del estudio.

IMPLEMENTACIÓN CON HyperSQL y GUI HyperSQL Database Manager Swing

1º) Descarga de ficheros
2º) Puesta en marcha del servidor en la carpeta /lib con comando "java -cp hsqldb.jar org.hsqldb.server.Server --database.0 file:tfg  --dbname.0 tfg"
3º) Arranque de la interfáz gráfica (GUI) con el comando "java -cp hsqldb.jar org.hsqldb.util.DatabaseManagerSwing"
4º) Conexión a la BBDD. Dirección hsql://localhost/tfg
5º) Preparación de las tablas. Carga del script "tablas.sql" y ejecución. 
6º) Inserción de los datos. Carga del script "datos.sql" y ejecución.
7º) Indagación libre: la BBDD debería estar completamente activa y operativa en este punto. Puede realizar todas las consultas que precise para recoger los datos.
