     _____                 _____ 
    ( ___ )---------------( ___ )
     |   |                 |   | 
     |   | ╔═╗╔╗╔╔═╗╦═╗╔╦╗ |   | 
     |   | ╚═╗║║║║ ║╠╦╝ ║  |   | 
     |   | ╚═╝╝╚╝╚═╝╩╚═ ╩  |   | 
     |___|                 |___| 
    (_____)---------------(_____)

El apartado de detecciones del IDS Snort sigue el siguiente esquema:

--> CSV: en este subdirectorio se encuentran los CSV que recogen la información de las detecciones ofrecidas por Snort, filtrando los campos de mayor interés

--> Logs: en este subdirectorio se encuentran los ficheros de texto (logs) que recogen las alertas devueltas por el IDS Snort para los distintos ataques implementados. 
Estas alertas se encuentran agrupadas por el paquete de reglas al que pertenecen, pudiendo así establecer la asociación entre SIDs y RuleSets.
