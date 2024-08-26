    +====================================================+
    |███████╗ ██████╗██████╗ ██╗██████╗ ████████╗███████╗|
    |██╔════╝██╔════╝██╔══██╗██║██╔══██╗╚══██╔══╝██╔════╝|
    |███████╗██║     ██████╔╝██║██████╔╝   ██║   ███████╗|
    |╚════██║██║     ██╔══██╗██║██╔═══╝    ██║   ╚════██║|
    |███████║╚██████╗██║  ██║██║██║        ██║   ███████║|
    |╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝╚═╝        ╚═╝   ╚══════╝|
    +====================================================+

En este directorio se encuentran los scripts que intervienen en la detección de Snort.

Para poder entender su funcionamiento se proporciona la siguiente guía.

    ----- GUÍA DE FUNCIONAMIENTO DE SCRIPTS DE SNORT -----

    -> analisis_snortvX.py: estos scripts tienen como finalidad principal elaborar un log resultante para cada pcap analizado, que condense las alertas generadas para los distintos paquetes de reglas. La versión 5 (la más reciente y la realmente operativa) realiza las siguientes tareas:
     --> Detecciones: el script realiza las detecciones del ataque para todos los RuleSets disponibles.
     --> Alertas: el script almacena tanto la salida estándar de las detecciones (fichero de texto "salida") como todas las alertas generadas (carpeta /DETECCIONES).
     --> CSV: para mayor accesibilidad visual, el script también transforma las alertas en formato de log a formato CSV (carpeta /CSV)
     --> Contaje: para recolectar resultados el script también lleva a cabo un recuento automático de los flujos, mensajes e instancias detectadas por Snort, para cada uno de los RuleSets. ¡IMPORTANTE! El apartado de flujos no se usa, pues el cálculo no está bien desarrollado. El resto de datos son válidos. Mensajes e instancias se calculan a partir del campo 'IDPaq', identificable en los logs de ambas versiones de Snort.

    -> analiza_snort.sh: script obsoleto, pero capaz de realizar las detecciones para los ataques. Incluye la funcionalidad de llamar al script sacarreglas.py. Desarrollado en Shell.

    -> calculaFlujos.py: script utilizado para el recuento de flujos de un fichero .pcapng. Para el cálculo hace uso de la herramnienta tranalyzer y tras transformar los resultados en un CSV comprueba el número de flujos distintos que tienen una cabecera válida (campo hdrDesc).

    -> extrae_sid.py: script obsoleto pero operativo. Puede ser usado en determinados contextos de la detección para extraer únicamente los SIDs.

    -> filtradoTPv4.py: script vinculado al script hermano "analisis_snortv5.py". Este script accede al CSV generado por el otro script, y filtra las alertas en base a los SIDs que se pasan como argumento. Usado fundamentalmente para el análisis automático, pues permite discriminar las alertas que comparten SID con el tráfico legítimo.

    -> sacarreglas.py: script que extrae de un log de salida de Snort el número de alertas distintas y el número total de alertas, atendiendo al marcador [**] que distingue las alertas de ataque del resto de lineas.

    -> sacasids.py: script que extrae de un fichero de texto (preferiblemente un fichero ordenado con la lista de alertas) los SIDs. Devuelve la lista en formato SID, SID, SID, útil para la representación en la hoja "Detecciones".

    -> une_sids.py: script usado para la unión de SIDs de diferentes logs.

    -> deteccionSYN/detector_syn.sh: este script está elaborado para efectuar un análisis de flujos con tranalyzer para los pcaps que se encuentren en el mismo directorio de ejecución. Está pensado para tan sólo generar los ficheros de texto necesarios para el estudio de flujos truncados.

    -> deteccionSYN/txt_to_csv.py: este script convierte los ficheros de texto generados por el script "detector_syn.sh" en CSVs.

    -> deteccionSYN/checkSYN.py: este script acude a los ficheros CSV generados por el script "txt_to_csv.py" y comprueba si alguno de los flujos está truncado. Para ello, analiza las banderas de las sesiones TCP en busca de coincidencias que alerten de un flujo incompleto. Como resultado, se crea un CSV final con los flujos truncados. Si este CSV se encuentra vacío, el ataque no contiene ningún flujo truncado.

    -> deteccionSYN/script_deteccion_falta_SYN.py: este script engloba la tarea de los tres scripts anteriores

    
