    +====================================================+
    |███████╗ ██████╗██████╗ ██╗██████╗ ████████╗███████╗|
    |██╔════╝██╔════╝██╔══██╗██║██╔══██╗╚══██╔══╝██╔════╝|
    |███████╗██║     ██████╔╝██║██████╔╝   ██║   ███████╗|
    |╚════██║██║     ██╔══██╗██║██╔═══╝    ██║   ╚════██║|
    |███████║╚██████╗██║  ██║██║██║        ██║   ███████║|
    |╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝╚═╝        ╚═╝   ╚══════╝|
    +====================================================+

En este directorio se encuentran los scripts que intervienen en la detección de PaloAlto.

Para poder entender su funcionamiento se proporciona la siguiente guía.

    ----- GUÍA DE FUNCIONAMIENTO DE SCRIPTS DE PALOALTO -----

    -> paloaltoHostv4.sh: desarrollado en Shell, este script se encarga del envío de las capturas de paquetes al equipo preparado para la reproducción de paquetes y de la recolección de los logs. La metodología es la siguiente. El script envía un pcap del directorio y accede vía ssh al equipo marcado con la dirección IP designada para ejecutar el script "PA.sh". Una vez se ejecuta este segundo script se extrae el log y se modifica el nombre para que coincida con el de la captura de paquetes.

    -> PA.sh: desarrollado en Shell, este script se encarga de la reproducción de las capturas de paquetes (pcaps) en el entorno PaloAlto. El procedimiento completo comienza con el cálculo de la PRIMERA LINEA. Debido a que el log de salida de las detecciones de PaloAlto es compartido, resulta necesario en una primera instancia establecer un punto de inicio para evitar colisiones. Posteriormente, se reproducen los paquetes en la interfaz adecuada, y se espera el tiempo apropiado para permitir el volcado total de las alertas en el fichero de log. Tras eso, se repiten los pasos una segunda vez, para comprobar de manera fiable si no se ha omitido ninguna alerta o si la primera ejecución fue irregular. Por último, se comprueba si ambos logs han generado el mismo número de alertas y se procede a eliminar el pcap del directorio.

    -> log_to_excel_CSV.py: desarrollado en Python, este script se encarga de la última parte del proceso completo de generación y recolección de los logs. Su función es la de transformar los logs (que contienen una gran variedad de alertas) en un CSV con las alertas filtradas a tan sólo las que hacen referencia a amenazas. Especificando a nivel de código, se atiende tan sólo a aquellas lineas que contienen la cadena "THREAT". Tras efectuar el filtrado se agrupan los valores de cada uno de los campos de interés y se elabora el fichero CSV, en el que se insertan todos los datos

    -> log_to_excel.py: desarrollado en Python, este script enumera cada una de las alertas de tipo "TRAFFIC" y tipo "THREAT" en un fichero de Excel. Además, muestra información adicional sobre las amenazas
    y hace un recuento del número total de alertas, teniendo en cuenta el campo repeatcnt y el número total de alertas tipo "TRAFFIC".

    -> calcula_flujos_log.py: desarrollado en Python, este script cuenta el número total de flujos detectados en el log. Previo a la ejecución de este script debe haberse usado log_to_excel.py

    -> calcula_flujos_log_THREAT.py: desarrollado en Python, este script cuenta el número total de flujos detectados de ataque. Es decir, solamente tiene en cuenta aquellas líneas con la cadena "THREAT". Previamente debe haberse ejecutado log_to_excel.py

