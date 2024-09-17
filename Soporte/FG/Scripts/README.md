    +====================================================+
    |███████╗ ██████╗██████╗ ██╗██████╗ ████████╗███████╗|
    |██╔════╝██╔════╝██╔══██╗██║██╔══██╗╚══██╔══╝██╔════╝|
    |███████╗██║     ██████╔╝██║██████╔╝   ██║   ███████╗|
    |╚════██║██║     ██╔══██╗██║██╔═══╝    ██║   ╚════██║|
    |███████║╚██████╗██║  ██║██║██║        ██║   ███████║|
    |╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝╚═╝        ╚═╝   ╚══════╝|
    +====================================================+

En este directorio se encuentran los scripts que intervienen en la detección de FortiGate.

Para poder entender su funcionamiento se proporciona la siguiente guía.

    ----- GUÍA DE FUNCIONAMIENTO DE SCRIPTS DE FORTIGATE -----

    -> fg.sh: desarrollado en Shell, este script se encarga de la reproducción de las capturas de paquetes (pcaps) en el entorno FortiGate. El procedimiento completo comienza con el cálculo de la PRIMERA LINEA. Debido a que el log de salida de las detecciones de FortiGate es compartido, resulta necesario en una primera instancia establecer un punto de inicio para evitar colisiones. Posteriormente, se reproducen los paquetes en la interfaz adecuada, y se espera el tiempo apropiado para permitir el volcado total de las alertas. Tras eso, se repiten los pasos una segunda vez, para comprobar de manera fiable si no se ha omitido ninguna alerta o si la primera ejecución fue irregular. Por último, se comprueba si ambos logs han generado el mismo número de alertas y se procede a eliminar el pcap del directorio. Está integrado con expect para poder reproducir paquetes y extraer logs de forma automática, sin que sea necesaria la intervención del usuario
    
    -> fortigatev2.sh: desarrollado en Shell, este script permite ir traspasando progresivamente los ficheros pcap a analizar al host de reproducción. Una vez realiza un traspaso, llama al script fg.sh, alojado en el host, y recoge el log de salida y lo introduce en la carpeta de logs del cliente
    
    -> run_tcpreplay.expect: desarrollado en expect, este script permite introducir la contraseña para la reproducción de paquetes de forma automática, sin que el usuario tenga que intervenir

    -> transformaCSV.py: desarrollado en Python, este script se encarga de la última parte del proceso completo de generación y recolección de los logs. Su función es la de transformar los logs (que contienen una gran variedad de alertas) en un CSV con las alertas filtradas a tan sólo las que hacen referencia a amenazas. Especificando a nivel de código, se atiende tan sólo a aquellas lineas que contienen la cadena "attackid". Tras efectuar el filtrado se agrupan los valores de cada uno de los campos de interés y se elabora el fichero CSV, en el que se insertan todos los datos

    -> transformaCSVv4-VIRUS.py: desarrollado en Python, integra los ataques basados en virus. Para este estudio tan sólo el ataque T1105-Ingress_Transfer_Tool_[5].pcapng incluye esta categoría de ataques. Este script busca, además de los campos característicos de los ataques corrientes de IPS, los asociados a virus, (virusid y virus).

    -> recuentaFlujosTotales.py: desarrollado en Python, este script cuenta el número total de flujos en el log, atendiendo al campo sessionid

    -> recuentaFlujosDetectados.py: desarrollado en Python, este script cuenta el número total de flujos detectados (flujos para los que existen lineas con attackid) en el log
