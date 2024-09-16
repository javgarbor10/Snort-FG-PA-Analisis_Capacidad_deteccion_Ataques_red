    +=======================================================================+
    |███████╗ ██████╗ ██████╗ ████████╗██╗ ██████╗  █████╗ ████████╗███████╗|
    |██╔════╝██╔═══██╗██╔══██╗╚══██╔══╝██║██╔════╝ ██╔══██╗╚══██╔══╝██╔════╝|
    |█████╗  ██║   ██║██████╔╝   ██║   ██║██║  ███╗███████║   ██║   █████╗  |
    |██╔══╝  ██║   ██║██╔══██╗   ██║   ██║██║   ██║██╔══██║   ██║   ██╔══╝  |
    |██║     ╚██████╔╝██║  ██║   ██║   ██║╚██████╔╝██║  ██║   ██║   ███████╗|
    |╚═╝      ╚═════╝ ╚═╝  ╚═╝   ╚═╝   ╚═╝ ╚═════╝ ╚═╝  ╚═╝   ╚═╝   ╚══════╝|
    +=======================================================================+

El apartado de detecciones del IDS FortiGate sigue el siguiente esquema:

    --> CSV: el contenido de estos archivos se corresponde exclusivamente con las alertas generadas por FortiGate (aquellas líneas del log que disponen del campo "attackid" indicando que ha existido correlación de un paquete con un registro de ataque basado en firmas). 
    Para estas alertas se han filtrado los campos de mayor interés. 
    Si para un ataque determinado no existe su correspondiente fichero CSV, se concluye que dicho ataque no ha generado ninguna alerta asociada a amenazas. 
    El formato de los ficheros CSV se basa en las siguientes columnas:

     -> attackid / virusid: esta columna contiene el identificador de la alerta generada por FortiGate
     -> sessionid: esta columnna contiene el valor del campo sessionid de los logs de FortiGate, asociado a la creación de un flujo en el sistema de detección
     -> repeated: en los logs de FG, es común apreciar en determinadas ocasiones la presencia de la cadena "repeated n times" en el campo "msg". Cuando las alertas se repiten el sistema de detección de FG está preparado para agrupar estas alertas (así no se aumenta innecesariamente el tamaño del log). Esto ocurre sólo cuando los paquetes que generan la alerta comparten flujo. Así, esta columna contiene el valor de dicho campo (en caso de que exista).
     -> severity: campo que indica el grado de severidad o gravedad de la alerta
     -> attack / virus: campo que detalla el nombre de la alerta, para entender su naturaleza
     -> service: servicio (normalmente protocolo de L5) del paquete que genera la alerta. Si no se reconoce el servicio suele aparecer el protocolo de L4 seguido del puerto destino del paquete
     -> srcip: dirección IP origen del paquete que genera la alerta
     -> dstip: dirección IP destino del paquete que genera la alerta
     -> subtype: subtipo de la alerta. Por lo general este campo tomará como valor "ips".
     -> eventtype: tipo de evento de la alerta. Por lo general, este campo tomará como valor "signature", pues las alertas se basan en firmas.
     -> url: dependiendo del ataque es posible o no encontrar este campo. Para ataques basados en URLs, este campo indica la URL objetivo del paquete que genera la alerta.
    
    --> Logs: dentro de este directorio se encuentran ficheros de texto (logs) que recogen las salidas generadas por FortiGate tras reproducir las capturas de paquetes en el entorno de detección. Las líneas de estos ficheros contienen información vinculada al ataque, relacionada con el propio tráfico, aplicaciones usadas y alertas basadas en firmas.
