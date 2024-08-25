    +=======================================================================+
    |███████╗ ██████╗ ██████╗ ████████╗██╗ ██████╗  █████╗ ████████╗███████╗|
    |██╔════╝██╔═══██╗██╔══██╗╚══██╔══╝██║██╔════╝ ██╔══██╗╚══██╔══╝██╔════╝|
    |█████╗  ██║   ██║██████╔╝   ██║   ██║██║  ███╗███████║   ██║   █████╗  |
    |██╔══╝  ██║   ██║██╔══██╗   ██║   ██║██║   ██║██╔══██║   ██║   ██╔══╝  |
    |██║     ╚██████╔╝██║  ██║   ██║   ██║╚██████╔╝██║  ██║   ██║   ███████╗|
    |╚═╝      ╚═════╝ ╚═╝  ╚═╝   ╚═╝   ╚═╝ ╚═════╝ ╚═╝  ╚═╝   ╚═╝   ╚══════╝|
    +=======================================================================+

El apartado de detecciones del IDS FortiGate sigue el siguiente esquema:

--> CSV: el contenido de estos archivos se corresponde exclusivamente con las alertas generadas por FortiGate (aquellas líneas del log que disponen del campo "attackid" indicando que ha existido correlación de un paquete con un registro de ataque basado en firmas). Para estas alertas se han filtrado los campos de mayor interés. Si para un ataque determinado no existe su correspondiente fichero CSV, se concluye que dicho ataque no ha generado ninguna alerta asociada a amenazas.

--> Logs: dentro de este directorio se encuentran ficheros de texto (logs) que recogen las salidas generadas por FortiGate tras reproducir las capturas de paquetes en el entorno de detección. Las líneas de estos ficheros contienen información vinculada al ataque, relacionada con el propio tráfico, aplicaciones usadas y alertas basadas en firmas.
