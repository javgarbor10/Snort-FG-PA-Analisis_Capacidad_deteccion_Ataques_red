    +================================================================+
    |██████╗  █████╗ ██╗      ██████╗  █████╗ ██╗  ████████╗ ██████╗ |
    |██╔══██╗██╔══██╗██║     ██╔═══██╗██╔══██╗██║  ╚══██╔══╝██╔═══██╗|
    |██████╔╝███████║██║     ██║   ██║███████║██║     ██║   ██║   ██║|
    |██╔═══╝ ██╔══██║██║     ██║   ██║██╔══██║██║     ██║   ██║   ██║|
    |██║     ██║  ██║███████╗╚██████╔╝██║  ██║███████╗██║   ╚██████╔╝|
    |╚═╝     ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═╝  ╚═╝╚══════╝╚═╝    ╚═════╝ |
    +================================================================+

El apartado de detecciones del IDS PaloAlto NGFW sigue el siguiente esquema:

--> CSV: el contenido de estos archivos se corresponde exclusivamente con las alertas generadas por PaloAlto (aquellas líneas del log que disponen del campo "threat_id" indicando que ha existido correlación de un paquete con un registro de ataque basado en firmas). Para estas alertas se han filtrado los campos de mayor interés. Si para un ataque determinado no existe su correspondiente fichero CSV, se concluye que dicho ataque no ha generado ninguna alerta asociada a amenazas.

--> Logs: dentro de este directorio se encuentran ficheros de texto (logs) que recogen las salidas generadas por PaloAlto tras reproducir las capturas de paquetes en el entorno de detección. Las líneas de estos ficheros contienen información vinculada al ataque, relacionada con el propio tráfico, aplicaciones usadas y alertas basadas en firmas.

Se puede observar que existen dos ficheros para cada técnica. Esto es debido a que el entorno de PaloAlto es complejo y al analizar diferentes técnicas puede llegar a generar diferentes alertas para un mismo fichero. Por tanto, utilizando un método detallado en la memoria de PaloAlto, se utilizó como requisito tener 2 ficheros de logs con el mismo número de alertas.
