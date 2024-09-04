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
      -> (D) - Análisis Resultados I - Snort: gráficas y análisis de resultados relativos al IDS Snort. Es posible encontrar información extraída de otras pestañas de esta misma hoja
      -> (D) - Análisis Resultados II - FortiGate: gráficas y análisis de resultados relativos al IDS FortiGate. Es posible encontrar información extraída de otras pestañas de esta misma hoja
      -> (D) - Análisis Resultados III - PaloAlto: gráficas y análisis de resultados relativos al IDS PaloAlto. Es posible encontrar información extraída de otras pestañas de esta misma hoja
      -> (D) - Análisis Resultados IV - Conjunto: gráficas y análisis de resultados relativos a todos los IDS. Es posible encontrar información extraída de otras pestañas de esta misma hoja
      -> (E) - Referencias: esta pestaña contiene un breve anexo con la leyenda de la procedencia de los pcaps. En la pestaña (B) existen varias columnas relacionadas con la caracterización de los pcaps con referencias como valores. Estas referencias se encuentran detalladas en esta pestaña
     
     ------------ SECCIÓN A.2: COLUMNAS PESTAÑA (B) HOJA DETECCIONES ------------
     
     Para entender los datos insertados en la pestaña de ataques de la hoja de detecciones, se adjunta una lista de las columnas con su definición.
      -> TÁCTICA: táctica a la que pertenece el ataque
      -> OTRAS TÁCTICAS: resto de tácticas a las que también pertenece el ataque
      -> ID TÁCTICA: ID de la táctica a la que pertenece el ataque
      -> TÉCNICA: técnica a la que pertenece el ataque
      -> ID TÉCNICA: ID de la técnica a la que pertenece el ataque
      -> SUBTÉCNICA: subtécnica a la que pertenece el ataque (puede no tener subtécnica asociada)
      -> ID SUBTÉCNICA: ID de la subtécnica a la que pertenece el ataque (puede no tener subtécnica asociada)
      -> ATAQUE: resumen breve del objetivo del ataque
      -> HERRAMIENTA: herramienta/s empleadas para la implementación del ataque
      -> FICHERO PCAP: nombre del fichero PCAP que recoge los paquetes generados durante la implementación del ataque
      -> Nº TOTAL DE FLUJOS: número total de flujos en el fichero pcap. Calculado haciendo uso de la herramienta tranalyzer, descartando aquellos flujos que no tienen una Cabecera asociada (descartando así la mayoría de flujos de capa <L3)
      -> Nº DE FLUJOS CON ATAQUE/S: número de flujos que contienen paquetes vinculados al ataque implementado
      -> Nº DE MENSAJES DE RED CON ATAQUE/S: número de mensajes/paquetes que contienen al ataque implementado o parte de él.
      -> Nº DE ATAQUES (INSTANCIAS) TOTALES: número total de instancias de ataque principales y colaterales. Una instancia es la unidad mínima de un ataque, pudiéndose tratar, por ejemplo, de un comando, una inyección SQL o un escaneo a un puerto concreto
      -> Nº DE ATAQUES (INSTANCIAS) PRINCIPALES: número de instancias de ataque en la captura de paquetes
      -> Nº DE ATAQUES (INSTANCIAS) COLATERALES: número de instancias en la captura de paquetes que constituyen amenaza y pueden generar alertas pero no están relacionadas con el propio ataque en sí.
      -> DETECTABLE POR PATRONES: SI o NO en función de si el ataque puede o podría ser detectado por patrones por un IDS
      -> MECANISMO DE DETECCIÓN: define el mecanismo usado o que podría usarse para detectar satisfactoriamente el ataque
      -> DETALLES DE IMPLEMENTACIÓN DE ATAQUE: descripción más extensa del proceso de implementación del ataque. Opcional
      -> PROCESO DE GENERACIÓN DE PCAP: contiene una referencia donde poder consultar detalladamente el proceso de generación del pcap
      -> VALIDACIÓN DE PCAP: contiene una referencia donde poder consultar detalladamente la validación del pcap, analizando los paquetes y comprobando que el ataque verdaderamente se encuentra correctamente capturado
      -> ANÁLISIS DE DETECCIONES DE PCAP (Snort): contiene una referencia donde poder consultar detalladamente el análisis de detecciones del pcap para el IDS Snort
      -> FORMATO PCAPNG: ✔ o ✘ en función de si la captura del ataque tiene formato .pcapng
      -> DETECTABILIDAD: SI o NO (con matices) dependiendo de si el ataque es detectable por un IDS
      -> ATAQUES COLATERALES: ✔ o ✘ en función de si la captura de paquetes contiene ataques colaterales
      -> VERIFICACIÓN MTU MÁXIMA: ✔ o ✘ en función de si la captura de paquetes ha sufrido el ajuste de MTU para los entornos de los IDS
      -> ERROR TCP_Replay: ✔ o ✘ en función de si la captura de paquetes ha devuelto errores en la reproducción de paquetes dentro de los entornos de los IDS
      -> CONTIENE SÓLO FLUJOS COMPLETOS CON SYN INICIAL: ✔ o ✘ en función de si la captura de paquetes tan sólo contiene flujos completos, es decir, no incluye flujos truncados
      -> SIDs (sin repetición): para cada RS de Snort, esta sección enumera los SIDs de las alertas devueltos por Snort para el RuleSet correspondiente
      -> #SIDs: para cada RS de Snort, número de SIDs diferentes de las alertas devueltos por Snort para el RuleSet correspondiente
      -> Número total de alertas: para cada RS de Snort, número total de alertas (con repetición) generadas por Snort para el RuleSet correspondiente.
      -> SIDs en legítimo y ataque: para cada RS de Snort, SIDs que aparecen tanto en las detecciones de tráfico legítimo como en el propio ataque
      -> SIDs sólo en ataque: para cada RS de Snort, SIDs que sólo aparecen en las detecciones del ataque
      -> SIDs FP (Manual): para cada RS de Snort, SIDs que manualmente han sido calificados como FP, ya sea por tratarse de simples eventos de red o por no estar relacionados
      -> SIDs FP (Automático): para cada RS de Snort, SIDs que aparecen en tráfico legítimo y que se usan para la metodología automática para calificar los SIDs del ataque como FP
      -> SIDs FP: para cada RS de Snort, contendrá los SIDs de la columna "SIDs FP (Manual)" si esta no es igual a "-". En tal caso (no se ha realizado el análisis manual) contendrá los SIDs de la columna "SIDs FP (Automático)"
      -> SIDs FP "No Relacionados": para cada RS de Snort, contendrá los SIDs que han sido considerados de forma manual como No Relacionados
      -> SIDs FP "Eventos de Red": para cada RS de Snort, contendrá los SIDs que han sido considerados de forma manual como Eventos de Red
      -> SIDs TP "Todas las Alertas" (Manual): para cada RS de Snort, SIDs que manualmente se ha comprobado que siempre son TP
      -> SIDs TP "Algunas Alertas" (Manual): para cada RS de Snort, SIDs que manualmente se ha comprobado que en ocasiones son TP y en otras FP
      -> Nº TOTAL DE FLUJOS DETECTADOS SNORTv3: para el RS1 y RS3, número de flujos totales analizados por Snortv3
      -> Nº TOTAL DE FLUJOS DETECTADOS SNORTv2: para cada RS2 y RS4 de Snort, número de flujos totales analizados por Snortv2
      -> Nº TOTAL DE FLUJOS CON ATAQUE/S TOTALES DETECTADOS: para cada RS de Snort, número de flujos con ataque detectados por el RuleSet. Para este cálculo, se cuenta el número de flujos totales dentro de los logs de alertas
      -> Nº DE MENSAJES DE RED CON ATAQUE/S TOTALES DETECTADOS: para cada RS de Snort, número de mensajes de red con ataque detectados por el RuleSet. Para este cálculo, se cuenta el número total de paquetes diferentes dentro de los logs de alertas
      -> Nº ATAQUES (INSTANCIAS) TOTALES DETECTADOS: para el RS1 de Snort, número de instancias de ataque totales detectadas. Para este cálculo, se cuenta el número total de alertas dentro de los logs de alertas.
      -> Nº ATAQUES (INSTANCIAS) DETECTADOS POR TALOS: para los RS2, RS3 y RS4 número de instancias de ataque totales detectadas por el paquete de reglas de Talos respectivo
      -> Nº ATAQUES (INSTANCIAS) DETECTADOS POR ETOPEN: para los RS2, RS3 y RS4 número de instancias de ataque totales detectadas por el paquete de reglas de ETOpen respectivo
      -> Nº TOTAL DE FLUJOS CON ATAQUE/S TP DETECTADOS (Manual): para cada RS de Snort, número de flujos con ataques manualmente calificados como TP detectados por el RuleSet
      -> Nº DE MENSAJES DE RED CON ATAQUE/S TP DETECTADOS (Manual): para cada RS de Snort, número de mensajes de red con ataques manualmente calificados como TP detectados por el RuleSet
      -> Nº ATAQUES (INSTANCIAS) TP DETECTADOS (Manual): para cada RS de Snort, número de instancias de ataques calificadas manualmente como TP totales detectadas
      -> Nº TOTAL DE FLUJOS CON ATAQUE/S TP DETECTADOS (Automático): para cada RS de Snort, número de flujos con ataques automáticamente calificados como TP detectados por el RuleSet. Para el cálculo, se discriminan todas aquellas alertas cuyo SID se encuentre también en los SIDs de tráfico legítimo
      -> Nº DE MENSAJES DE RED CON ATAQUE/S TP DETECTADOS (Automático): para cada RS de Snort, número de mensajes con ataques automáticamente calificados como TP detectados por el RuleSet. Para el cálculo, se discriminan todas aquellas alertas cuyo SID se encuentre también en los SIDs de tráfico legítimo
      -> Nº ATAQUES (INSTANCIAS) TP DETECTADOS (Automático): para el RS1 de Snort, número de instancias de ataques automáticamente calificadas como TP detectadas por el RuleSet. Para el cálculo, se discriminan todas aquellas alertas cuyo SID se encuentre también en los SIDs de tráfico legítimo
      -> Nº ATAQUES (INSTANCIAS) TP DETECTADOS POR TALOS (Automático): para los RS2, RS3 y RS4, número de instancias de ataques automáticamente calificadas como TP detectadas por el paquete de reglas Talos respectivo. Para el cálculo, se discriminan todas aquellas alertas cuyo SID se encuentre también en los SIDs de tráfico legítimo
      -> Nº ATAQUES (INSTANCIAS) TP DETECTADOS POR ETOPEN (Automático): para los RS2, RS3 y RS4, número de instancias de ataques automáticamente calificadas como TP detectadas por el paquete de reglas ETOpen respectivo. Para el cálculo, se discriminan todas aquellas alertas cuyo SID se encuentre también en los SIDs de tráfico legítimo
      -> Nº ATAQUES (INSTANCIAS) TP TOTALES DETECTADOS (Automático + Manual): para los RS2, RS3 y RS4, número de instancias de ataques automáticamente calificadas como TP detectadas en total. Para el cálculo, se discriminan todas aquellas alertas cuyo SID se encuentre también en los SIDs de tráfico legítimo así como se realiza una puesta en conjunto manual para asociar las alertas de cada paquete de reglas a una instancia.
      -> % DETECCIÓN FLUJOS: para cada RS, número de flujos con ataques detectados entre número de flujos con ataques de la captura
      -> % DETECCIÓN FLUJOS TP (Automático): para cada RS, número de flujos con ataques TP filtrados automáticamente detectados entre número de flujos con ataques de la captura
      -> % DETECCIÓN FLUJOS TP (Manual): para cada RS, número de flujos con ataques TP filtrados manualmente detectados entre número de flujos con ataques de la captura
      -> % DETECCIÓN MENSAJES: para cada RS, número de mensajes con ataques detectados entre número de mensajes con ataques de la captura
      -> % DETECCIÓN MENSAJES TP (Automático): para cada RS, número de mensajes con ataques TP filtrados automáticamente detectados entre número de mensajes con ataques de la captura
      -> % DETECCIÓN MENSAJES TP (Manual): para cada RS, número de mensajes con ataques TP filtrados manualmente detectados entre número de mensajes con ataques de la captura
      -> % DETECCIÓN INSTANCIAS: para el RS1, número de instancias de ataques detectadas entre número de instancias de ataques de la captura
      -> % DETECCIÓN INSTANCIAS TP (Automático): para el RS1, número de instancias de ataques TP filtrados automáticamente detectas entre número de instancias de ataques de la captura
      -> % DETECCIÓN INSTANCIAS (Manual): para los RS2, RS3 y RS4, número de instancias de ataques detectadas calculadas manualmente entre número de instancias de ataques en la captura
      -> % DETECCIÓN INSTANCIAS (Automático + Manual): para los RS2, RS3 y RS4, número de instancias de ataques TP filtrados automáticamente y calculados manualmente entre número de instancias de ataques de la captura
      -> % DETECCIÓN INSTANCIAS TP (Manual): para cada RS, número de instancias de ataques TP filtrados manualmente detectadas entre número de instancias de ataques de la captura
      -> ANÁLISIS MANUAL REALIZADO: para cada ataque, esta columna indica si se ha podido realizar el análisis manual basado en flujos, mensajes e instancias. Debido a la existencia de pcaps de gran tamaño y que por consiguiente pueden generar un gran número de alertas, su manejo y clasificación puede resultar inabordable, por lo que se deja indicado en esta columna. Aquellos ataques con una ✘ en esta celda no serán contemplados para los registros manuales (además disponen de "-" en los apartados manuales)
      -> COMENTARIOS DE LAS DETECCIONES SNORT: es posible que en determinados casos resulte necesario añadir comentarios acerca de un ataque en particular. En esta columna podrá encontrar dichos comentarios para el caso de Snort.
      -> Attackids (sin repetición): para FortiGate, muestra la lista de los attackids devueltos por la detección de FortiGate para un ataque concreto
      -> #Attackid: para FortiGate, número de attackids diferentes
      -> Attackids FP Dataset_Legítimo_XX: para FortiGate, attackids que aparecen tanto en la captura del ataque como en el dataset legitimo XX
      -> #Attackids FP Dataset_Legítimo_XX: para FortiGate, número de attackids que aparecen tanto en la captura del ataque como en el dataset legitimo XX
      -> Attackids FP (Manual): attackids que han sido considerados como FP de forma manual
      -> Attackids FP (Automático): attackids que han sido considerados como FP de forma automática, es decir, en base a los attackids que han aparecido también en el tráfico legítimo
      -> Attackids TP (Manual): attackids que han sido considerados como TP de forma manual
      -> Attackids TP (Automático): attackids que han sido considerados como TP de forma automática, es decir, aquellos que no han aparecido en las detecciones del tráfico legítimo.
      -> Attackids FP Totales: para FortiGate, Attackids considerados como FP totales. Para esta columna se usará siempre que se haya podido efectuar el análisis manual los attackids que aparezcan en la columna "Attackids FP (Manual)". En su defecto se usarán los valores del análisis automático.
      -> #Attackids FP Totales: número de attackids FP que han acabado identificándose.
      -> COMENTARIOS DE LAS DETECCIONES FG: es posible que en determinados casos resulte necesario añadir comentarios acerca de un ataque en particular. En esta columna podrá encontrar dichos comentarios para el caso de FortiGate
      -> Nº FLUJOS IDENTIFICADOS POR FORTIGATE: número de sessionids diferentes que aparecen en el log generado para un ataque. Este parámetro sirve para identificar el número total de flujos detectados por FortiGate.
      -> Nº FLUJOS CON ATAQUE DETECTADOS POR FORTIGATE: número de sessionids diferentes que tienen asociado un attackid en el log generado por FortiGate.
      -> % DETECCIÓN FORTIGATE: número de flujos con ataque detectados por FortiGate entre número de flujos con ataque en la captura
      -> threat_ids (sin repetición): para PaloAlto, muestra la lista de los threat_ids devueltos por la detección de PaloAlto para un ataque concreto
      -> #threat_id: para PaloAlto, número de threat_ids diferentes
      -> threat_ids FP Dataset_Legítimo_XX: para PaloAlto, threat_ids que aparecen tanto en la captura del ataque como en el dataset legitimo XX
      -> #threat_ids FP Dataset_Legítimo_XX: para PaloAlto, número de threat_ids que aparecen tanto en la captura del ataque como en el dataset legitimo XX
      -> threat_ids FP (Manual): threat_ids que han sido considerados como FP de forma manual
      -> threat_ids FP (Automático): threat_ids que han sido considerados como FP de forma automática, es decir, en base a los threat_ids que han aparecido también en el tráfico legítimo
      -> threat_ids TP (Manual): threat_ids que han sido considerados como TP de forma manual
      -> threat_ids TP (Automático): threat_ids que han sido considerados como TP de forma automática, es decir, aquellos que no han aparecido en las detecciones del tráfico legítimo.
      -> threat_ids FP Totales: para PaloAlto, threat_ids considerados como FP totales. Para esta columna se usará siempre que se haya podido efectuar el análisis manual los threat_ids que aparezcan en la columna "threat_ids FP (Manual)". En su defecto se usarán los valores del análisis automático.
      -> #threat_ids FP Totales: número de threat_ids FP que han acabado identificándose.
      -> COMENTARIOS DE LAS DETECCIONES PA: es posible que en determinados casos resulte necesario añadir comentarios acerca de un ataque en particular. En esta columna podrá encontrar dichos comentarios para el caso de PaloAlto
      -> Nº FLUJOS IDENTIFICADOS POR PaloAlto: número de sessionids diferentes que aparecen en el log generado para un ataque. Este parámetro sirve para identificar el número total de flujos detectados por PaloAlto.
      -> Nº FLUJOS CON ATAQUE DETECTADOS POR PaloAlto: número de sessionids diferentes que tienen asociado un threat_id en el log generado por PaloAlto.
      -> % DETECCIÓN PALOALTO: número de flujos con ataque detectados por PaloAlto entre número de flujos con ataque en la captura
      -> USADO PARA CÁLCULO DE CAPACIDAD DE DETECCIÓN: ✔ o ✘ en función de si los resultados obtenidos para un ataque acaban siendo usados para elaborar los análisis finales o no. Esta decisión se basa en parámetros como la detectabilidad, si es detectable por patrones y si se ha producido algún error en la reproducción de paquetes

     ------------ SECCIÓN B: HOJA MAPEOS ------------

     En esta hoja puede encontrarse información relacionada con las asociaciones táctica/técnica/subtécnica/IDs de ataques, así como contadores particulares y globales. A continuación se describen las pestañas que componen la hoja.

     -> (A) - Mapeo Tácticas/Técnicas: contiene una tabla con la asociación entre técnicas implementadas en el estudio y la/s táctica/s a la/s que pertenece/n
     -> (B) - Mapeo Tácticas/Subtécnicas: contiene una tabla con la asociación entre subtécnicas implementadas en el estudio y la/s táctica/s a la/s que pertenece/n
     -> (C) - Tabla Táctica/Técnica/Subtécnica: contiene una descripción detallada de toda la matriz MITRE ATT&CK, filtrando los campos que resultan de mayor interés para el estudio
     -> (D) - Recuento Total: contiene toda clase de contadores relacionados con las tácticas, técnicas y subtécnicas de la matriz, tanto las que han sido implementadas como las que no (porque no son detectables por red)
     -> Otras pestañas: el resto de pestañas están centradas en la asociación SIDs <-> Tácticas/Técnicas, tanto para Snort como para el resto de IDS



      



 
