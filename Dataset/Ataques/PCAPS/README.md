     +========================================+
     |██████╗  ██████╗ █████╗ ██████╗ ███████╗|
     |██╔══██╗██╔════╝██╔══██╗██╔══██╗██╔════╝|
     |██████╔╝██║     ███████║██████╔╝███████╗|
     |██╔═══╝ ██║     ██╔══██║██╔═══╝ ╚════██║|
     |██║     ╚██████╗██║  ██║██║     ███████║|
     |╚═╝      ╚═════╝╚═╝  ╚═╝╚═╝     ╚══════╝|
     +========================================+
                                  
En este directorio se halla gran parte de los pcaps de ataque que conforman el estudio completo, cada uno con su nombre de técnica asociado, siendo posible su identificación unívoca.
Estos pcaps están modificados de tal forma que son detectables al completo para todos los IDS. Carecen de flujos truncados, incluyen tanto la preparación del ataque (donde se encuentran la mayor parte de establecimientos de conexión) y el propio ataque en sí y disponen de
paquetes con la MTU ajustada al límite que habilita la detección completa y que no supone pérdidas de paquetes.

Los PCAPS se encuentran divididos en dos carpetas, según la capa del modelo OSI sobre la que se desarrollan (L2 para ataques L2 y L3 para ataques L3 o superior)

Por razones de limitación de tamaño y repetición este directorio no contiene todos los pcaps. No obstante, podrá encontrar todas las capturas de paquetes de las nuevas implementaciones (TFGs de 2024) y pcaps antiguos que han sido revisados y corregidos. El resto de pcaps se encuentran bajo la supervisión del departamento de Ingeniería Telemática de la Universidad de Sevilla.
