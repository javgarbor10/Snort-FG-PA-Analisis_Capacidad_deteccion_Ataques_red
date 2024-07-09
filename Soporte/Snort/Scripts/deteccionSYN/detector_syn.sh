#!/bin/bash

#Este script es la parte 1/3 de la detección de flujos truncados TCP SYN. Para su correcto uso debe encontrarse con
#el resto de scripts (checkSYN.py, txt_to_csv.py y script_deteccion_falta_SYN.py)
#En este script se realiza el análisis mediante tranalyzer de los flujos de los archivos pcap
#existentes en el directorio actual. La sálida de tranalyzer se filtra mediante awk seleccionando
#los campos más relevantes y se crean ficheros .txt por cada pcap analizado.

DIRECTORIO="."

#Colocar el script en el mismo directorio que los ficheros .pcapng

# Analizar todos los archivos .pcapng en el directorio
for pcap_file in *.pcapng; 
do
  [ -e "$pcap_file" ] || continue
  tranalyzer -r "$pcap_file"
done

# Aplicar awk a todos los archivos *_flows.txt y guardar el resultado en archivos filtrados
for flow_file in *_flows.txt; 
do
  [ -e "$flow_file" ] || continue
  base_name=$(basename "$flow_file" "_flows.txt")
  awk -F'\t' 'BEGIN {OFS="\t"} {print $2, $1, $4, $22, $73, $14, $18, $17, $21}' "$flow_file" > "filtrado_${base_name}_flows.txt"
done

# Eliminar todos los archivos *_flows.txt que no sean filtrados
for flow_file in *_flows.txt; 
do
  [ -e "$flow_file" ] || continue
  if [[ "$flow_file" != filtrado_* ]]; then
    rm "$flow_file"
    rm *_protocols.txt
    rm *_headers.txt
    rm *_icmpStats.txt
  fi
done

echo "Proceso completado."
