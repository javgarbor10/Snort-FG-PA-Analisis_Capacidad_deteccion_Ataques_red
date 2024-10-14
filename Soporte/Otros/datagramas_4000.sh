### SCRIPT PARA LA DETECCIÓN DE FICHEROS PCAPS CON DATAGRAMAS SUPERIORES A 4000 BYTES

for file in *.pcap*; do echo "$file - Nº de Paquetes > 4000: $(tshark -r "$file" -R 'frame.len > 4000' -2 | wc -l)" >> resultados.txt; done
