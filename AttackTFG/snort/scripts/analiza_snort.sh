#!/bin/bash

# Verificar si se proporcionó una opción válida (snortv2, snortv3 o sacarreglas)
if [ "$1" != "snortv2" ] && [ "$1" != "snortv3" ] && [ "$1" != "sacarreglas" ]; then
    echo "Uso: $0 {snortv2|snortv3|sacarreglas}"
    exit 1
fi

# Función para procesar archivos con Snortv2
process_snortv2() {
    # Vaciar el fichero de alertas
    > /var/log/snort/alert
    
    # Procesar cada archivo .pcapng en el directorio actual
    for pcap_file in *.pcapng; do
        if [ -f "$pcap_file" ]; then
            > /var/log/snort/alert
            echo "Analizando $pcap_file con Snortv2..."

            # Ejecutar Snortv2 con el archivo .pcapng
            snortv2 -c /etc/snort/snort.conf -r "$pcap_file" -A full -l /var/log/snort/

            # Verificar si se generó el archivo de alertas
            if [ -f /var/log/snort/alert ]; then
                # Guardar el contenido de las alertas en un archivo .txt
                output_file="${pcap_file%.pcapng}.txt"
                cat /var/log/snort/alert > "$output_file"
                echo "Resultados guardados en $output_file"
            else
                echo "No se encontró el archivo de alertas para $pcap_file"
            fi
        else
            echo "No se encontraron archivos .pcapng en el directorio."
        fi
    done
}

# Función para procesar archivos con Snortv3
process_snortv3() {
    # Definir la ruta
    # Vaciar el fichero de alertas
    > /var/log/snort/alert_full.txt
    
    # Procesar cada archivo .pcapng en el directorio actual
    for pcap_file in *.pcapng; do
        if [ -f "$pcap_file" ]; then
            echo "Analizando $pcap_file con Snortv3..."
            > /var/log/snort/alert_full.txt
            # Ejecutar Snortv3 con el archivo .pcapng
            snort -c /usr/local/etc/snort/snort.lua -r "$pcap_file" -A full -l /var/log/snort/
            
            # Verificar si se generó el archivo de alertas
            if [ -f /var/log/snort/alert_full.txt ]; then
                # Guardar el contenido de las alertas en un archivo .txt
                output_file="${pcap_file%.pcapng}.txt"
                cat /var/log/snort/alert_full.txt > "$output_file"
                echo "Resultados guardados en $output_file"
            else
                echo "No se encontró el archivo de alertas para $pcap_file"
            fi
        else
            echo "No se encontraron archivos .pcapng en el directorio."
        fi
    done
}

# Función para ejecutar sacarreglas.py en cada archivo .txt y guardar la salida en un archivo <nombre.txt>-sacarreglas
run_sacarreglas() {
    for txt_file in *.txt; do
        if [ -f "$txt_file" ]; then
            echo "Ejecutando sacarreglas.py en $txt_file..."
            output_file="${txt_file}-sacarreglas"
            python3 sacarreglas.py "$txt_file" > "$output_file"
            echo "Resultados guardados en $output_file"
        else
            echo "No se encontraron archivos .txt en el directorio."
        fi
    done
}

# Ejecutar la función correspondiente según la opción proporcionada
if [ "$1" == "snortv2" ]; then
    process_snortv2
elif [ "$1" == "snortv3" ]; then
    process_snortv3
elif [ "$1" == "sacarreglas" ]; then
    run_sacarreglas
fi
