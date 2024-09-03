#!/bin/bash

# Variables
REMOTE_PCAP_DIR="/opt/pa/palo-usu1/pcaps/"
REMOTE_LOG_FILE="/var/log/remote/ait02-us-es_PA"
VNET_INTERFACE="vnet3"
FIXED_RATE=1.0
SLEEP_TIME=300
THRESHOLD_SIZE=6000

# Función para calcular la tasa de transferencia requerida
calculate_rate() {
    file_size_kb=$1
    time_seconds=60  # Tiempo en segundos para la transferencia
    # Convertir tamaño de archivo de KB a bits (1 KB = 1024 bytes, 1 byte = 8 bits)
    file_size_bits=$((file_size_kb * 1024 * 8))
    # Calcular la tasa en bps y luego convertir a Mbps
    rate_mbps=$(echo "scale=4; $file_size_bits / ($time_seconds * 1000000)" | bc)
    echo $rate_mbps
}

# Función para analizar el archivo pcap
analyze_pcap() {
    pcap_file=$1
    rate=$2
    iteration=$3
    log_filename="${pcap_file%.pcapng}_iteration_${iteration}.log"

    # 1. Obtener la línea actual del log
    PRIMERA_LINEA=$(($(wc -l < $REMOTE_LOG_FILE) + 1))
    
    echo "A: ${PRIMERA_LINEA}"
    sleep 120
    # 2. Lanzar análisis del pcap
    sudo tcpreplay-edit -i $VNET_INTERFACE -d 1 -m 65520 --mtu-trunc --mbps $rate $REMOTE_PCAP_DIR$pcap_file
    sleep $SLEEP_TIME

    # 3. Recoger log
    tail -n +${PRIMERA_LINEA} $REMOTE_LOG_FILE | grep 'ethernet1/3' > $REMOTE_PCAP_DIR$log_filename

    # Verificación del log
    if [ -s $REMOTE_PCAP_DIR$log_filename ]; then
        echo "Análisis completado para $pcap_file a ${rate}Mbps y log generado correctamente."
    else
        echo "Advertencia: El log generado está vacío, revisa el análisis."
    fi
}

# Obtener el archivo pcap en la carpeta y analizar automáticamente
pcap_file=$(ls $REMOTE_PCAP_DIR*.pcapng | head -n 1)
if [ -n "$pcap_file" ]; then
    pcap_filename=$(basename $pcap_file)
    
    # Obtener el tamaño del archivo pcap en KB
    file_size_kb=$(du -k "$REMOTE_PCAP_DIR$pcap_filename" | cut -f1)
    
    echo "Tamaño del archivo: ${file_size_kb}KB"

    # Determinar la tasa a utilizar
    if [ $file_size_kb -gt $THRESHOLD_SIZE ]; then
        rate=$FIXED_RATE
        echo "Utilizando tasa fija de ${rate}Mbps"
    else
        rate=$(calculate_rate $file_size_kb)
        echo "Utilizando tasa calculada de ${rate}Mbps"
    fi

    # Análisis 1
    analyze_pcap $pcap_filename $rate 1
    
    # Análisis 2
    #analyze_pcap $pcap_filename $rate 2

else
    echo "No hay archivos .pcapng en la carpeta $REMOTE_PCAP_DIR"
fi
