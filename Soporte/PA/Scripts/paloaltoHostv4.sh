#!/bin/bash

# Variables
REMOTE_USER="palo-usu1"
REMOTE_IP="172.16.17.111"
REMOTE_PORT="17651"
REMOTE_PCAP_DIR="/opt/pa/palo-usu1/pcaps/"
LOCAL_PCAP_DIR="/opt/pcaps-nuevos/"
LOCAL_LOG_DIR="/opt/pcaps-nuevos/logs"
VNET_INTERFACE="vnet3"
REMOTE_COMMAND="/opt/pa/palo-usu1/pcaps/PA.sh"
SSH_PASSWORD="palo-usu1-103"

# Función para enviar archivo pcap
send_pcap() {
    pcap_file=$1
    echo "Enviando $pcap_file a $REMOTE_IP..."
    sshpass -p "$SSH_PASSWORD" scp -oPort=$REMOTE_PORT "$LOCAL_PCAP_DIR$pcap_file" $REMOTE_USER@$REMOTE_IP:$REMOTE_PCAP_DIR
    echo "Archivo enviado."
}

# Función para recoger logs y eliminar archivos remotos
fetch_logs_and_cleanup() {
    pcap_file=$1
    local_log_dir=$2

    for iteration in 1 2; do
        log_filename="${pcap_file%.pcapng}_iteration_${iteration}.log"
        sshpass -p "$SSH_PASSWORD" scp -oPort=$REMOTE_PORT $REMOTE_USER@$REMOTE_IP:$REMOTE_PCAP_DIR$log_filename $local_log_dir
        echo "$log_filename descargado a $local_log_dir"
    done

    # Eliminar los archivos pcap y logs en el remoto
    sshpass -p "$SSH_PASSWORD" ssh -oPort=$REMOTE_PORT $REMOTE_USER@$REMOTE_IP "rm -f $REMOTE_PCAP_DIR$pcap_file $REMOTE_PCAP_DIR${pcap_file%.pcapng}_iteration_1.log $REMOTE_PCAP_DIR${pcap_file%.pcapng}_iteration_2.log"
    echo "Archivo remoto y logs eliminados."
}

# Procesar cada archivo pcap en los directorios especificados
for dir in nuevos Red2 basicos LAN CIC; do
    pcap_files=($(ls $LOCAL_PCAP_DIR$dir/*.pcapng 2>/dev/null))
    
    # Primer ciclo de análisis
    for pcap_file in "${pcap_files[@]}"; do
        pcap_filename=$(basename $pcap_file)
        send_pcap $dir/$pcap_filename

        # Ejecutar comando remoto
        sshpass -p "$SSH_PASSWORD" ssh -t -oPort=$REMOTE_PORT $REMOTE_USER@$REMOTE_IP "$REMOTE_COMMAND"

        # Recoger logs y limpiar archivos remotos
        fetch_logs_and_cleanup $pcap_filename $LOCAL_LOG_DIR/$dir
    done

done
