#!/bin/bash
# SCRIPT que automatiza el análisis de Fortigate
PRIMERA_LINEA=$(($(wc -l /var/log/remote/{fichero_usuario} | cut -d" " -f1)+1))
echo $PRIMERA_LINEA
archivo_pcap=$(find /opt/fg/forti-usu1/pcaps/ -type f -name "*.pcapng" -print -quit)
sudo tcpreplay-edit -i vnet3 -d 1 -m 65520 --mtu-trunc --mbps 1 "$archivo_pcap"
sleep 60
tail -n +${PRIMERA_LINEA} /var/log/remote/{fichero_usuario} | grep 'srcintf="port4"' > /opt/fg/forti-usu1/pcaps/file.log

PRIMERA_LINEA=$(($(wc -l /var/log/remote/{fichero_usuario} | cut -d" " -f1)+1))
echo $PRIMERA_LINEA
archivo_pcap=$(find /opt/fg/forti-usu1/pcaps/ -type f -name "*.pcapng" -print -quit)
sudo tcpreplay-edit -i vnet3 -d 1 -m 65520 --mtu-trunc --mbps 1 "$archivo_pcap" 
sleep 60
tail -n +${PRIMERA_LINEA} /var/log/remote/{fichero_usuario} | grep 'srcintf="port4"' > /opt/fg/forti-usu1/pcaps/file2.log

if [[ $(cat /opt/fg/forti-usu1/pcaps/file.log | grep 'level="alert"' | wc -l) -eq $(cat /opt/fg/forti-usu1/pcaps/file2.log | grep 'level="alert"' | wc -l) ]]; then
    echo "TODO OK"
else
    echo "REVISE EL PCAP $archivo_pcap"
fi

rm /opt/fg/forti-usu1/pcaps/T*.pcapng
