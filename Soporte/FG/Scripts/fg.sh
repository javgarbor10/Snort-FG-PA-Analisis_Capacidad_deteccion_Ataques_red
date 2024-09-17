#!/bin/bash

EXPECT_SCRIPT="/opt/fg/forti-usu1/pcaps/run_tcpreplay.expect"
USER="forti-usu1"
PASSWORD="forti-usu1-101"
VNET_INTERFACE="vnet3"
rate=10


PRIMERA_LINEA=$(($(wc -l /var/log/remote/ait29.us.es | cut -d" " -f1)+1))
echo $PRIMERA_LINEA
archivo_pcap=$(find /opt/fg/forti-usu1/pcaps/ -type f -name "*.pcapng" -print -quit)

$EXPECT_SCRIPT $USER $PASSWORD $VNET_INTERFACE $rate "$archivo_pcap"

sleep 60
tail -n +${PRIMERA_LINEA} /var/log/remote/ait29.us.es | grep 'srcintf="port4"' > /opt/fg/forti-usu1/pcaps/file.log

PRIMERA_LINEA=$(($(wc -l /var/log/remote/ait29.us.es | cut -d" " -f1)+1))
echo $PRIMERA_LINEA
archivo_pcap=$(find /opt/fg/forti-usu1/pcaps/ -type f -name "*.pcapng" -print -quit)

$EXPECT_SCRIPT $USER $PASSWORD $VNET_INTERFACE $rate "$archivo_pcap"

sleep 60
tail -n +${PRIMERA_LINEA} /var/log/remote/ait29.us.es | grep 'srcintf="port4"' > /opt/fg/forti-usu1/pcaps/file2.log

if [[ $(cat /opt/fg/forti-usu1/pcaps/file.log | grep 'level="alert"' | wc -l) -eq $(cat /opt/fg/forti-usu1/pcaps/file2.log | grep 'level="alert"' | wc -l) ]]; then
    echo "TODO OK"
else
    echo "REVISE EL PCAP $archivo_pcap"
fi

rm /opt/fg/forti-usu1/pcaps/T*.pcapng
