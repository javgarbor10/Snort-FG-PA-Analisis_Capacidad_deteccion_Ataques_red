#!/bin/bash

DIRECTORIO_BASE="."

for pcap_file in "$DIRECTORIO_BASE"/*.pcapng;
do
    > /var/log/snort/alert_fast.txt
    > /var/log/snort/snort.alert.fast
    snort -c /etc/snort/snort3.lua -u snort -g snort -r "$pcap_file" -A fast -l /var/log/snort
    /usr/sbin/snort -c /etc/snort/snort.conf -u snort -g snort -r "$pcap_file"
    nombre="${pcap_file%.pcapng}"
    python3 /home/dit/Escritorio/sacarreglas.py /var/log/snort/alert_fast.txt >> /home/dit/Escritorio/Ataques-en-red_Snort/AttackTFG/detecciones/"${nombre}.txt"
    python3 /home/dit/Escritorio/sacarreglas.py /var/log/snort/snort.alert.fast >> /home/dit/Escritorio/Ataques-en-red_Snort/AttackTFG/detecciones/"${nombre}.txt"
    > /var/log/snort/alert_fast.txt
    > /var/log/snort/snort.alert.fast
     snort -c /etc/snort/snort3REG.lua -u snort -g snort -r "$pcap_file" -A fast -l /var/log/snort
     /usr/sbin/snort -c /etc/snort/snortOPT.conf -u snort -g snort -r "$pcap_file"
     python3 /home/dit/Escritorio/sacarreglas.py /var/log/snort/alert_fast.txt >> /home/dit/Escritorio/Ataques-en-red_Snort/AttackTFG/detecciones/"${nombre}.txt"
    python3 /home/dit/Escritorio/sacarreglas.py /var/log/snort/snort.alert.fast >> /home/dit/Escritorio/Ataques-en-red_Snort/AttackTFG/detecciones/"${nombre}.txt"
    done
