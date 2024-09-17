#!/bin/bash
for fichero in "/opt/pcaps-nuevos/red/final/"*.pcapng; do
	if [[ "$fichero" == *.pcapng ]]; then
		nuevo_fichero=$(basename "${fichero%.pcapng}")
	fi
	if [[ "$fichero" == *.pcapng-FIX ]]; then
                nuevo_fichero=$(basename "${fichero%.pcapng-FIX}")
        fi

sshpass -p forti-usu1-101 scp -oPort=17651 "$fichero" forti-usu1@172.16.17.115://opt/fg/forti-usu1/pcaps/
sshpass -p forti-usu1-101 ssh -t -oPort=17651 forti-usu1@172.16.17.115 "/opt/fg/forti-usu1/pcaps/fg.sh"
sshpass -p forti-usu1-101 scp -oPort=17651 forti-usu1@172.16.17.115://opt/fg/forti-usu1/pcaps/file.log /opt/pcaps-nuevos/logs/file.log
mv /opt/pcaps-nuevos/logs/file.log /opt/pcaps-nuevos/logs/final/"$nuevo_fichero.log"

done
