#!/bin/bash
# SCRIPT que automatiza el envío de pcaps al host y recogida de logs
for fichero in "/opt/pcaps-nuevos/red/revisados/Red2/"*.pcapng; do
	if [[ "$fichero" == *.pcapng ]]; then
		nuevo_fichero=$(basename "${fichero%.pcapng}")
	fi
	if [[ "$fichero" == *.pcapng-FIX ]]; then
                nuevo_fichero=$(basename "${fichero%.pcapng-FIX}")
        fi

scp -oPort=17651 "$fichero" forti-usu1@172.16.17.115://opt/fg/forti-usu1/pcaps/
ssh -t -oPort=17651 forti-usu1@172.16.17.115 "/opt/fg/forti-usu1/pcaps/fg.sh"
scp -oPort=17651 forti-usu1@172.16.17.115://opt/fg/forti-usu1/pcaps/file.log /opt/pcaps-nuevos/logs/file.log
mv /opt/pcaps-nuevos/logs/file.log /opt/pcaps-nuevos/logs/"$nuevo_fichero.log"

done
