#!/bin/bash
import os
import sys

# Este script analizara con snort todos los pcaps de un directorio,
# y extraera los sids resultantes. 

# Definimos los directorios
dir_pcaps = "/home/jaime/pcaps/ataques/"
dir_analisis_snort = "/home/jaime/analisis_snort/RS1/"
dir_sids = "/home/jaime/sids/RS1/"

version = input("Introduzca la version de Snort que va a ser utilizada (2/3): ")

if version == "3": 
	comando_snort = "snort -c /usr/local/etc/snort/snort_community.lua -A full -r" 
else:
	if version == "2":
		comando_snort = "snort -q -A console -c /etc/snort/snort.conf -r"
	else: 
		print ("Error: Ha introducido una version incorrecta.")
		sys.exit()


lines = []


with os.scandir(dir_pcaps) as pcaps:

	for pcap in pcaps:

		# Iniciamos las alertas totales (con la variable cont contaremos todas las alertas
		# , incluso las repetidas)
		cont = 0
		alerts = []
		str_alertas = ""

		if len(sys.argv) == 1: 

			print("Procesando pcap: " + pcap.name)
			attack = pcap.name.split(".p")[0]
			os.system(comando_snort + " " + dir_pcaps + pcap.name + " > " + dir_analisis_snort + attack + ".txt")
			print("Snort ha analizado " + pcap.name)

			with open(dir_analisis_snort + attack + ".txt") as f:
				lines = f.readlines()
				for line in lines:
					if "[**]" in line:
						if version == "3":
							var = line.split(":")[1]
						else: 
							var = line.split(":")[3]
						cont += 1
						if var not in alerts:
							alerts.append(var)
							
				for i in alerts:
					#os.system('touch sids/' + sys.argv[1]) 
					if i != alerts[len(alerts)-1]:
						str_alertas += (i+",")
					else:
						str_alertas += i

				str_alertas += ". Hay " + str(len(alerts)) + " alertas no repetidas y un total de " + str(cont) + "."
				print(str_alertas)

				os.system("echo " + str_alertas + " > " + dir_sids + attack + ".txt")

		else:
			print("Error en el numero de argumentos")


		
