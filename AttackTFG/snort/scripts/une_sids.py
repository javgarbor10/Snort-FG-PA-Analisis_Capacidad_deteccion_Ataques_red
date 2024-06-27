#!/bin/bash
import os
import sys

# Este script analiza dos directorios diferentes y, por cada
# par de archivos con el mismo nombre, crea un archivo que contiene
# los SIDs (Security Identifiers) de ambos, eliminando las repeticiones.

# Definimos los directorios
dir_ori1 = "/home/jaime/sids/RS1_OR_Talos_registered/"
dir_ori2 = "/home/jaime/sids/ETOpen_des/"
dir_des = "/home/jaime/sids/RS4/"

linesf1 = []
linesf2 = []

# Iteramos sobre los archivos en el primer directorio
with os.scandir(dir_ori1) as ficheros1:
    for aux in ficheros1:
        with open(aux, 'r') as f1:
            union = []
            linesf1 = f1.readlines()
            alertsf1 = linesf1[0].split(".")[0].split(",")
            total1 = linesf1[0].split(".")[1].split(" ")[10]
            
            # Procesamos las alertas del primer archivo
            for alertf1 in alertsf1:
                if alertf1 != "":
                    union.append(alertf1)
            
            # Iteramos sobre los archivos en el segundo directorio
            with os.scandir(dir_ori2) as ficheros2:
                for aux2 in ficheros2:
                    with open(aux2, 'r') as f2:
                        # Verificamos si los nombres de los archivos coinciden
                        if os.path.basename(f2.name) == os.path.basename(f1.name):
                            linesf2 = f2.readlines()
                            alertsf2 = linesf2[0].split(".")[0].split(",")
                            total2 = linesf2[0].split(".")[1].split(" ")[10]
                            
                            # Procesamos las alertas del segundo archivo
                            for alertf2 in alertsf2:
                                igual = False
                                for alertu in union:
                                    if alertu == alertf2:
                                        igual = True
                                        break
                                if not igual:
                                    if alertf2 != "":
                                        union.append(alertf2)
                            
                            # Construimos una cadena con las alertas no repetidas
                            str_alertas = ""
                            for i in union:
                                if i != union[len(union)-1]:
                                    str_alertas += (i + ",")
                                else:
                                    str_alertas += i

                            # Calculamos la suma total de alertas
                            suma_total = int(total1) + int(total2)

                            # Añadimos información sobre el total de alertas y escribimos en el nuevo archivo
                            str_alertas += ". Hay " + str(len(union)) + " alertas no repetidas y un total de " + str(suma_total) + "."

                            print(str_alertas)
                            os.system("echo " + str_alertas + " > " + dir_des + os.path.basename(f1.name))


