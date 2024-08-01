import os
import shutil
import subprocess
import sys
import csv
import glob
from scapy.all import rdpcap
import re
import pandas as pd


def guardar_en_csv(datos, archivo_salida, escribir_encabezado):
    with open(archivo_salida, 'a', newline='') as archivo_csv:
        escritor = csv.writer(archivo_csv)
        # Escribir el encabezado solo si se especifica
        if escribir_encabezado==True:
            escritor.writerow(['PaqueteReglas', 'SID', 'Detalles', 'Seq', 'IPOrigen', 'IPDestino', 'PrtOrigen', 'PrtDestino', 'IDPaq'])
        escritor.writerows(datos)

def parsear_archivo_alertas(ruta_archivo):
    detecciones = []
    
    with open(ruta_archivo, 'r') as archivo:
        contenido = archivo.read()
    
    # Obtener el nombre del archivo sin la ruta y quitar la palabra 'alertas'
    nombre_archivo = os.path.basename(ruta_archivo)
    paquete_reglas = nombre_archivo.replace('alertas', '').replace('.txt', '').strip()
    
    # Usar regex para capturar todas las alertas, incluso si están una tras otra
    alertas = re.split(r'(?=\[\*\*\] \[1:\d+:\d+\])', contenido)
    
    # Depuración: Mostrar cuántas alertas se han detectado
   

    for alerta in alertas:
        if not alerta.strip():
            continue

        # Depuración: Mostrar una muestra de la alerta
      
        
        # Extracción del SID y Detalles
        coincidencia_sid_detalles = re.search(r'\[\*\*\] \[1:(\d+):\d+\] (.+?) \[\*\*\]', alerta)
        if not coincidencia_sid_detalles:
            print("No se encontró SID y Detalles")
            continue
        
        sid = coincidencia_sid_detalles.group(1)
        detalles = coincidencia_sid_detalles.group(2)
        
        # Extracción de las direcciones IP y puertos
        coincidencia_ip_puerto = re.search(r'(\d+\.\d+\.\d+\.\d+):(\d+) -> (\d+\.\d+\.\d+\.\d+):(\d+)', alerta)
        ip_origen = coincidencia_ip_puerto.group(1) if coincidencia_ip_puerto else ''
        puerto_origen = coincidencia_ip_puerto.group(2) if coincidencia_ip_puerto else ''
        ip_destino = coincidencia_ip_puerto.group(3) if coincidencia_ip_puerto else ''
        puerto_destino = coincidencia_ip_puerto.group(4) if coincidencia_ip_puerto else ''
        
        # Extracción del ID del paquete
        coincidencia_id_paq = re.search(r'ID:(\d+)', alerta)
        id_paq = coincidencia_id_paq.group(1) if coincidencia_id_paq else ''
        
        # Extracción de la secuencia
        coincidencia_seq = re.search(r'Seq:\s*0x([0-9A-Fa-f]+)', alerta)
        seq = coincidencia_seq.group(1) if coincidencia_seq else ''
        
        detecciones.append([paquete_reglas, sid, detalles, seq, ip_origen, ip_destino, puerto_origen, puerto_destino, id_paq])
    
    return detecciones

def analiza_pcap(pcap_file):

    pcap_original = pcap_file
    nombre_base = os.path.splitext(pcap_original)[0]
    log_rs1 = os.path.join('LOGS', f"{nombre_base}_RS1.log")
    log_rs2 = os.path.join('LOGS', f"{nombre_base}_RS2.log")
    log_rs3 = os.path.join('LOGS', f"{nombre_base}_RS3.log")
    log_rs4 = os.path.join('LOGS', f"{nombre_base}_RS4.log")

    directorio_flujos = 'FLOWS'
    directorio_csv = 'CSV'
    directorio_logs = 'LOGS'
    directorio_capturas = 'CAPTURAS'
    directorio_detecciones = 'DETECCIONES'
    directorio_actual = os.path.abspath('.')  # Ruta completa del directorio actual


    detecciones = [
    ['PaqueteReglas', 'SID', 'Detalles','Seq', 'IPOrigen', 'IPDestino', 'PrtOrigen', 'PrtDestino', 'IDPaq']
]

    # Crea las carpetas si no existen
    os.makedirs(directorio_flujos, exist_ok=True)
    os.makedirs(directorio_csv, exist_ok=True)
    os.makedirs(directorio_logs, exist_ok=True)
    os.makedirs(directorio_capturas, exist_ok=True)
    os.makedirs(directorio_detecciones, exist_ok=True)

    try:

         # --- Sección Community ---

        if (not os.path.exists('DETECCIONES/alertasCommunity')):
            # Ejecuta Snort con la configuración snort3.lua
            snort_cmd_rs1 = f"sudo snort -c /etc/snort/snort3.lua -u snort -g snort -r {pcap_original} -A full -l {directorio_actual}"
            print(f"Ejecutando comando para RS1: {snort_cmd_rs1}")
            subprocess.run(snort_cmd_rs1, shell=True, check=True)

            # Cambia los permisos de los archivos generados por Snort para RS1
            chmod_cmd_rs1 = "sudo chmod 777 alert_full*"
            print(f"Ejecutando comando: {chmod_cmd_rs1}")
            subprocess.run(chmod_cmd_rs1, shell=True, check=True)

            fichero_deteccion = glob.glob('alert_full*')[0]
     

            subprocess.run(['mv', fichero_deteccion, 'DETECCIONES/alertasCommunity'])

        
            # --- Sección ETOpen ---

        if (not os.path.exists('DETECCIONES/alertasETOpen')):
            snort_cmd_etopen = f"sudo /usr/sbin/snort -c /etc/snort/snort.conf -u snort -g snort -r {pcap_original} -l {directorio_actual} -A full"
            subprocess.run(snort_cmd_etopen, shell=True, check=True)

            chmod_cmd = "sudo chmod 777 alert*"
            print(f"Ejecutando comando: {chmod_cmd}")
            subprocess.run(chmod_cmd, shell=True, check=True)

            fichero_deteccion1 = glob.glob('alert*')
            if fichero_deteccion1:
                 fichero_deteccion=fichero_deteccion1[0]
                 subprocess.run(['mv',fichero_deteccion,'DETECCIONES/alertasETOpen'])
            fichero_extra1 = glob.glob('snort.log*')
            if fichero_extra1:
                 fichero_extra=fichero_extra1[0]


                 subprocess.run(['rm', '-rf',fichero_extra])
  
        
            



            # --- Sección Talos ---

        if (not os.path.exists('DETECCIONES/alertasTalos')):
            # Ejecuta Snort con la configuración snort3.lua
            snort_cmd = f"sudo snort -c /etc/snort/snort3REG.lua -u snort -g snort -r {pcap_original} -A full -l {directorio_actual}"
            subprocess.run(snort_cmd, shell=True, check=True)

            # Cambia los permisos de los archivos generados por Snort para RS1
            chmod_cmd = "sudo chmod 777 alert_full*"
            subprocess.run(chmod_cmd, shell=True, check=True)

            fichero_deteccion = glob.glob('alert_full*')[0]
        
            subprocess.run(['mv', fichero_deteccion, 'DETECCIONES/alertasTalos'])


            # --- Sección ETOpenOptimizada ---

        if (not os.path.exists('DETECCIONES/alertasETOpenOpt')):
            snort_cmd_etopen = f"sudo /usr/sbin/snort -c /etc/snort/snortOPT.conf -u snort -g snort -r {pcap_original} -l {directorio_actual} -A full"
            subprocess.run(snort_cmd_etopen, shell=True, check=True)

            chmod_cmd = "sudo chmod 777 alert*"
            print(f"Ejecutando comando: {chmod_cmd}")
            subprocess.run(chmod_cmd, shell=True, check=True)

            fichero_deteccion1 = glob.glob('alert*')
            if fichero_deteccion1:
                 fichero_deteccion=fichero_deteccion1[0]
                 subprocess.run(['mv',fichero_deteccion,'DETECCIONES/alertasETOpenOpt'])
            fichero_extra1 = glob.glob('snort.log*')
            if fichero_extra1:
                 fichero_extra=fichero_extra1[0]
                 subprocess.run(['rm', '-rf',fichero_extra])


            
  
        nombre_archivo_sin_extension = os.path.splitext(os.path.basename(pcap_file))[0]
            



        # ------- EXTRACCIÓN ----------

        datos_community = parsear_archivo_alertas('DETECCIONES/alertasCommunity')
        guardar_en_csv(datos_community,nombre_archivo_sin_extension+'.csv',True)
        datos_etopen = parsear_archivo_alertas('DETECCIONES/alertasETOpen')
        guardar_en_csv(datos_etopen,nombre_archivo_sin_extension+'.csv',False)
        datos_talos = parsear_archivo_alertas('DETECCIONES/alertasTalos')
        guardar_en_csv(datos_talos,nombre_archivo_sin_extension+'.csv',False)
        datos_etopenopt = parsear_archivo_alertas('DETECCIONES/alertasETOpenOpt')
        guardar_en_csv(datos_etopenopt,nombre_archivo_sin_extension+'.csv',False)


        # Leer el archivo CSV generado
        df = pd.read_csv(nombre_archivo_sin_extension+'.csv')
        df = df[df['IDPaq'].notna()]

        # Filtrar las filas donde PaqueteReglas es "Community" o "ETOpen"
        df_filtrado_RS1 = df[df['PaqueteReglas'].isin(['Community'])]

        # Contar el número de valores distintos en la columna "Seq"
        flujos_detectados = df_filtrado_RS1['Seq'].nunique()
        mensajes_detectados = df_filtrado_RS1['IDPaq'].nunique()
        instancias_detectadas = df_filtrado_RS1.shape[0]

        print(f'Número de flujos con ataque detectados para RS1: {flujos_detectados}')
        print(f'Número de mensajes de red con ataque detectados para RS1: {mensajes_detectados}')
        print(f'Número de instancias con ataque detectadas para Community: {instancias_detectadas}')
        
        # Filtrar las filas donde PaqueteReglas es "Community" o "ETOpen"
        df_filtrado_RS2 = df[df['PaqueteReglas'].isin(['Community', 'ETOpen'])]
        df_filtrado_ETOpen =  df[df['PaqueteReglas'].isin(['ETOpen'])]

        # Contar el número de valores distintos en la columna "Seq"
        flujos_detectados = df_filtrado_RS2['Seq'].nunique()
        mensajes_detectados = df_filtrado_RS2['IDPaq'].nunique()
        instancias_detectadas_ETOpen = df_filtrado_ETOpen.shape[0]
        print(f'Número de flujos con ataque detectados para RS2: {flujos_detectados}')
        print(f'Número de mensajes de red con ataque detectados para RS2: {mensajes_detectados}')
        print(f'Número de instancias con ataque detectadas para ETOpen: {instancias_detectadas_ETOpen}')

        # Filtrar las filas donde PaqueteReglas es "Community" o "ETOpen"
        df_filtrado_RS3 = df[df['PaqueteReglas'].isin(['Talos', 'ETOpen'])]
        df_filtrado_Talos =  df[df['PaqueteReglas'].isin(['Talos'])]

        # Contar el número de valores distintos en la columna "Seq"
        flujos_detectados = df_filtrado_RS3['Seq'].nunique()
        mensajes_detectados = df_filtrado_RS3['IDPaq'].nunique()
        instancias_detectadas_Talos = df_filtrado_Talos.shape[0]
        print(f'Número de flujos con ataque detectados para RS3: {flujos_detectados}')
        print(f'Número de mensajes de red con ataque detectados para RS3: {mensajes_detectados}')
        print(f'Número de instancias con ataque detectadas para Talos: {instancias_detectadas_Talos}')

        # Filtrar las filas donde PaqueteReglas es "Community" o "ETOpen"
        df_filtrado_RS4 = df[df['PaqueteReglas'].isin(['Talos', 'ETOpenOpt'])]
        df_filtrado_ETOpenOpt =  df[df['PaqueteReglas'].isin(['ETOpenOpt'])]

        # Contar el número de valores distintos en la columna "Seq"
        flujos_detectados = df_filtrado_RS4['Seq'].nunique()
        mensajes_detectados = df_filtrado_RS4['IDPaq'].nunique()
        instancias_detectadas_ETOpenOpt = df_filtrado_ETOpenOpt.shape[0]
        print(f'Número de flujos con ataque detectados para RS4: {flujos_detectados}')
        print(f'Número de mensajes de red con ataque detectados para RS4: {mensajes_detectados}')
        print(f'Número de instancias con ataque detectadas para ETOpenOpt: {instancias_detectadas_ETOpenOpt}')

        

        
    except subprocess.CalledProcessError as e:
        print(f"Ocurrió un error al ejecutar tranalyzer o Snort: {e}")
    except FileNotFoundError as e:
        print(f"Archivo no encontrado: {e}")
    except Exception as e:
        print(f"Ocurrió un error inesperado: {e}")
        
if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Uso: python analyze_pcap.py <archivo.pcapng>")
        sys.exit(1)

    pcap_file = sys.argv[1]
    analiza_pcap(pcap_file)
