import os
import shutil
import subprocess
import sys
import csv
import glob
from scapy.all import rdpcap


def convert_txt_to_csv(txt_file, csv_file):
    """
    Convierte el archivo TXT a CSV.
    """
    with open(txt_file, 'r') as txt_f:
        with open(csv_file, 'w', newline='') as csv_f:
            reader = csv.reader(txt_f, delimiter='\t')
            writer = csv.writer(csv_f)
            for row in reader:
                writer.writerow(row)

def count_flows_scapy(pcap_file):
    """
    Cuenta el número total de flujos únicos en el archivo pcap usando scapy.
    """
    try:
        packets = rdpcap(pcap_file)
        flows = set()
        
        for pkt in packets:
            if IP in pkt:
                if TCP in pkt:
                    flow = (pkt[IP].src, pkt[IP].dst, pkt[TCP].sport, pkt[TCP].dport)
                elif UDP in pkt:
                    flow = (pkt[IP].src, pkt[IP].dst, pkt[UDP].sport, pkt[UDP].dport)
                else:
                    continue
                
                flows.add(flow)
        
        return len(flows)
    except Exception as e:
        print(f"Error al contar flujos en {pcap_file} con scapy: {e}")
        return 0
    
def count_packets(pcap_file):
    """
    Cuenta el número total de paquetes y el número de paquetes únicos en el archivo pcap.
    """
    try:
        packets = rdpcap(pcap_file)
        num_total_packets = len(packets)
        unique_packets = set()
        
        for pkt in packets:
            # Usar el hash de la representación en bytes del paquete para contar paquetes únicos
            unique_packets.add(hash(bytes(pkt)))
        
        num_unique_packets = len(unique_packets)
        return num_unique_packets, num_total_packets
    except Exception as e:
        print(f"Error al contar paquetes en {pcap_file}: {e}")
        return 0, 0

def count_flows(pcap_file):
    """
    Cuenta el número total de flujos únicos en el archivo pcap.
    """
    try:
        packets = rdpcap(pcap_file)
        flows = set()
        
        for pkt in packets:
            # Identificar flujo usando la dirección IP y el puerto
            if hasattr(pkt, 'IP') and hasattr(pkt, 'TCP'):
                flow = (pkt[IP].src, pkt[IP].dst, pkt[TCP].sport, pkt[TCP].dport)
                flows.add(flow)
            elif hasattr(pkt, 'IP') and hasattr(pkt, 'UDP'):
                flow = (pkt[IP].src, pkt[IP].dst, pkt[UDP].sport, pkt[UDP].dport)
                flows.add(flow)
        
        return len(flows)
    except Exception as e:
        print(f"Error al contar flujos en {pcap_file}: {e}")
        return 0

def count_flows_from_csv(csv_file):
    """
    Cuenta el número total de flujos únicos en el archivo CSV generado por tranalyzer.
    """
    try:
        max_flow_ind = 0
        empty_hdr_desc_flows = set()
        with open(csv_file, 'r') as f:
            reader = csv.DictReader(f)
            for row in reader:
                if 'flowInd' in row and row['flowInd'].isdigit():
                    flow_ind = int(row['flowInd'])
                    if flow_ind > max_flow_ind:
                        max_flow_ind = flow_ind
                
                # Verifica si hdrDesc está vacío
                if 'hdrDesc' in row and row['hdrDesc'].strip() == '':
                    if 'flowInd' in row and row['flowInd'].isdigit():
                        empty_hdr_desc_flows.add(row['flowInd'])
        
        num_flows = max_flow_ind  # Los índices de flujo empiezan en 0
        num_flows_with_empty_hdr_desc = len(empty_hdr_desc_flows)
        num_valid_flows = num_flows - num_flows_with_empty_hdr_desc
        return num_valid_flows
    except Exception as e:
        print(f"Error al contar flujos desde {csv_file}: {e}")
        return 0

def analiza_pcap(pcap_file):
    pcap_original = pcap_file
    pcap_alertas_community = 'pcap_alertas_community.pcap'
    pcap_alertas_talos = 'pcap_alertas_talos.pcap'
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

    # Crea las carpetas si no existen
    os.makedirs(directorio_flujos, exist_ok=True)
    os.makedirs(directorio_csv, exist_ok=True)
    os.makedirs(directorio_logs, exist_ok=True)
    os.makedirs(directorio_capturas, exist_ok=True)
    os.makedirs(directorio_detecciones, exist_ok=True)
    

    try:

         # --- Sección RS1 ---
        
        # Ejecuta Snort con la configuración snort3.lua
        snort_cmd_rs1 = f"sudo snort -c /etc/snort/snort3.lua -u snort -g snort -r {pcap_original} -A unified2 -l {directorio_actual}"
        print(f"Ejecutando comando para RS1: {snort_cmd_rs1}")
        subprocess.run(snort_cmd_rs1, shell=True, check=True)

        # Cambia los permisos de los archivos generados por Snort para RS1
        chmod_cmd_rs1 = "sudo chmod 777 unified2.log.*"
        print(f"Ejecutando comando: {chmod_cmd_rs1}")
        subprocess.run(chmod_cmd_rs1, shell=True, check=True)

        # Convierte el archivo unified2 a pcap usando u2boat
        u2boat_cmd = f"u2boat -t pcap unified2.log.* {pcap_alertas_community}"
        print(f"Ejecutando comando: {u2boat_cmd}")
        subprocess.run(u2boat_cmd, shell=True, check=True)

        # Contar paquetes únicos y totales en el nuevo pcap generado
        num_mensajes_ataque_rs1, num_instancias_ataque_rs1 = count_packets(pcap_alertas_community)

        # Contar flujos únicos en el nuevo pcap generado
        num_flujos_ataque_rs1 = count_flows(pcap_alertas_community)

        con_pcap_rs1=1
      
        # Ejecuta tranalyzer en el nuevo pcap generado
        if (num_mensajes_ataque_rs1!=0 and num_flujos_ataque_rs1!=0):
            tranalyzer_cmd_rs1 = f"tranalyzer -r {pcap_alertas_community}"
            print(f"Ejecutando comando para tranalyzer en el nuevo pcap: {tranalyzer_cmd_rs1}")
            subprocess.run(tranalyzer_cmd_rs1, shell=True, check=True)

            # Verifica si el archivo de resumen existe
            fichero_resumen_rs1 = os.path.splitext(pcap_alertas_community)[0] + '_flows.txt'
            if not os.path.isfile(fichero_resumen_rs1):
                print(f"El archivo de resumen {fichero_resumen_rs1} no existe.")
                return
        
            # Convierte el archivo de resumen de tranalyzer a CSV
            fichero_csv_rs1 = os.path.splitext(pcap_alertas_community)[0] + '_flows.csv'
            convert_txt_to_csv(fichero_resumen_rs1, fichero_csv_rs1)
            print(f"Convertido {fichero_resumen_rs1} a {fichero_csv_rs1}")

            # Lee el archivo CSV para obtener el número total de flujos detectados por Snort
            num_flujos_ataque_rs1 = count_flows_from_csv(fichero_csv_rs1)

        else:
            con_pcap_rs1=0
       
        # Escribe el resultado en el archivo de log para RS1
        with open(log_rs1, 'w') as log:
            log.write(f"RS1\n")
            log.write(f"Número Total de Flujos Detectados por Snort: {num_flujos_ataque_rs1}\n")
            log.write(f"Número de Mensajes de Red con Ataque/s Detectados: {num_mensajes_ataque_rs1}\n")
            log.write(f"Número de Ataques (Instancias) Detectados: {num_instancias_ataque_rs1}\n")

        print(f"Análisis RS1 completo. Datos escritos en el archivo de log: {log_rs1}")

        # Mueve los archivos generados a las carpetas correspondientes para RS1
        if (con_pcap_rs1==1):
            subprocess.run(['mv', fichero_resumen_rs1, directorio_flujos])
            subprocess.run(['mv', fichero_csv_rs1, directorio_csv])
        subprocess.run(['mv', log_rs1, directorio_logs])
       # subprocess.run(['mv', pcap_alertas_community, directorio_capturas])
       
       


         # Almacena los archivos generados por Snort para RS1
        snort_files = glob.glob('unified2*')
        for file in snort_files:
            subprocess.run(['mv', file , directorio_detecciones+'/alertaCommunity'])
            print(f"Archivo almacenado: {file}")
        # Elimina los archivos .txt restantes generados por tranalyzer para RS1
        txt_files_rs1 = [f for f in os.listdir('.') if f.endswith('.txt') and f != fichero_resumen_rs1]
        for txt_file in txt_files_rs1:
            os.remove(txt_file)
            print(f"Archivo eliminado: {txt_file}")

        print(f"Archivos movidos y eliminados para RS1.")

        
        # --- Sección RS2 ---
        # Ejecuta Snort en el archivo pcap original
        snort_cmd_rs2 = f"sudo /usr/sbin/snort -c /etc/snort/snort.conf -u snort -g snort -r {pcap_original} -A full -l {directorio_actual}"
        print(f"Ejecutando comando para RS2: {snort_cmd_rs2}")
        subprocess.run(snort_cmd_rs2, shell=True, check=True)


        con_pcap_rs2 = 1
        
        pcaps_etopen = glob.glob('snort.log.*')
        
        if not pcaps_etopen:
            print(f"No se encontraron archivos pcap generados por Snort.")
            con_pcap_rs2=0
            

        else:
            pcap_etopen = pcaps_etopen[0]

        if (con_pcap_rs2==1):
            # Cambia los permisos de los archivos generados por Snort
            chmod_cmd_etopen = "sudo chmod 777 snort.log.*"
            print(f"Ejecutando comando: {chmod_cmd_etopen}")
            subprocess.run(chmod_cmd_etopen, shell=True, check=True)

        # Busca el archivo pcap generado por Snort
        

        if (con_pcap_rs2==1 or con_pcap_rs1==1):
        
            mergecap_cmd = f"mergecap -w pcap_rs2.pcap {pcap_alertas_community} {pcap_etopen}"
            print(f"Ejecutando comando para fusionar pcaps: {mergecap_cmd}")
            subprocess.run(mergecap_cmd, shell=True, check=True)

            # Busca el archivo pcap generado por Snort
            pcaps_rs2 = glob.glob('pcap_rs2*')
        
            if not pcaps_rs2:
                print(f"No se encontraron archivos pcap generados por Snort en fusion.")
                return

            pcap_rs2= pcaps_rs2[0]
        
            # Contar paquetes únicos y totales en el archivo pcap de Snort
            num_mensajes_ataque_rs2, num_instancias_ataque_rs2 = count_packets(pcap_rs2)

            # Contar flujos únicos en el archivo pcap de Snort
            tranalyzer_cmd_rs2 = f"tranalyzer -r {pcap_rs2}"
            print(f"Ejecutando comando para tranalyzer en el pcap de Snort: {tranalyzer_cmd_rs2}")
            subprocess.run(tranalyzer_cmd_rs2, shell=True, check=True)

            # Verifica si el archivo de resumen existe
            fichero_resumen_rs2 = os.path.splitext(pcap_rs2)[0] + '_flows.txt'
            if not os.path.isfile(fichero_resumen_rs2):
                print(f"El archivo de resumen {fichero_resumen_rs2} no existe.")
                return
        
            # Convierte el archivo de resumen de tranalyzer a CSV
            fichero_csv_rs2 = os.path.splitext(pcap_rs2)[0] + '_flows.csv'
            convert_txt_to_csv(fichero_resumen_rs2, fichero_csv_rs2)
            print(f"Convertido {fichero_resumen_rs2} a {fichero_csv_rs2}")

            # Lee el archivo CSV para obtener el número total de flujos detectados por Snort
            num_flujos_ataque_rs2 = count_flows_from_csv(fichero_csv_rs2)

            # Mueve los archivos generados a las carpetas correspondientes para RS2
            subprocess.run(['mv', fichero_resumen_rs2, directorio_flujos])
            subprocess.run(['mv', fichero_csv_rs2, directorio_csv])
            subprocess.run(['mv', log_rs2, directorio_logs])
            subprocess.run(['mv', pcap_etopen, directorio_capturas+'/pcap_alertas_etopen'])
            subprocess.run(['mv','alert',directorio_detecciones+'/alertaETOpen'])
        else:
            num_flujos_ataque_rs2=0
            num_mensajes_ataque_rs2=0
            num_instancias_ataque_rs2=0

            # Escribe el resultado en el archivo de log para RS2
        with open(log_rs2, 'w') as log:
            log.write(f"RS2\n")
            log.write(f"Número Total de Flujos Detectados por Snort: {num_flujos_ataque_rs2}\n")
            log.write(f"Número de Mensajes de Red con Ataque/s Detectados: {num_mensajes_ataque_rs2}\n")
            log.write(f"Número de Ataques (Instancias) Detectados: {num_instancias_ataque_rs2}\n")

        print(f"Análisis RS2 completo. Datos escritos en el archivo de log: {log_rs2}")

    
        
    

        # Elimina los archivos .txt restantes generados por tranalyzer para RS2
        txt_files = [f for f in os.listdir('.') if f.endswith('.txt') and f != fichero_resumen_rs2]
        for txt_file in txt_files:
            os.remove(txt_file)
            print(f"Archivo eliminado: {txt_file}")

        print(f"Archivos movidos y eliminados para RS2.")

        
  # --- Sección RS3 ---

        con_pcap_rs3=1
        # Ejecuta Snort con la configuración snort3.lua
        snort_cmd_talos = f"sudo snort -c /etc/snort/snort3REG.lua -u snort -g snort -r {pcap_original} -A unified2 -l {directorio_actual}"
        print(f"Ejecutando comando para RS1: {snort_cmd_talos}")
        subprocess.run(snort_cmd_talos, shell=True, check=True)

        # Cambia los permisos de los archivos generados por Snort para RS1
        chmod_cmd_talos = "sudo chmod 777 unified2.log.*"
        print(f"Ejecutando comando: {chmod_cmd_talos}")
        subprocess.run(chmod_cmd_talos, shell=True, check=True)

        # Convierte el archivo unified2 a pcap usando u2boat
        u2boat_cmd = f"u2boat -t pcap unified2.log.* {pcap_alertas_talos}"
        print(f"Ejecutando comando: {u2boat_cmd}")
        subprocess.run(u2boat_cmd, shell=True, check=True)

        
        # Contar paquetes únicos y totales en el nuevo pcap generado
        num_mensajes_ataque_talos, num_instancias_ataque_talos = count_packets(pcap_alertas_talos)
        # Contar flujos únicos en el nuevo pcap generado
        num_flujos_ataque_talos = count_flows(pcap_alertas_talos)

        if (num_flujos_ataque_talos==0 and num_mensajes_ataque_talos==0):
            con_pcap_rs3=0
        
        if (con_pcap_rs2==1):
            mergecap_cmd = f"mergecap -w pcap_rs3.pcap {pcap_alertas_talos} {pcap_rs2}"
            print(f"Ejecutando comando para fusionar pcaps: {mergecap_cmd}")
            subprocess.run(mergecap_cmd, shell=True, check=True)

            # Busca el archivo pcap generado por Snort
            pcaps_rs3 = glob.glob('pcap_rs3*')

            pcap_rs3 = pcaps_rs3[0]
        elif (con_pcap_rs3==1):
            pcap_rs3 = pcap_alertas_talos

        

    
        if (con_pcap_rs3==1 or con_pcap_rs2==1):
            # Ejecuta tranalyzer en el nuevo pcap generado
            tranalyzer_cmd_rs3 = f"tranalyzer -r {pcap_rs3}"
            print(f"Ejecutando comando para tranalyzer en el nuevo pcap: {tranalyzer_cmd_rs3}")
            subprocess.run(tranalyzer_cmd_rs3, shell=True, check=True)

            # Verifica si el archivo de resumen existe
            fichero_resumen_rs3 = os.path.splitext(pcap_rs3)[0] + '_flows.txt'
            if not os.path.isfile(fichero_resumen_rs3):
                print(f"El archivo de resumen {fichero_resumen_rs3} no existe.")
                return
        
            # Convierte el archivo de resumen de tranalyzer a CSV
            fichero_csv_rs3 = os.path.splitext(pcap_rs3)[0] + '_flows.csv'
            convert_txt_to_csv(fichero_resumen_rs3, fichero_csv_rs3)
            print(f"Convertido {fichero_resumen_rs3} a {fichero_csv_rs3}")

            # Lee el archivo CSV para obtener el número total de flujos detectados por Snort
            num_flujos_ataque_rs3 = count_flows_from_csv(fichero_csv_rs3)
            # Contar paquetes únicos y totales en el nuevo pcap generado
            num_mensajes_ataque_rs3, num_instancias_ataque_rs3 = count_packets(pcap_rs3)

            # Mueve los archivos generados a las carpetas correspondientes para RS3
            subprocess.run(['mv', fichero_resumen_rs3, directorio_flujos])
            subprocess.run(['mv', fichero_csv_rs3, directorio_csv])

        else:
            num_flujos_ataque_rs3=0
            num_mensajes_ataque_rs3=0
            num_instancias_ataque_rs3=0
        # Escribe el resultado en el archivo de log para RS3
        with open(log_rs3, 'w') as log:
            log.write(f"RS3\n")
            log.write(f"Número Total de Flujos Detectados por Snort: {num_flujos_ataque_rs3}\n")
            log.write(f"Número de Mensajes de Red con Ataque/s Detectados: {num_mensajes_ataque_rs3}\n")
            log.write(f"Número de Ataques (Instancias) Detectados: {num_instancias_ataque_rs3}\n")

        print(f"Análisis RS3 completo. Datos escritos en el archivo de log: {log_rs3}")

        
        subprocess.run(['mv', log_rs3, directorio_logs])
        #subprocess.run(['mv', pcap_alertas_talos, directorio_capturas])


        snort_files = glob.glob('unified2*')
        for file in snort_files:
            subprocess.run(['mv', file , directorio_detecciones+'/alertaTalos'])
            print(f"Archivo almacenado: {file}")

       

        # Elimina los archivos .txt restantes generados por tranalyzer para RS1
        txt_files_rs3 = [f for f in os.listdir('.') if f.endswith('.txt') and f != fichero_resumen_rs3]
        for txt_file in txt_files_rs3:
            os.remove(txt_file)
            print(f"Archivo eliminado: {txt_file}")

        print(f"Archivos movidos y eliminados para RS3.")
        
        
        # --- Sección RS4 ---
        # Borra archivos generados por Snort y tranalyzer antes de iniciar RS4
        con_pcap_rs4=1

        

        # Ejecuta Snort en el archivo pcap original con configuración alternativa
        snort_cmd_etopenopt = f"sudo /usr/sbin/snort -c /etc/snort/snortOPT.conf -u snort -g snort -r {pcap_original} -A full -l {directorio_actual}"
        print(f"Ejecutando comando para RS4: {snort_cmd_etopenopt}")
        subprocess.run(snort_cmd_etopenopt, shell=True, check=True)

        # Cambia los permisos de los archivos generados por Snort
        chmod_cmd_etopenopt = "sudo chmod 777 snort.log.*"
        print(f"Ejecutando comando: {chmod_cmd_etopenopt}")
        subprocess.run(chmod_cmd_etopenopt, shell=True, check=True)

        # Busca el archivo pcap generado por Snort después de cambiar permisos
        pcaps_etopenopt = glob.glob('snort.log.*')
        
        if not pcaps_etopenopt:
            print(f"No se encontraron archivos pcap generados por Snort con configuración alternativa.")
            con_pcap_rs4=0
            

        else:
            pcap_etopenopt = pcaps_etopenopt[0]


        if (con_pcap_rs3==1 or con_pcap_rs4==1):
            mergecap_cmd = f"mergecap -w pcap_rs4.pcap {pcap_alertas_talos} {pcap_etopenopt}"
            print(f"Ejecutando comando para fusionar pcaps: {mergecap_cmd}")
            subprocess.run(mergecap_cmd, shell=True, check=True)

            # Busca el archivo pcap generado por Snort
            pcaps_rs4 = glob.glob('pcap_rs4*')
        
            if not pcaps_rs4:
                print(f"No se encontraron archivos pcap generados por Snort en fusion.")
                return

            pcap_rs4 = pcaps_rs4[0]
        
            # Contar paquetes únicos y totales en el archivo pcap de Snort con configuración alternativa
            num_mensajes_ataque_rs4, num_instancias_ataque_rs4 = count_packets(pcap_rs4)

        
            # Contar flujos únicos en el archivo pcap de Snort con configuración alternativa
            tranalyzer_cmd_opt = f"tranalyzer -r {pcap_rs4}"
            print(f"Ejecutando comando para tranalyzer en el pcap de Snort con configuración alternativa: {tranalyzer_cmd_opt}")
            subprocess.run(tranalyzer_cmd_opt, shell=True, check=True)

            # Verifica si el archivo de resumen existe
            fichero_resumen_rs4 = os.path.splitext(pcap_rs4)[0] + '_flows.txt'
            if not os.path.isfile(fichero_resumen_rs4):
                print(f"El archivo de resumen {fichero_resumen_rs4} no existe.")
                return
        
            # Convierte el archivo de resumen de tranalyzer a CSV
            fichero_csv_opt = os.path.splitext(pcap_rs4)[0] + '_flows.csv'
            convert_txt_to_csv(fichero_resumen_rs4, fichero_csv_opt)
            print(f"Convertido {fichero_resumen_rs4} a {fichero_csv_opt}")

            # Lee el archivo CSV para obtener el número total de flujos detectados por Snort
            num_flujos_ataque_rs4 = count_flows_from_csv(fichero_csv_opt)

        else:
            num_flujos_ataque_rs4=0
            num_mensajes_ataque_rs4=0
            num_instancias_ataque_rs4=0
        # Escribe el resultado en el archivo de log para RS4
        with open(log_rs4, 'w') as log:
            log.write(f"RS4\n")
            log.write(f"Número Total de Flujos Detectados por Snort: {num_flujos_ataque_rs4}\n")
            log.write(f"Número de Mensajes de Red con Ataque/s Detectados: {num_mensajes_ataque_rs4}\n")
            log.write(f"Número de Ataques (Instancias) Detectados: {num_instancias_ataque_rs4}\n")

        print(f"Análisis RS4 completo. Datos escritos en el archivo de log: {log_rs4}")

        if(con_pcap_rs1==1 or con_pcap_rs2==1):
            subprocess.run(['mv', pcap_rs2, directorio_capturas+'/pcap_rs2'])


        if (con_pcap_rs4==1):
            # Mueve los archivos generados a las carpetas correspondientes para RS4
            subprocess.run(['mv', fichero_resumen_rs4, directorio_flujos])
            subprocess.run(['mv', fichero_csv_opt, directorio_csv])
            subprocess.run(['mv', pcap_etopenopt, directorio_capturas+'/pcap_alertas_etopenopt'])
        subprocess.run(['mv', log_rs4, directorio_logs])
        
        
       # subprocess.run(['mv', pcap_opt, directorio_capturas])

        # Elimina los archivos generados por Snort para RS4
        snort_files_opt = glob.glob('snort.log.*')
        for file in snort_files_opt:
            os.remove(file)
            print(f"Archivo eliminado: {file}")

        # Elimina los archivos .txt restantes generados por tranalyzer para RS4
        txt_files_opt = [f for f in os.listdir('.') if f.endswith('.txt') and f != fichero_resumen_rs4]
        for txt_file in txt_files_opt:
            os.remove(txt_file)
            print(f"Archivo eliminado: {txt_file}")

        print(f"Archivos movidos y eliminados para RS4.")

        
        subprocess.run(['mv', pcap_alertas_community, directorio_capturas+'/pcap_alertas_community'])

        
            

        if (con_pcap_rs2==1 or con_pcap_rs3==1):
            subprocess.run(['mv', pcap_rs3, directorio_capturas+'/pcap_rs3'])
        subprocess.run(['mv', pcap_rs4, directorio_capturas+'/pcap_rs4'])
        subprocess.run(['mv', pcap_alertas_talos, directorio_capturas+'/pcap_alertas_talos'])
        subprocess.run(['mv','alert',directorio_detecciones+'/alertaETOpenOpt'])
        
        # Cambia los permisos de los archivos generados por Snort
        chmod_cmd_opt = "sudo chmod 777 DETECCIONES/*"
        print(f"Ejecutando comando: {chmod_cmd_opt}")
        subprocess.run(chmod_cmd_opt, shell=True, check=True)
        
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
