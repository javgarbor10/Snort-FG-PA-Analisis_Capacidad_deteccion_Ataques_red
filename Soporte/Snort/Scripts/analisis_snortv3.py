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

def analyze_pcap(pcap_file):
    pcap_file_original = pcap_file
    pcap_file_new_rs1 = 'new_pcap_file_rs1.pcap'
    pcap_file_new_rs3 = 'new_pcap_file_rs3.pcap'
    base_name = os.path.splitext(pcap_file_original)[0]
    log_file_rs1 = os.path.join('LOGS', f"{base_name}_RS1.log")
    log_file_rs2 = os.path.join('LOGS', f"{base_name}_RS2.log")
    log_file_rs3 = os.path.join('LOGS', f"{base_name}_RS3.log")
    log_file_rs4 = os.path.join('LOGS', f"{base_name}_RS4.log")
    
    flows_dir = 'FLOWS'
    csv_dir = 'CSV'
    logs_dir = 'LOGS'
    captures_dir = 'CAPTURAS'
    detections_dir = 'DETECCIONES'
    current_directory = os.path.abspath('.')  # Ruta completa del directorio actual

    # Crea las carpetas si no existen
    os.makedirs(flows_dir, exist_ok=True)
    os.makedirs(csv_dir, exist_ok=True)
    os.makedirs(logs_dir, exist_ok=True)
    os.makedirs(captures_dir, exist_ok=True)
    os.makedirs(detections_dir, exist_ok=True)
    

    try:

         # --- Sección RS1 ---
        # Ejecuta Snort con la configuración snort3.lua
        snort_cmd_rs1 = f"sudo snort -c /etc/snort/snort3.lua -u snort -g snort -r {pcap_file_original} -A unified2 -l {current_directory}"
        print(f"Ejecutando comando para RS1: {snort_cmd_rs1}")
        subprocess.run(snort_cmd_rs1, shell=True, check=True)

        # Cambia los permisos de los archivos generados por Snort para RS1
        chmod_cmd_rs1 = "sudo chmod 777 unified2.log.*"
        print(f"Ejecutando comando: {chmod_cmd_rs1}")
        subprocess.run(chmod_cmd_rs1, shell=True, check=True)

        # Convierte el archivo unified2 a pcap usando u2boat
        u2boat_cmd = f"u2boat -t pcap unified2.log.* {pcap_file_new_rs1}"
        print(f"Ejecutando comando: {u2boat_cmd}")
        subprocess.run(u2boat_cmd, shell=True, check=True)

        # Contar paquetes únicos y totales en el nuevo pcap generado
        num_messages_with_attacks_rs1, num_attacks_instances_rs1 = count_packets(pcap_file_new_rs1)

        # Contar flujos únicos en el nuevo pcap generado
        num_flows_with_attacks_rs1 = count_flows(pcap_file_new_rs1)

        # Ejecuta tranalyzer en el nuevo pcap generado
        tranalyzer_cmd_rs1 = f"tranalyzer -r {pcap_file_new_rs1}"
        print(f"Ejecutando comando para tranalyzer en el nuevo pcap: {tranalyzer_cmd_rs1}")
        subprocess.run(tranalyzer_cmd_rs1, shell=True, check=True)

        # Verifica si el archivo de resumen existe
        summary_file_rs1 = os.path.splitext(pcap_file_new_rs1)[0] + '_flows.txt'
        if not os.path.isfile(summary_file_rs1):
            print(f"El archivo de resumen {summary_file_rs1} no existe.")
            return
        
        # Convierte el archivo de resumen de tranalyzer a CSV
        csv_file_rs1 = os.path.splitext(pcap_file_new_rs1)[0] + '_flows.csv'
        convert_txt_to_csv(summary_file_rs1, csv_file_rs1)
        print(f"Convertido {summary_file_rs1} a {csv_file_rs1}")

        # Lee el archivo CSV para obtener el número total de flujos detectados por Snort
        num_flows_with_attacks_rs1 = count_flows_from_csv(csv_file_rs1)

        # Escribe el resultado en el archivo de log para RS1
        with open(log_file_rs1, 'w') as log:
            log.write(f"RS1\n")
            log.write(f"Número Total de Flujos Detectados por Snort: {num_flows_with_attacks_rs1}\n")
            log.write(f"Número de Mensajes de Red con Ataque/s Detectados: {num_messages_with_attacks_rs1}\n")
            log.write(f"Número de Ataques (Instancias) Detectados: {num_attacks_instances_rs1}\n")

        print(f"Análisis RS1 completo. Datos escritos en el archivo de log: {log_file_rs1}")

        # Mueve los archivos generados a las carpetas correspondientes para RS1
        subprocess.run(['mv', summary_file_rs1, flows_dir])
        subprocess.run(['mv', csv_file_rs1, csv_dir])
        subprocess.run(['mv', log_file_rs1, logs_dir])
       # subprocess.run(['mv', pcap_file_new_rs1, captures_dir])
       
       


         # Elimina los archivos generados por Snort para RS4
        snort_files = glob.glob('unified2*')
        for file in snort_files:
            subprocess.run(['mv', file , detections_dir])
            print(f"Archivo almacenado: {file}")
        # Elimina los archivos .txt restantes generados por tranalyzer para RS1
        txt_files_rs1 = [f for f in os.listdir('.') if f.endswith('.txt') and f != summary_file_rs1]
        for txt_file in txt_files_rs1:
            os.remove(txt_file)
            print(f"Archivo eliminado: {txt_file}")

        print(f"Archivos movidos y eliminados para RS1.")

        
        # --- Sección RS2 ---
        # Ejecuta Snort en el archivo pcap original
        snort_cmd_rs2 = f"sudo /usr/sbin/snort -c /etc/snort/snort.conf -u snort -g snort -r {pcap_file_original} -A full -l {current_directory}"
        print(f"Ejecutando comando para RS2: {snort_cmd_rs2}")
        subprocess.run(snort_cmd_rs2, shell=True, check=True)

        # Cambia los permisos de los archivos generados por Snort
        chmod_cmd_rs2 = "sudo chmod 777 snort.log.*"
        print(f"Ejecutando comando: {chmod_cmd_rs2}")
        subprocess.run(chmod_cmd_rs2, shell=True, check=True)

        # Busca el archivo pcap generado por Snort
        snort_pcap_files_rs2 = glob.glob('snort.log.*')
        
        if not snort_pcap_files_rs2:
            print(f"No se encontraron archivos pcap generados por Snort.")
            return

        snort_pcap_file_rs2 = snort_pcap_files_rs2[0]


        mergecap_cmd = f"mergecap -w pcap_fusion_rs1_rs2.pcap {pcap_file_new_rs1} {snort_pcap_file_rs2}"
        print(f"Ejecutando comando para fusionar pcaps: {mergecap_cmd}")
        subprocess.run(mergecap_cmd, shell=True, check=True)

        # Busca el archivo pcap generado por Snort
        snort_pcap_files_rs2_rs1 = glob.glob('pcap_fusion_rs1_rs2*')
        
        if not snort_pcap_files_rs2_rs1:
            print(f"No se encontraron archivos pcap generados por Snort en fusion.")
            return

        snort_pcap_fusion_rs1_rs2 = snort_pcap_files_rs2_rs1[0]
        
        # Contar paquetes únicos y totales en el archivo pcap de Snort
        num_messages_with_attacks_rs2, num_attacks_instances_rs2 = count_packets(snort_pcap_fusion_rs1_rs2)

        # Contar flujos únicos en el archivo pcap de Snort
        tranalyzer_cmd_rs2 = f"tranalyzer -r {snort_pcap_file_rs2}"
        print(f"Ejecutando comando para tranalyzer en el pcap de Snort: {tranalyzer_cmd_rs2}")
        subprocess.run(tranalyzer_cmd_rs2, shell=True, check=True)

        # Verifica si el archivo de resumen existe
        summary_file_rs2 = os.path.splitext(snort_pcap_file_rs2)[0] + '_flows.txt'
        if not os.path.isfile(summary_file_rs2):
            print(f"El archivo de resumen {summary_file_rs2} no existe.")
            return
        
        # Convierte el archivo de resumen de tranalyzer a CSV
        csv_file_rs2 = os.path.splitext(snort_pcap_file_rs2)[0] + '_flows.csv'
        convert_txt_to_csv(summary_file_rs2, csv_file_rs2)
        print(f"Convertido {summary_file_rs2} a {csv_file_rs2}")

        # Lee el archivo CSV para obtener el número total de flujos detectados por Snort
        num_flows_with_attacks_rs2 = count_flows_from_csv(csv_file_rs2)

        # Escribe el resultado en el archivo de log para RS2
        with open(log_file_rs2, 'w') as log:
            log.write(f"RS2\n")
            log.write(f"Número Total de Flujos Detectados por Snort: {num_flows_with_attacks_rs2}\n")
            log.write(f"Número de Mensajes de Red con Ataque/s Detectados: {num_messages_with_attacks_rs2}\n")
            log.write(f"Número de Ataques (Instancias) Detectados: {num_attacks_instances_rs2}\n")

        print(f"Análisis RS2 completo. Datos escritos en el archivo de log: {log_file_rs2}")

        # Mueve los archivos generados a las carpetas correspondientes para RS2
        subprocess.run(['mv', summary_file_rs2, flows_dir])
        subprocess.run(['mv', csv_file_rs2, csv_dir])
        subprocess.run(['mv', log_file_rs2, logs_dir])
        #subprocess.run(['mv', snort_pcap_file_rs2, captures_dir])
        subprocess.run(['mv','alert',detections_dir+'/alertaRS2'])
        
    

        # Elimina los archivos .txt restantes generados por tranalyzer para RS2
        txt_files = [f for f in os.listdir('.') if f.endswith('.txt') and f != summary_file_rs2]
        for txt_file in txt_files:
            os.remove(txt_file)
            print(f"Archivo eliminado: {txt_file}")

        print(f"Archivos movidos y eliminados para RS2.")

  # --- Sección RS3 ---
        # Ejecuta Snort con la configuración snort3.lua
        snort_cmd_rs3 = f"sudo snort -c /etc/snort/snort3REG.lua -u snort -g snort -r {pcap_file_original} -A unified2 -l {current_directory}"
        print(f"Ejecutando comando para RS1: {snort_cmd_rs3}")
        subprocess.run(snort_cmd_rs3, shell=True, check=True)

        # Cambia los permisos de los archivos generados por Snort para RS1
        chmod_cmd_rs3 = "sudo chmod 777 unified2.log.*"
        print(f"Ejecutando comando: {chmod_cmd_rs1}")
        subprocess.run(chmod_cmd_rs3, shell=True, check=True)

        # Convierte el archivo unified2 a pcap usando u2boat
        u2boat_cmd = f"u2boat -t pcap unified2.log.* {pcap_file_new_rs3}"
        print(f"Ejecutando comando: {u2boat_cmd}")
        subprocess.run(u2boat_cmd, shell=True, check=True)

        mergecap_cmd = f"mergecap -w pcap_fusion_rs2_rs3.pcap {pcap_file_new_rs3} {snort_pcap_file_rs2}"
        print(f"Ejecutando comando para fusionar pcaps: {mergecap_cmd}")
        subprocess.run(mergecap_cmd, shell=True, check=True)

        # Busca el archivo pcap generado por Snort
        snort_pcap_files_rs2_rs3 = glob.glob('pcap_fusion_rs2_rs3*')
        
        if not snort_pcap_files_rs2_rs3:
            print(f"No se encontraron archivos pcap generados por Snort en fusion.")
            return

        snort_pcap_fusion_rs2_rs3 = snort_pcap_files_rs2_rs3[0]

        # Contar paquetes únicos y totales en el nuevo pcap generado
        num_messages_with_attacks_rs3, num_attacks_instances_rs3 = count_packets(snort_pcap_fusion_rs2_rs3)

    

        # Ejecuta tranalyzer en el nuevo pcap generado
        tranalyzer_cmd_rs3 = f"tranalyzer -r {pcap_file_new_rs3}"
        print(f"Ejecutando comando para tranalyzer en el nuevo pcap: {tranalyzer_cmd_rs3}")
        subprocess.run(tranalyzer_cmd_rs3, shell=True, check=True)

        # Verifica si el archivo de resumen existe
        summary_file_rs3 = os.path.splitext(pcap_file_new_rs3)[0] + '_flows.txt'
        if not os.path.isfile(summary_file_rs3):
            print(f"El archivo de resumen {summary_file_rs3} no existe.")
            return
        
        # Convierte el archivo de resumen de tranalyzer a CSV
        csv_file_rs3 = os.path.splitext(pcap_file_new_rs3)[0] + '_flows.csv'
        convert_txt_to_csv(summary_file_rs3, csv_file_rs3)
        print(f"Convertido {summary_file_rs3} a {csv_file_rs3}")

        # Lee el archivo CSV para obtener el número total de flujos detectados por Snort
        num_flows_with_attacks_rs3 = count_flows_from_csv(csv_file_rs3)

        # Escribe el resultado en el archivo de log para RS3
        with open(log_file_rs3, 'w') as log:
            log.write(f"RS3\n")
            log.write(f"Número Total de Flujos Detectados por Snort: {num_flows_with_attacks_rs3}\n")
            log.write(f"Número de Mensajes de Red con Ataque/s Detectados: {num_messages_with_attacks_rs3}\n")
            log.write(f"Número de Ataques (Instancias) Detectados: {num_attacks_instances_rs3}\n")

        print(f"Análisis RS3 completo. Datos escritos en el archivo de log: {log_file_rs3}")

        # Mueve los archivos generados a las carpetas correspondientes para RS3
        subprocess.run(['mv', summary_file_rs3, flows_dir])
        subprocess.run(['mv', csv_file_rs3, csv_dir])
        subprocess.run(['mv', log_file_rs3, logs_dir])
        #subprocess.run(['mv', pcap_file_new_rs3, captures_dir])


        snort_files = glob.glob('unified2*')
        for file in snort_files:
            subprocess.run(['mv', file , detections_dir])
            print(f"Archivo almacenado: {file}")

       

        # Elimina los archivos .txt restantes generados por tranalyzer para RS1
        txt_files_rs3 = [f for f in os.listdir('.') if f.endswith('.txt') and f != summary_file_rs3]
        for txt_file in txt_files_rs3:
            os.remove(txt_file)
            print(f"Archivo eliminado: {txt_file}")

        print(f"Archivos movidos y eliminados para RS3.")
        
        
        # --- Sección RS4 ---
        # Borra archivos generados por Snort y tranalyzer antes de iniciar RS4
        files_to_delete = [summary_file_rs2, csv_file_rs2]
        for file in files_to_delete:
            if os.path.isfile(file):
                os.remove(file)
                print(f"Archivo eliminado: {file}")

        # Ejecuta Snort en el archivo pcap original con configuración alternativa
        snort_cmd_opt = f"sudo /usr/sbin/snort -c /etc/snort/snortOPT.conf -u snort -g snort -r {pcap_file_original} -A full -l {current_directory}"
        print(f"Ejecutando comando para RS4: {snort_cmd_opt}")
        subprocess.run(snort_cmd_opt, shell=True, check=True)

        # Cambia los permisos de los archivos generados por Snort
        chmod_cmd_opt = "sudo chmod 777 snort.log.*"
        print(f"Ejecutando comando: {chmod_cmd_opt}")
        subprocess.run(chmod_cmd_opt, shell=True, check=True)

        # Busca el archivo pcap generado por Snort después de cambiar permisos
        snort_pcap_files_opt = glob.glob('snort.log.*')
        
        if not snort_pcap_files_opt:
            print(f"No se encontraron archivos pcap generados por Snort con configuración alternativa.")
            return

        snort_pcap_file_opt = snort_pcap_files_opt[0]


        mergecap_cmd = f"mergecap -w pcap_fusion_rs3_rs4.pcap {pcap_file_new_rs3} {snort_pcap_file_opt}"
        print(f"Ejecutando comando para fusionar pcaps: {mergecap_cmd}")
        subprocess.run(mergecap_cmd, shell=True, check=True)

        # Busca el archivo pcap generado por Snort
        snort_pcap_files_rs3_rs4 = glob.glob('pcap_fusion_rs3_rs4*')
        
        if not snort_pcap_files_rs3_rs4:
            print(f"No se encontraron archivos pcap generados por Snort en fusion.")
            return

        snort_pcap_fusion_rs3_rs4 = snort_pcap_files_rs3_rs4[0]
        
        # Contar paquetes únicos y totales en el archivo pcap de Snort con configuración alternativa
        num_messages_with_attacks_opt, num_attacks_instances_opt = count_packets(snort_pcap_fusion_rs3_rs4)

        # Contar flujos únicos en el archivo pcap de Snort con configuración alternativa
        tranalyzer_cmd_opt = f"tranalyzer -r {snort_pcap_file_opt}"
        print(f"Ejecutando comando para tranalyzer en el pcap de Snort con configuración alternativa: {tranalyzer_cmd_opt}")
        subprocess.run(tranalyzer_cmd_opt, shell=True, check=True)

        # Verifica si el archivo de resumen existe
        summary_file_opt = os.path.splitext(snort_pcap_file_opt)[0] + '_flows.txt'
        if not os.path.isfile(summary_file_opt):
            print(f"El archivo de resumen {summary_file_opt} no existe.")
            return
        
        # Convierte el archivo de resumen de tranalyzer a CSV
        csv_file_opt = os.path.splitext(snort_pcap_file_opt)[0] + '_flows.csv'
        convert_txt_to_csv(summary_file_opt, csv_file_opt)
        print(f"Convertido {summary_file_opt} a {csv_file_opt}")

        # Lee el archivo CSV para obtener el número total de flujos detectados por Snort
        num_flows_with_attacks_opt = count_flows_from_csv(csv_file_opt)

        # Escribe el resultado en el archivo de log para RS4
        with open(log_file_rs4, 'w') as log:
            log.write(f"RS4\n")
            log.write(f"Número Total de Flujos Detectados por Snort: {num_flows_with_attacks_opt}\n")
            log.write(f"Número de Mensajes de Red con Ataque/s Detectados: {num_messages_with_attacks_opt}\n")
            log.write(f"Número de Ataques (Instancias) Detectados: {num_attacks_instances_opt}\n")

        print(f"Análisis RS4 completo. Datos escritos en el archivo de log: {log_file_rs4}")

        # Mueve los archivos generados a las carpetas correspondientes para RS4
        subprocess.run(['mv', summary_file_opt, flows_dir])
        subprocess.run(['mv', csv_file_opt, csv_dir])
        subprocess.run(['mv', log_file_rs4, logs_dir])
        subprocess.run(['mv', snort_pcap_file_rs2, captures_dir])
        subprocess.run(['mv', snort_pcap_file_opt, captures_dir])
       # subprocess.run(['mv', snort_pcap_file_opt, captures_dir])

        # Elimina los archivos generados por Snort para RS4
        snort_files_opt = glob.glob('snort.log.*')
        for file in snort_files_opt:
            os.remove(file)
            print(f"Archivo eliminado: {file}")

        # Elimina los archivos .txt restantes generados por tranalyzer para RS4
        txt_files_opt = [f for f in os.listdir('.') if f.endswith('.txt') and f != summary_file_opt]
        for txt_file in txt_files_opt:
            os.remove(txt_file)
            print(f"Archivo eliminado: {txt_file}")

        print(f"Archivos movidos y eliminados para RS4.")
        
        subprocess.run(['mv', pcap_file_new_rs1, captures_dir])
        subprocess.run(['mv', snort_pcap_fusion_rs1_rs2, captures_dir])
        subprocess.run(['mv', snort_pcap_fusion_rs2_rs3, captures_dir])
        subprocess.run(['mv', snort_pcap_fusion_rs3_rs4, captures_dir])
        subprocess.run(['mv', pcap_file_new_rs3, captures_dir])
        subprocess.run(['mv','alert',detections_dir+'/alertaRS4'])
        
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
    analyze_pcap(pcap_file)
