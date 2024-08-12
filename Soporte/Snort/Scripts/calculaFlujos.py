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



if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Uso: python calculaFlujos.py <archivo.pcapng>")
        sys.exit(1)

    snort_pcap_file_opt = sys.argv[1]
    tranalyzer_cmd_opt = f"tranalyzer -r {snort_pcap_file_opt}"
    print(f"Ejecutando comando para tranalyzer en el pcap de Snort con configuración alternativa: {tranalyzer_cmd_opt}")
    subprocess.run(tranalyzer_cmd_opt, shell=True, check=True)

    # Verifica si el archivo de resumen existe
    summary_file_opt = os.path.splitext(snort_pcap_file_opt)[0] + '_flows.txt'
    if not os.path.isfile(summary_file_opt):
        print(f"El archivo de resumen {summary_file_opt} no existe.")
        
    # Convierte el archivo de resumen de tranalyzer a CSV
    csv_file_opt = os.path.splitext(snort_pcap_file_opt)[0] + '_flows.csv'
    convert_txt_to_csv(summary_file_opt, csv_file_opt)
    print(f"Convertido {summary_file_opt} a {csv_file_opt}")


    num_flows_with_attacks_opt = count_flows_from_csv(csv_file_opt)

    print(f"El total de flujos es de {num_flows_with_attacks_opt}")

    subprocess.run(['rm','*.txt'])
    subprocess.run
