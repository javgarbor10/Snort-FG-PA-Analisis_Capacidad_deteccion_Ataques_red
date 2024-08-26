import sys
import re

def count_unique_sessionids(log_file_path):
    # Expresión regular para encontrar líneas con sessionid=n
    sessionid_pattern = re.compile(r'sessionid=(\d+)')

    # Conjunto para almacenar sessionids únicos
    sessionid_set = set()

    # Procesar el archivo de registro
    with open(log_file_path, 'r') as log_file:
        for line in log_file:
            sessionid_match = sessionid_pattern.search(line)
            if sessionid_match:
                sessionid = sessionid_match.group(1)
                sessionid_set.add(sessionid)

    # Contar el número de sessionids únicos
    num_unique_sessionids = len(sessionid_set)
    print(f"Se encontraron {num_unique_sessionids} sessionids únicos en el archivo de registro.")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Uso: python script.py <ruta_archivo_log>")
        sys.exit(1)

    log_file_path = sys.argv[1]

    # Contar sessionids únicos en todas las líneas
    count_unique_sessionids(log_file_path)
