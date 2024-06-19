import re

def extraer_sids(input_file, output_file):
    sids = []

    # Expresión regular para buscar el segundo número dentro de corchetes
    sid_pattern = re.compile(r'\[\d+:(\d+):\d+\]')

    # Abrir el archivo de entrada para lectura
    with open(input_file, 'r') as f:
        # Leer cada línea del archivo
        for line in f:
            # Buscar coincidencias de la expresión regular en la línea
            match = sid_pattern.search(line)
            if match:
                # Extraer el segundo número dentro de corchetes como SID
                sid = match.group(1)
                sids.append(sid)

    # Escribir los SIDs en el archivo de salida
    with open(output_file, 'w') as f:
        f.write(', '.join(sids))

    print(f'Se han extraído y guardado los siguientes SIDs en {output_file}:')
    print(', '.join(sids))

# Ejemplo de uso:
input_file = 'detecciones.txt'  # Reemplaza con tu nombre de archivo de entrada
output_file = 'sids_extraidos.txt'  # Nombre del archivo de salida

extraer_sids(input_file, output_file)
