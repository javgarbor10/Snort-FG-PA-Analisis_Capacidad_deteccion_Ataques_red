import pandas as pd
import glob
import os

# Directorio donde se encuentran los archivos filtrados
directorio = './'  # Puedes cambiar esto al directorio específico

# Patrón para buscar archivos filtrados
patron_archivos = 'filtrado_*.txt'

# Obtener la lista de archivos que coinciden con el patrón
archivos = glob.glob(os.path.join(directorio, patron_archivos))

# Iterar sobre cada archivo y procesarlo
for archivo in archivos:
    # Obtener el nombre base del archivo sin la extensión y el prefijo 'filtrado_'
    nombre_base = os.path.splitext(os.path.basename(archivo))[0][len('filtrado_'):]

    # Nombre del archivo de Excel de salida
    excel_file = f'csv_{nombre_base}.xlsx'

    # Leer el archivo CSV
    df = pd.read_csv(archivo, sep='\t')  # Cambia '\t' por el delimitador que corresponda

    # Escribir en un archivo Excel
    df.to_excel(excel_file, index=False)

    print(f'Datos exportados a {excel_file} correctamente.')
