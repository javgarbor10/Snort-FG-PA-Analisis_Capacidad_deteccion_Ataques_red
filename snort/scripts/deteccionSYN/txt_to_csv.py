import pandas as pd
import glob
import os

#Script: txt_to_csv.py
#Este script es la parte 2/3 de la detección de flujos truncados TCP SYN. Para su correcto uso debe encontrarse
#con el resto de scripts (checkSYN.py, detector_syn.sh y script_deteccion_falta_SYN.py)

#En este script se convierte la salida de tranalyzer, devuelta en formato txt a formato csv creando
#un fichero .csv por cada fichero .txt que exista
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
