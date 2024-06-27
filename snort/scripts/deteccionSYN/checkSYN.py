import pandas as pd
import numpy as np
import glob
import os

# Nombre del archivo de Excel de salida
archivo_resultados = 'RESULTADOS_EXCEL.xlsx'

# Inicializar DataFrame para almacenar todos los resultados
df_global = pd.DataFrame()

# Patrón de archivos a procesar
patron_archivos = 'csv_*_flows.xlsx'

# Obtener lista de archivos que coinciden con el patrón
archivos_a_procesar = glob.glob(patron_archivos)

# Definir la máscara binaria para multiplicar tcpFlags
mascara_binaria = int('00000010', 2)

# Función para convertir tcpFlags a binario y aplicar la máscara
def convertir_y_multiplicar(flags_hex):
    # Convertir el valor hexadecimal a binario
    flags_binario = bin(int(flags_hex, 16))[2:]  # Convertir y quitar el prefijo '0b'

    # Aplicar la máscara binaria usando operación AND bit a bit
    mascara_binaria = '00000010'
    resultado_binario = bin(int(flags_binario, 2) & int(mascara_binaria, 2))[2:]

    return resultado_binario

# Iterar sobre los archivos a procesar
for archivo in archivos_a_procesar:
    print(f"Procesando archivo: {archivo}")
    
    # Cargar el archivo Excel en un DataFrame de Pandas
    df = pd.read_excel(archivo)

    # Filtrar las filas que cumplen las condiciones
    filtros_aplicados = df[(df['%dir'] == 'A') & (df['l4Proto'] == 6)]

    # Inicializar lista para guardar filas truncadas
    filas_truncadas = []

    # Iterar sobre las filas que pasan los filtros
    for index, fila in filtros_aplicados.iterrows():
        # Obtener el resultado binario de tcpFlags
        resultado_binario = convertir_y_multiplicar(fila['tcpFlags'])

        # Determinar si el flujo está truncado o no
        if resultado_binario == '10':
            # Flujo correcto (tiene SYN)
            print(f"Flujo correcto: {fila['flowInd']} - {fila['%dir']} - {fila['tcpFlags']}")
        else:
            # Flujo truncado (carece de SYN)
            print(f"Flujo truncado: {fila['flowInd']} - {fila['%dir']} - {fila['tcpFlags']}")
            # Guardar la fila en la lista de filas truncadas
            fila['Archivo'] = archivo  # Agregar el nombre del archivo de origen
            filas_truncadas.append(fila)

    # Crear un DataFrame con las filas truncadas
    df_truncado = pd.DataFrame(filas_truncadas)

    # Concatenar el DataFrame de filas truncadas al DataFrame global
    df_global = pd.concat([df_global, df_truncado])

# Verificar si el archivo Excel ya existe
if os.path.exists(archivo_resultados):
    # Leer el archivo existente para actualizarlo
    df_existente = pd.read_excel(archivo_resultados)
    df_final = pd.concat([df_existente, df_global])
else:
    # Si el archivo no existe, usar el DataFrame global
    df_final = df_global

# Guardar el DataFrame final en un archivo Excel
try:
    with pd.ExcelWriter(archivo_resultados, engine='openpyxl', mode='w') as writer:
        df_final.to_excel(writer, index=False, sheet_name='Resultados')
    print(f"Se han guardado todos los resultados en '{archivo_resultados}'.")
except PermissionError:
    print(f"No se pudo guardar '{archivo_resultados}' porque no tienes permisos para escribir en este directorio.")
except Exception as e:
    print(f"Ocurrió un error al guardar '{archivo_resultados}': {str(e)}")
