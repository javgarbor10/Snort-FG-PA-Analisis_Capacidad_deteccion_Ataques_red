import os
import pandas as pd

# Ruta del directorio que contiene los archivos Excel (ejemplo de ruta en Windows)
directorio = r'C:\Users\34693\OneDrive\Escritorio\TFG\APUNTES\PALOALTO\LOGS\CIC\DEFINITIVOS\DEFINITIVOS_NUEVOS\HULK'

# Archivo de salida
archivo_salida = 'resultado_flujos_unicos.txt'

# Inicializar una lista para almacenar los resultados
resultados = []

# Recorrer todos los archivos en el directorio
for archivo in os.listdir(directorio):
    if archivo.endswith('.xlsx') or archivo.endswith('.xls'):
        ruta_archivo = os.path.join(directorio, archivo)
        
        # Leer el archivo Excel
        try:
            df = pd.read_excel(ruta_archivo)
        except Exception as e:
            print(f"Error leyendo {archivo}: {e}")
            continue
        
        # Comprobar si existen las columnas necesarias
        if {'src_ip', 'src_port', 'dst_ip', 'dst_port'}.issubset(df.columns):
            # Crear una lista de tuplas que representen cada flujo
            flujos = list(zip(df['src_ip'], df['src_port'], df['dst_ip'], df['dst_port']))
            
            # Convertir la lista a un conjunto para obtener los flujos únicos
            flujos_unicos = set(flujos)
            
            # Guardar el resultado
            resultados.append(f"{archivo}: {len(flujos_unicos)} flujos únicos")
        else:
            print(f"El archivo {archivo} no contiene las columnas necesarias.")
        
# Escribir los resultados en el archivo de salida
with open(os.path.join(directorio, archivo_salida), 'w') as f:
    for resultado in resultados:
        f.write(f"{resultado}\n")

print("Proceso completado. Revisa el archivo de salida.")
