# Nombre del archivo: malicious_activity.py

import os

# Ruta donde se creará el archivo
file_path = "C:\\Users\\dit\\malicious_activity.txt"

# Contenido del archivo
file_content = "Este archivo fue creado por un script malicioso."

# Crear y escribir en el archivo
with open(file_path, "w") as file:
    file.write(file_content)

print(f"Archivo creado en {file_path}")
