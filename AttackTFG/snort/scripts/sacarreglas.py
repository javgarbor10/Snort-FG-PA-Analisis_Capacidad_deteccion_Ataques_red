import sys


#Saca cuáles son las reglas distintas que han saltado en un ataque
# Verificar si se ha proporcionado el nombre del archivo
if len(sys.argv) < 2:
    print("Uso: python script.py <nombre_del_archivo>")
    sys.exit(1)

file = sys.argv[1]

try:
    with open(file, "r") as f:
        alertas = []
        for linea in f:
            # Verificar si la línea contiene "[**]"
            if "[**]" in linea:
                tipo = linea.split("[**]")
                # Verificar si el split tiene al menos 2 elementos
                if len(tipo) > 1:
                    regla = tipo[1].strip()
                    if regla not in alertas:
                        alertas.append(regla)
        
    print("Nº alertas = " + str(len(alertas)))
    for y in alertas:
        print(y)

except FileNotFoundError:
    print(f"Error: El archivo '{file}' no se encontró.")
except Exception as e:
    print(f"Error al procesar el archivo: {e}")

