import os
import subprocess
import re

def ejecutar_comando(comando):
    """Ejecuta un comando en la terminal y devuelve la salida como una lista de líneas."""
    resultado = subprocess.run(comando, shell=True, capture_output=True, text=True)
    return resultado.stdout.splitlines()

def extraer_numero_linea(lineas, patron):
    """Extrae el primer número que coincide con el patrón dado en una lista de líneas."""
    for linea in lineas:
        match = re.search(patron, linea)
        if match:
            return int(match.group(1))
    return None

def extraer_lineas_relevantes(lineas):
    """Extrae las líneas que comienzan con 'Número de' para procesarlas."""
    return [linea.strip() for linea in lineas if linea.startswith("Número de")]

def borrar_archivos(extension, directorio='.'):
    """Borra todos los archivos con la extensión dada en el directorio especificado."""
    for fichero in os.listdir(directorio):
        if fichero.endswith(extension):
            os.remove(os.path.join(directorio, fichero))

def borrar_archivos_carpeta(carpeta):
    """Borra todos los archivos dentro de la carpeta especificada."""
    for fichero in os.listdir(carpeta):
        ruta_fichero = os.path.join(carpeta, fichero)
        if os.path.isfile(ruta_fichero):
            os.remove(ruta_fichero)

def transformar_sids(lista_sids):
    """Transforma la lista de SIDs con comas a un formato con espacios."""
    return " ".join(lista_sids.split(','))

def mezclar_lineas(lineas1, lineas2):
    """Intercala tres líneas de lineas1 con tres líneas de lineas2 y devuelve la lista mezclada."""
    mezcladas = []
    while lineas1 or lineas2:
        for _ in range(3):
            if lineas1:
                mezcladas.append(lineas1.pop(0))
        for _ in range(3):
            if lineas2:
                mezcladas.append(lineas2.pop(0) + " (FILTRADO)")
    return mezcladas

def procesar_pcapng(fichero_pcapng):
    nombre_base = os.path.splitext(fichero_pcapng)[0]
    log_resultados = f"{nombre_base}_resultados.log"
    nombre_csv = f"{nombre_base}.csv"

    # 1º) Ejecutar calculaFlujos.py
    salida_calcula_flujos = ejecutar_comando(f"python3 calculaFlujos.py {fichero_pcapng}")
    num_flujos = extraer_numero_linea(salida_calcula_flujos, r"El total de flujos es de (\d+)")
    
    with open(log_resultados, 'w') as log:
        log.write(f"Numero de flujos totales de la captura: {num_flujos}\n")

        # 2º) Ejecutar analisis_snortv5.py
        ejecutar_comando(f"python3 analisis_snortv5.py {fichero_pcapng} > salida 2>&1")

        with open("salida", 'r') as salida_snort:
            lineas_snort = salida_snort.readlines()

            # Extraer "flows" de la primera sección de "stream"
            num_flujos_snortv3 = extraer_numero_linea(lineas_snort, r"flows: (\d+)")
            log.write(f"Numero de flujos totales detectados Snortv3: {num_flujos_snortv3}\n")

            # Extraer "Total sessions" de la primera sección de "Stream statistics"
            num_flujos_snortv2 = extraer_numero_linea(lineas_snort, r"Total sessions: (\d+)")
            log.write(f"Numero de flujos totales detectados Snortv2: {num_flujos_snortv2}\n")

            # Extraer las líneas que comienzan con "Número de"
            lineas_relevantes_snort = extraer_lineas_relevantes(lineas_snort)

    # 3º) Ejecutar filtradoTPv4.py con la lista de SIDs transformada
    lista_sids = "2002749,2002752,2101620,51037,2001117,2001219,2002910,2002911,2003068,2008120,2009207,2010935," \
                 "2010937,2019102,2100381,2100384,2100385,2100399,2100402,2100408,2100469,2100472,2100527,2100615," \
                 "2100650,2101384,2101390,2101411,2101417,2101444,2101917,2009582,2100366,2100476,2100382,2100404," \
                 "2036751,2008470,2009205,2009206,2009208,2009967,2027397."
    lista_sids_transformada = transformar_sids(lista_sids)

    ejecutar_comando(f"python3 filtradoTPv4.py {nombre_csv} {lista_sids_transformada} > salidaTP 2>&1")

    with open("salidaTP", 'r') as salida_tp:
        lineas_tp = salida_tp.readlines()

        # Extraer las líneas que comienzan con "Número de"
        lineas_relevantes_tp = extraer_lineas_relevantes(lineas_tp)

    # 4º) Mezclar las líneas de "salida" y "salidaTP"
    lineas_mezcladas = mezclar_lineas(lineas_relevantes_snort, lineas_relevantes_tp)

    # 5º) Escribir las líneas mezcladas en el archivo de log
    with open(log_resultados, 'a') as log:
        for linea in lineas_mezcladas:
            log.write(linea + '\n')

    # Borrar archivos .txt en el directorio de ejecución
    borrar_archivos('.txt')
    borrar_archivos('flows.csv')

    # Borrar archivos en la carpeta DETECCIONES
    borrar_archivos_carpeta('DETECCIONES')

def main():
    # Procesar todos los archivos .pcapng en el directorio actual
    for fichero in os.listdir('.'):
        if fichero.endswith('.pcapng'):
            procesar_pcapng(fichero)

if __name__ == "__main__":
    main()
