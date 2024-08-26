import csv
import argparse
from collections import defaultdict

def leer_csv(filename):
    filas = []

    with open(filename, newline='') as csvfile:
        reader = csv.DictReader(csvfile)
        for row in reader:
            paquete_reglas = row['PaqueteReglas']
            ip_origen = row['IPOrigen']
            ip_destino = row['IPDestino']
            prt_origen = row['PrtOrigen']
            prt_destino = row['PrtDestino']
            seq = row['Seq']

            # Si los campos de IPs, Puertos y Seq están vacíos, ignoramos la fila
            if not ip_origen and not ip_destino and not prt_origen and not prt_destino and not seq:
                continue
            
            # Almacenamos todos los datos necesarios en una lista de diccionarios
            filas.append({
                "PaqueteReglas": paquete_reglas,
                "IPOrigen": ip_origen,
                "IPDestino": ip_destino,
                "PrtOrigen": prt_origen,
                "PrtDestino": prt_destino,
                "Seq": seq
            })
    
    return filas

def contar_combinaciones(filas, reglas_interes):
    combinaciones_unicas = set()

    for fila in filas:
        ip_origen = fila['IPOrigen']
        ip_destino = fila['IPDestino']
        prt_origen = fila['PrtOrigen']
        prt_destino = fila['PrtDestino']
        seq = fila['Seq']
        paquete_reglas = fila['PaqueteReglas']

        # Si el PaqueteReglas está en las reglas de interés
        if paquete_reglas in reglas_interes:
            # Creamos la combinación de IPs y puertos (o usamos Seq si es necesario)
            if ip_origen or ip_destino or prt_origen or prt_destino:
                combinacion = (ip_origen, ip_destino, prt_origen, prt_destino)
                combinacion_invertida = (ip_destino, ip_origen, prt_destino, prt_origen)
                combinacion_canonica = tuple(sorted([combinacion, combinacion_invertida]))[0]
                combinaciones_unicas.add(combinacion_canonica)
            else:
                combinaciones_unicas.add(seq)

    return len(combinaciones_unicas)

def main():
    parser = argparse.ArgumentParser(description='Analiza un archivo CSV para contar combinaciones de IPs y puertos.')
    parser.add_argument('filename', help='Ruta del archivo CSV a analizar')
    args = parser.parse_args()

    filas = leer_csv(args.filename)

    # Contamos las combinaciones para cada conjunto de reglas
    community_count = contar_combinaciones(filas, {"Community"})
    community_etopen_count = contar_combinaciones(filas, {"Community", "ETOpen"})
    etopen_talos_count = contar_combinaciones(filas, {"ETOpen", "Talos"})
    talos_etopenopt_count = contar_combinaciones(filas, {"Talos", "ETOpenOpt"})

    # Mostramos los resultados
    print("Combinaciones distintas por tipo de PaqueteReglas:")
    print(f"- Community: {community_count} combinaciones distintas")
    print(f"- Community+ETOpen: {community_etopen_count} combinaciones distintas")
    print(f"- ETOpen+Talos: {etopen_talos_count} combinaciones distintas")
    print(f"- Talos+ETOpenOpt: {talos_etopenopt_count} combinaciones distintas")

if __name__ == "__main__":
    main()
