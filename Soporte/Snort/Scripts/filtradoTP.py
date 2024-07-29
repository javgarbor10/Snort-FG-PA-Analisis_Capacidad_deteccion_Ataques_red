import os
import sys
import re
import subprocess
from scapy.all import rdpcap, wrpcap

def leer_argumentos():
    if len(sys.argv) != 2:
        print("Uso: python filtradoTP.py listadeSIDs")
        sys.exit(1)
    sids = sys.argv[1].split()
    return sids

def seleccionar_archivo(carpeta, prefijo, indice):
    archivos = [f for f in os.listdir(carpeta) if f.startswith(prefijo)]

    if len(archivos) < indice + 1:
        print(f"No se encontraron suficientes archivos con el prefijo {prefijo} en la carpeta {carpeta}.")
        sys.exit(1)

    archivos.sort()
    archivo = archivos[indice]
    return os.path.join(carpeta, archivo)

def leer_alertas_rs2(archivo_alertas):
    with open(archivo_alertas, 'r') as f:
        lineas = f.readlines()

    alertas_parseadas = []
    posicion_actual = 1
    alerta_actual = []

    for linea in lineas:
        if linea.startswith('[**] [1:'):
            if alerta_actual:  # Si ya hay una alerta en curso, la terminamos
                alerta = ''.join(alerta_actual).strip()
                if alerta:
                    sid_match = re.search(r'\[1:(\d+):\d+\]', alerta)
                    if sid_match:
                        sid = sid_match.group(1)
                        alertas_parseadas.append({
                            'sid': sid,
                            'detalles': alerta,
                            'posicion': posicion_actual
                        })
                        posicion_actual += 1
                alerta_actual = []

        alerta_actual.append(linea)

    # Procesar la última alerta en curso si existe
    if alerta_actual:
        alerta = ''.join(alerta_actual).strip()
        if alerta:
            sid_match = re.search(r'\[1:(\d+):\d+\]', alerta)
            if sid_match:
                sid = sid_match.group(1)
                alertas_parseadas.append({
                    'sid': sid,
                    'detalles': alerta,
                    'posicion': posicion_actual
                })

    return alertas_parseadas

def convertir_unified2_a_texto(archivo_unified2):
    comando = ['u2spewfoo', archivo_unified2]
    resultado = subprocess.run(comando, capture_output=True, text=True)
    if resultado.returncode != 0:
        print(f"Error al convertir el archivo unified2: {resultado.stderr}")
        sys.exit(1)
    return resultado.stdout

def filtrar_alertas_por_sids(alertas, sids):
    return [alerta for alerta in alertas if alerta['sid'] in sids]

def identificar_paquetes_a_eliminar(alertas, texto_unified2):
    paquetes_a_eliminar = set()
    eventos = texto_unified2.split('(Event)')
    eventos = [evento.strip() for evento in eventos if evento.strip()]

    for idx, evento in enumerate(eventos):
        m = re.search(r'Rule 1:(\d+):\d+', evento)
        if m:
            sid = m.group(1)
            if sid in [alerta['sid'] for alerta in alertas]:
                paquetes_a_eliminar.add(idx + 1)  # Ajustar la numeración a 1-based

    return paquetes_a_eliminar

def eliminar_paquetes_por_posicion(posiciones, archivo_pcap_entrada, archivo_pcap_salida):
    paquetes = rdpcap(archivo_pcap_entrada)
    paquetes_filtrados = [pkt for idx, pkt in enumerate(paquetes, start=1) if idx not in posiciones]
    wrpcap(archivo_pcap_salida, paquetes_filtrados)

def fusionar_pcaps_con_mergecap(archivos_pcap, archivo_pcap_salida):
    comandos = ['mergecap', '-w', archivo_pcap_salida] + archivos_pcap
    resultado = subprocess.run(comandos, capture_output=True, text=True)
    if resultado.returncode != 0:
        print(f"Error al fusionar los archivos pcap: {resultado.stderr}")
        sys.exit(1)

def procesar_archivos(sids, prefijo_unified2, archivo_alertas, archivo_pcap_entrada, archivo_pcap_salida, archivo_pcap_filtrado, orden):
    archivo_unified2 = seleccionar_archivo('DETECCIONES', prefijo_unified2, orden)
    archivo_snort_log = seleccionar_archivo('CAPTURAS', 'snort.log.', orden)

    alertas = leer_alertas_rs2(archivo_alertas)
    alertas_filtradas = filtrar_alertas_por_sids(alertas, sids)
    
    texto_unified2 = convertir_unified2_a_texto(archivo_unified2)
    
    posiciones_a_eliminar_rs2 = [alerta['posicion'] for alerta in alertas_filtradas]
    
    # Filtrar alertas en unified2
    alertas_unified2 = []
    eventos = texto_unified2.split('(Event)')
    eventos = [evento.strip() for evento in eventos if evento.strip()]
    for idx, evento in enumerate(eventos):
        m = re.search(r'Rule 1:(\d+):\d+', evento)
        if m:
            sid = m.group(1)
            if sid in sids:
                alertas_unified2.append({
                    'sid': sid,
                    'detalles': evento,
                    'posicion': idx + 1  # Ajustar la numeración a 1-based
                })
    
    posiciones_a_eliminar_unified2 = [alerta['posicion'] for alerta in alertas_unified2]
    
    eliminar_paquetes_por_posicion(posiciones_a_eliminar_rs2, archivo_snort_log, archivo_pcap_salida)
    eliminar_paquetes_por_posicion(posiciones_a_eliminar_unified2, archivo_pcap_entrada, archivo_pcap_filtrado)
    
    archivo_pcap_fusionado = archivo_pcap_salida.replace('.pcap', '_filtrado.pcap')
    fusionar_pcaps_con_mergecap([archivo_pcap_salida, archivo_pcap_filtrado], archivo_pcap_fusionado)
    
    return len(alertas_filtradas), len(alertas_unified2)  # Retornar el número de alertas procesadas

def count_packets(pcap_file):
    """
    Cuenta el número total de paquetes y el número de paquetes únicos en el archivo pcap.
    """
    try:
        packets = rdpcap(pcap_file)
        num_total_packets = len(packets)
        unique_packets = set()
        
        for pkt in packets:
            # Usar el hash de la representación en bytes del paquete para contar paquetes únicos
            unique_packets.add(hash(bytes(pkt)))
        
        num_unique_packets = len(unique_packets)
        return num_unique_packets, num_total_packets
    except Exception as e:
        print(f"Error al contar paquetes en {pcap_file}: {e}")
        return 0, 0

def main():
    sids = leer_argumentos()
    
    # Procesar primer conjunto de archivos (RS1)
    coincidencias_rs1, coincidencias_unified2_rs1 = procesar_archivos(
        sids,
        'unified2.log.',
        'DETECCIONES/alertaRS2',
        'CAPTURAS/new_pcap_file_rs1.pcap',
        'CAPTURAS/snort_log_rs1_filtrado.pcap',
        'CAPTURAS/new_pcap_file_rs1_filtrado.pcap',
        0
    )
    
    # Procesar segundo conjunto de archivos (RS3)
    coincidencias_rs3, coincidencias_unified2_rs3 = procesar_archivos(
        sids,
        'unified2.log.',
        'DETECCIONES/alertaRS4',
        'CAPTURAS/new_pcap_file_rs3.pcap',
        'CAPTURAS/snort_log_rs3_filtrado.pcap',
        'CAPTURAS/new_pcap_file_rs3_filtrado.pcap',
        1
    )
    
    print(f"RS2 y RS1: Coincidencias en RS2: {coincidencias_rs1}, Coincidencias en unified2: {coincidencias_unified2_rs1}")
    print(f"RS4 y RS3: Coincidencias en RS4: {coincidencias_rs3}, Coincidencias en unified2: {coincidencias_unified2_rs3}")

    # Contar paquetes únicos y totales en los archivos filtrados
    num_paquetes_unicos_rs1_rs2, num_paquetes_totales_rs1_rs2 = count_packets('CAPTURAS/filtrado_rs1_rs2.pcap')
    num_paquetes_unicos_rs3_rs4, num_paquetes_totales_rs3_rs4 = count_packets('CAPTURAS/filtrado_rs3_rs4.pcap')

    print(f"Número de paquetes únicos en filtrado_rs1_rs2.pcap: {num_paquetes_unicos_rs1_rs2}")
    print(f"Número de paquetes totales en filtrado_rs1_rs2.pcap: {num_paquetes_totales_rs1_rs2}")
    print(f"Número de paquetes únicos en filtrado_rs3_rs4.pcap: {num_paquetes_unicos_rs3_rs4}")
    print(f"Número de paquetes totales en filtrado_rs3_rs4.pcap: {num_paquetes_totales_rs3_rs4}")

if __name__ == "__main__":
    main()
