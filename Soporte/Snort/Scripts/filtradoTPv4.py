import pandas as pd
import sys

def filtrar_por_sids(input_csv, output_csv, lista_sids):
    # Leer el archivo CSV existente
    df = pd.read_csv(input_csv)
    
    # Filtrar las filas cuyo SID no esté en la lista proporcionada
    df_filtrado = df[~df['SID'].astype(str).isin(lista_sids)]
    
    # Guardar el DataFrame filtrado en un nuevo archivo CSV
    df_filtrado.to_csv(output_csv, index=False)


    

if __name__ == "__main__":
    # Asegurarse de que el script se ejecute con los parámetros necesarios
    if len(sys.argv) < 1:
        print("Uso: python filtrar_sids.py <sid1> <sid2> ... <sidN>")
        sys.exit(1)


    
    
    # Resto de los argumentos: lista de SIDs a excluir
    lista_sids = sys.argv[1:]

    # Llamar a la función de filtrado
    filtrar_por_sids('resumen.csv', 'resumenTP.csv', lista_sids)
    
    print(f'Filtrado completado. El resultado se ha guardado en resumenTP.csv')

    # Leer el archivo CSV generado
    df = pd.read_csv('resumenTP.csv')

    # Filtrar las filas donde PaqueteReglas es "Community" o "ETOpen"
    df_filtrado_RS1 = df[df['PaqueteReglas'].isin(['Community'])]
        
    # Contar el número de valores distintos en la columna "Seq"
    flujos_detectados = df_filtrado_RS1['Seq'].nunique()
    mensajes_detectados = df_filtrado_RS1['IDPaq'].nunique()
    instancias_detectadas = df_filtrado_RS1.shape[0]

    print(f'Número de flujos con ataque detectados para RS1: {flujos_detectados}')
    print(f'Número de mensajes de red con ataque detectados para RS1: {mensajes_detectados}')
    print(f'Número de instancias con ataque detectadas para Community: {instancias_detectadas}')
        
    # Filtrar las filas donde PaqueteReglas es "Community" o "ETOpen"
    df_filtrado_RS2 = df[df['PaqueteReglas'].isin(['Community', 'ETOpen'])]
    df_filtrado_ETOpen =  df[df['PaqueteReglas'].isin(['ETOpen'])]
        
    # Contar el número de valores distintos en la columna "Seq"
    flujos_detectados = df_filtrado_RS2['Seq'].nunique()
    mensajes_detectados = df_filtrado_RS2['IDPaq'].nunique()
    instancias_detectadas_ETOpen = df_filtrado_ETOpen.shape[0]
    print(f'Número de flujos con ataque detectados para RS2: {flujos_detectados}')
    print(f'Número de mensajes de red con ataque detectados para RS2: {mensajes_detectados}')
    print(f'Número de instancias con ataque detectadas para ETOpen: {instancias_detectadas_ETOpen}')

    # Filtrar las filas donde PaqueteReglas es "Community" o "ETOpen"
    df_filtrado_RS3 = df[df['PaqueteReglas'].isin(['Talos', 'ETOpen'])]
    df_filtrado_Talos =  df[df['PaqueteReglas'].isin(['Talos'])]

    # Contar el número de valores distintos en la columna "Seq"
    flujos_detectados = df_filtrado_RS3['Seq'].nunique()
    mensajes_detectados = df_filtrado_RS3['IDPaq'].nunique()
    instancias_detectadas_Talos = df_filtrado_Talos.shape[0]
    print(f'Número de flujos con ataque detectados para RS3: {flujos_detectados}')
    print(f'Número de mensajes de red con ataque detectados para RS3: {mensajes_detectados}')
    print(f'Número de instancias con ataque detectadas para Talos: {instancias_detectadas_Talos}')

    # Filtrar las filas donde PaqueteReglas es "Community" o "ETOpen"
    df_filtrado_RS4 = df[df['PaqueteReglas'].isin(['Talos', 'ETOpenOpt'])]
    df_filtrado_ETOpenOpt =  df[df['PaqueteReglas'].isin(['ETOpenOpt'])]
    
    # Contar el número de valores distintos en la columna "Seq"
    flujos_detectados = df_filtrado_RS4['Seq'].nunique()
    mensajes_detectados = df_filtrado_RS4['IDPaq'].nunique()
    instancias_detectadas_ETOpenOpt = df_filtrado_ETOpenOpt.shape[0]
    print(f'Número de flujos con ataque detectados para RS4: {flujos_detectados}')
    print(f'Número de mensajes de red con ataque detectados para RS4: {mensajes_detectados}')
    print(f'Número de instancias con ataque detectadas para ETOpenOpt: {instancias_detectadas_ETOpenOpt}')
