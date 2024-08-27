import pandas as pd
import argparse
import os

def transform_excel(input_file):
    # Leer el archivo Excel original, asumiendo que la primera fila es la cabecera
    df = pd.read_excel(input_file)

    # Crear una lista para almacenar los nuevos registros
    records = []

    # Recorrer cada fila del DataFrame original
    for index, row in df.iterrows():
        pcap = row['PCAP']  # Nombre del PCAP
        attackids = row['ATTACKID']  # Columna con los ATTACKID
        fp_column = row['FP']  # Columna con los FP

        # Convertir attackids en lista de ATTACKIDs
        attackid_list = [aid.strip() for aid in str(attackids).split(',')]

        # Convertir fp_column en conjunto de ATTACKIDs de FP
        fp_sids = {aid.strip() for aid in str(fp_column).split(',')} if pd.notna(fp_column) else set()

        # Crear un registro para cada ATTACKID
        for attackid in attackid_list:
            try:
                attackid_int = int(attackid)
                tp_value = 0 if attackid in fp_sids else 1
                records.append([pcap, attackid_int, tp_value])
            except ValueError:
                # Ignorar valores no convertibles a int
                continue

    # Crear un nuevo DataFrame con los registros transformados
    transformed_df = pd.DataFrame(records, columns=['PCAP', 'ATTACKID', 'TP'])

    # Determinar el nombre del archivo de salida
    base_name, ext = os.path.splitext(input_file)
    output_file = f"{base_name}-transformed{ext}"

    # Escribir el DataFrame transformado a un nuevo archivo Excel
    transformed_df.to_excel(output_file, index=False)
    print(f"Archivo transformado guardado en: {output_file}")

def main():
    # Configurar el analizador de argumentos
    parser = argparse.ArgumentParser(description="Transformar un archivo Excel de PCAPs y ATTACKIDs en un formato específico.")
    parser.add_argument("input_file", help="Ruta al archivo Excel de entrada")

    # Parsear los argumentos
    args = parser.parse_args()

    # Llamar a la función de transformación
    transform_excel(args.input_file)

if __name__ == "__main__":
    main()
