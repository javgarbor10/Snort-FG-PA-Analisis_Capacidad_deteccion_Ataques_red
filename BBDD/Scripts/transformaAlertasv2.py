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
        filename = row.iloc[0]  # Nombre del fichero
        alert_sets = row.iloc[1:]  # Las columnas restantes contienen RS y FP intercalados

        # Crear un conjunto para almacenar los SIDs únicos que ya hemos visto
        seen_sids = set()

        # Procesar las columnas de RS y FP en pares
        for i in range(0, len(alert_sets), 2):
            rs_column = alert_sets[i]
            fp_column = alert_sets[i + 1] if i + 1 < len(alert_sets) else None

            rs_index = (i // 2) + 1  # Calcular el número de RS (1, 2, 3, 4, ...)

            if pd.notna(rs_column) and rs_column != '-':  # Verificar que el conjunto de alertas RS no sea NaN o '-'
                # Convertir rs_column en lista de SIDs
                sids = [sid.strip() for sid in str(rs_column).split(',')]

                # Convertir fp_column en conjunto de SIDs
                fp_sids = {sid.strip() for sid in str(fp_column).split(',')} if pd.notna(fp_column) else set()

                for sid in sids:
                    try:
                        sid_int = int(sid)
                        if sid_int not in seen_sids:
                            # Comparar cada SID en RS con los SIDs en FP
                            tp_value = 0 if sid in fp_sids else 1
                            records.append([filename, sid_int, rs_index, tp_value])
                            seen_sids.add(sid_int)
                    except ValueError:
                        # Ignorar valores no convertibles a int
                        continue

    # Crear un nuevo DataFrame con los registros transformados
    transformed_df = pd.DataFrame(records, columns=['Fichero', 'SID', 'RS', 'TP'])

    # Determinar el nombre del archivo de salida
    base_name, ext = os.path.splitext(input_file)
    output_file = f"{base_name}-bbdd{ext}"

    # Escribir el DataFrame transformado a un nuevo archivo Excel
    transformed_df.to_excel(output_file, index=False)
    print(f"Archivo transformado guardado en: {output_file}")

def main():
    # Configurar el analizador de argumentos
    parser = argparse.ArgumentParser(description="Transformar un archivo Excel de alertas en un formato específico.")
    parser.add_argument("input_file", help="Ruta al archivo Excel de entrada")

    # Parsear los argumentos
    args = parser.parse_args()

    # Llamar a la función de transformación
    transform_excel(args.input_file)

if __name__ == "__main__":
    main()
