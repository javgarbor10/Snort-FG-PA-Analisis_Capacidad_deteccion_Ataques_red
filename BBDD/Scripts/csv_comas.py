import pandas as pd
import argparse

def convert_csv(input_file, output_file):
    # Leer el archivo CSV con punto y coma como delimitador y mantener las cadenas de texto
    df = pd.read_csv(input_file, delimiter=';', dtype=str)

    # Guardar el DataFrame en un nuevo archivo CSV usando coma como delimitador
    df.to_csv(output_file, index=False, sep=',')

def main():
    # Configurar el analizador de argumentos
    parser = argparse.ArgumentParser(description="Convertir un archivo CSV delimitado por punto y coma a uno delimitado por coma.")
    parser.add_argument("input_file", help="Ruta al archivo CSV de entrada")
    parser.add_argument("output_file", help="Ruta al archivo CSV de salida")

    # Parsear los argumentos
    args = parser.parse_args()

    # Convertir el archivo CSV
    convert_csv(args.input_file, args.output_file)
    print(f"Archivo convertido guardado en: {args.output_file}")

if __name__ == "__main__":
    main()
