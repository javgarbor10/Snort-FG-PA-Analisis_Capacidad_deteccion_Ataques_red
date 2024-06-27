import subprocess
import os

#USO: Para el correcto funcionamiento de la herramienta, debe encontrarse situada en el mismo directorio que los ficheros .pcap
#     Además, debe encontrarse con los ficheros detector_syn.sh,txt_to_csv.py,checkSYN.py
#     Este script unifica los otros 3
#       COMANDO PARA EJECUTAR: python3 script_deteccion_falta_SYN.py
#     Recomendable antes de ejecutar comprobar tener instalado pandas y openpyxl
#     En caso de no tenerlo o tener version desactualizada: pip install --upgrade pandas          pip install --upgrade openpyxl


# Definir path a los scripts
detector_script = './detector_syn.sh'
txt_to_csv_script = './txt_to_csv.py'
check_syn_script = './checkSYN.py'

def execute_script(script_path, is_python_script=False):
    try:
        # Determinar el comando a ejecutar
        if is_python_script:
            command = f'python3 {script_path}'
        else:
            command = script_path

        # Ejecutar los scripts
        result = subprocess.run(command, shell=True, check=True, capture_output=True, text=True)
        print(f"Output of {script_path}: {result.stdout}")
    except subprocess.CalledProcessError as e:
        print(f"Error executing {script_path}: {e.stderr}")

def main():
    # Comprobar los scripts existan
    if not os.path.isfile(detector_script):
        print(f"{detector_script} does not exist.")
        return
    if not os.path.isfile(txt_to_csv_script):
        print(f"{txt_to_csv_script} does not exist.")
        return
    if not os.path.isfile(check_syn_script):
        print(f"{check_syn_script} does not exist.")
        return

    # Ejecutar los scripts en orden
    print("Executing detector_syn.sh...")
    execute_script(detector_script)

    print("Executing txt_to_csv.py...")
    execute_script(txt_to_csv_script, is_python_script=True)

    print("Executing checkSYN.py...")
    execute_script(check_syn_script, is_python_script=True)

if __name__ == "__main__":
    main()
