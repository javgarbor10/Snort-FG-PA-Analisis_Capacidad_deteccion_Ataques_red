SET TABLE temp_detecciones SOURCE "/home/dit/Escritorio/hsqldb/hsqldb-2.7.3/hsqldb/lib/Datos.csv;ignore_first=true"
INSERT INTO detecciones SELECT * FROM detecciones;
