SET TABLE temp_detecciones_ataque SOURCE "/home/dit/Escritorio/hsqldb/hsqldb-2.7.3/hsqldb/lib/detecciones_ataque.csv;ignore_first=true"
INSERT INTO detecciones_ataque SELECT * FROM temp_detecciones_ataque;
SET TABLE temp_detecciones_legitimo SOURCE "/home/dit/Escritorio/hsqldb/hsqldb-2.7.3/hsqldb/lib/detecciones_legitimo.csv;ignore_first=true"
INSERT INTO detecciones_legitimo SELECT * FROM temp_detecciones_legitimo;
SET TABLE temp_alertas_ataque_snort SOURCE "/home/dit/Escritorio/hsqldb/hsqldb-2.7.3/hsqldb/lib/alertas_ataque_snort-bbdd.csv;ignore_first=true"
INSERT INTO alertas_ataque_snort SELECT * FROM temp_alertas_ataque_snort;
