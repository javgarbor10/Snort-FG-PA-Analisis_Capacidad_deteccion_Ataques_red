SET TABLE temp_caracterizacion_pcaps_ataque SOURCE "/home/dit/Escritorio/hsqldb/hsqldb-2.7.3/hsqldb/lib/caracterizacion_pcaps_ataque.csv;ignore_first=true"
INSERT INTO caracterizacion_pcaps_ataque SELECT * FROM temp_caracterizacion_pcaps_ataque;

SET TABLE temp_caracterizacion_pcaps_legitimo SOURCE "/home/dit/Escritorio/hsqldb/hsqldb-2.7.3/hsqldb/lib/caracterizacion_pcaps_legitimo.csv;ignore_first=true"
INSERT INTO caracterizacion_pcaps_legitimo SELECT * FROM temp_caracterizacion_pcaps_legitimo;

SET TABLE temp_deteccion_snort SOURCE "/home/dit/Escritorio/hsqldb/hsqldb-2.7.3/hsqldb/lib/deteccion_snort.csv;ignore_first=true"
INSERT INTO deteccion_snort SELECT * FROM temp_deteccion_snort;

SET TABLE temp_deteccion_fortigate SOURCE "/home/dit/Escritorio/hsqldb/hsqldb-2.7.3/hsqldb/lib/deteccion_fortigate.csv;ignore_first=true"
INSERT INTO deteccion_fortigate SELECT * FROM temp_deteccion_fortigate;

SET TABLE temp_deteccion_paloalto SOURCE "/home/dit/Escritorio/hsqldb/hsqldb-2.7.3/hsqldb/lib/deteccion_paloalto.csv;ignore_first=true"
INSERT INTO deteccion_paloalto SELECT * FROM temp_deteccion_paloalto;

SET TABLE temp_alertas_ataque_snort SOURCE "/home/dit/Escritorio/hsqldb/hsqldb-2.7.3/hsqldb/lib/alertas_ataque_snort.csv;ignore_first=true"
INSERT INTO alertas_ataque_snort SELECT * FROM temp_alertas_ataque_snort;

SET TABLE temp_alertas_legitimo_snort SOURCE "/home/dit/Escritorio/hsqldb/hsqldb-2.7.3/hsqldb/lib/alertas_legitimo_snort.csv;ignore_first=true"
INSERT INTO alertas_legitimo_snort SELECT * FROM temp_alertas_legitimo_snort;

SET TABLE temp_resumen SOURCE "/home/dit/Escritorio/hsqldb/hsqldb-2.7.3/hsqldb/lib/mapeos.csv;ignore_first=true"
INSERT INTO resumen SELECT * FROM temp_resumen;

SET TABLE temp_alertas_ataque_fg SOURCE "/home/dit/Escritorio/hsqldb/hsqldb-2.7.3/hsqldb/lib/alertas_ataque_fortigate.csv;ignore_first=true"
INSERT INTO alertas_ataque_fg SELECT * FROM temp_alertas_ataque_fg;

SET TABLE temp_alertas_ataque_pa SOURCE "/home/dit/Escritorio/hsqldb/hsqldb-2.7.3/hsqldb/lib/alertas_ataque_paloalto.csv;ignore_first=true"
INSERT INTO alertas_ataque_pa SELECT * FROM temp_alertas_ataque_pa;
