DROP TABLE if exists alertas_ataque_FG;
DROP TABLE if exists alertas_ataque_snort;
DROP TABLE if exists alertas_legitimo_snort;
DROP TABLE if exists temp_detecciones;
DROP TABLE if exists detecciones_ataque;
DROP TABLE if exists detecciones_legitimo;



CREATE TABLE detecciones_ataque (
tactica varchar(1000),
otrastacticas varchar(1000),
idtactica varchar(1000),
tecnica varchar(1000),
idtecnica varchar(1000),
subtecnica varchar(1000),
idsubtecnica varchar(1000),
ataque varchar(1000),
herramienta varchar(1000),
ficheropcap varchar(1000) PRIMARY KEY,
nflujos INTEGER,
ninstancias INTEGER,
nflujoscolaterales INTEGER,
detectablepatrones varchar(1000),
mecanismodeteccion varchar(1000),
implementacion varchar(1000),
procesogeneracionpcap varchar(1000),
validacionpcap varchar(1000),
analisisdeteccionespcap varchar(1000),
formatopcapng INTEGER,
detectabilidad INTEGER,
ataquescolaterales INTEGER,
mtumaxima INTEGER,
error_tcp_replay INTEGER,
flujos_completos INTEGER,
nflujosdetectados_rs1 INTEGER,
deteccion_rs1 numeric(3,2),
nflujosdetectados_rs2 INTEGER,
deteccion_rs2 numeric(3,2),
nflujosdetectados_rs3 INTEGER,
deteccion_rs3 numeric(3,2),
nflujosdetectados_rs4 INTEGER,
deteccion_rs4 numeric(3,2),
comentarios_detecciones varchar(1000),
nflujosdetectados_fg INTEGER,
deteccion_fg numeric(3,2),
usado_para_analisis INTEGER
);

CREATE TABLE detecciones_legitimo (
ficheropcap varchar(1000) PRIMARY KEY,
tipotrafico varchar(1000),
categoria varchar(1000),
tamanoreal_Mb numeric,
nflujos INTEGER,
ndirecciones INTEGER,
flujoscompletos INTEGER
);

CREATE TABLE alertas_ataque_snort (
ficheropcap varchar(1000) REFERENCES detecciones_ataque(ficheropcap),
sid INTEGER,
ruleset INTEGER
);

CREATE TABLE alertas_legitimo_snort (
ficheropcap varchar(1000) REFERENCES detecciones_legitimo(ficheropcap),
sid INTEGER,
ruleset INTEGER
);

CREATE TABLE alertas_ataque_FG (
ficheropcap varchar(1000) REFERENCES detecciones_ataque(ficheropcap),
attackid INTEGER
);


CREATE TEXT TABLE temp_detecciones (
tactica varchar(1000),
otrastacticas varchar(1000),
idtactica varchar(1000),
tecnica varchar(1000),
idtecnica varchar(1000),
subtecnica varchar(1000),
idsubtecnica varchar(1000),
ataque varchar(1000),
herramienta varchar(1000),
ficheropcap varchar(1000),
nflujos INTEGER,
ninstancias INTEGER,
nflujoscolaterales INTEGER,
detectablepatrones varchar(1000),
mecanismodeteccion varchar(1000),
implementacion varchar(1000),
procesogeneracionpcap varchar(1000),
validacionpcap varchar(1000),
analisisdeteccionespcap varchar(1000),
formatopcapng INTEGER,
detectabilidad INTEGER,
ataquescolaterales INTEGER,
mtumaxima INTEGER,
error_tcp_replay INTEGER,
flujos_completos INTEGER,
nflujosdetectados_rs1 INTEGER,
deteccion_rs1 numeric(3,2),
nflujosdetectados_rs2 INTEGER,
deteccion_rs2 numeric(3,2),
nflujosdetectados_rs3 INTEGER,
deteccion_rs3 numeric(3,2),
nflujosdetectados_rs4 INTEGER,
deteccion_rs4 numeric(3,2),
comentarios_detecciones varchar(1000),
nflujosdetectados_fg INTEGER,
deteccion_fg numeric(3,2),
usado_para_analisis INTEGER
);


