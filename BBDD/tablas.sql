DROP TABLE if exists alertas_ataque_rs1;
DROP TABLE if exists alertas_ataque_rs2;
DROP TABLE if exists alertas_ataque_rs3;
DROP TABLE if exists alertas_ataque_rs4;
DROP TABLE if exists alertas_legitimoyataque_rs1;
DROP TABLE if exists alertas_legitimoyataque_rs2;
DROP TABLE if exists alertas_legitimoyataque_rs3;
DROP TABLE if exists alertas_legitimoyataque_rs4;
DROP TABLE if exists temp_detecciones;
DROP TABLE if exists detecciones;



CREATE TABLE detecciones (
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

CREATE TABLE alertas_ataques_RS1 (

ficheropcap varchar(1000) REFERENCES detecciones(ficheropcap),
sid INTEGER

);

CREATE TABLE alertas_ataques_RS2 (

ficheropcap varchar(1000) REFERENCES detecciones(ficheropcap),
sid INTEGER

);

CREATE TABLE alertas_ataques_RS3 (

ficheropcap varchar(1000) REFERENCES detecciones(ficheropcap),
sid INTEGER

);

CREATE TABLE alertas_ataques_RS4 (

ficheropcap varchar(1000) REFERENCES detecciones(ficheropcap),
sid INTEGER

);

CREATE TABLE alertas_legitimoyataques_RS1 (

ficheropcap varchar(1000) REFERENCES detecciones(ficheropcap),
sid INTEGER

);

CREATE TABLE alertas_legitimoyataques_RS2 (

ficheropcap varchar(1000) REFERENCES detecciones(ficheropcap),
sid INTEGER

);

CREATE TABLE alertas_legitimoyataques_RS3 (

ficheropcap varchar(1000) REFERENCES detecciones(ficheropcap),
sid INTEGER

);

CREATE TABLE alertas_legitimoyataques_RS4 (

ficheropcap varchar(1000) REFERENCES detecciones(ficheropcap),
sid INTEGER

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


