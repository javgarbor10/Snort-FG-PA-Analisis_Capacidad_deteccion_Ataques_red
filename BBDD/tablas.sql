DROP TABLE if exists alertas_ataque_FG;
DROP TABLE if exists temp_alertas_ataque_FG;
DROP TABLE if exists alertas_ataque_snort;
DROP TABLE if exists temp_alertas_ataque_snort;
DROP TABLE if exists alertas_legitimo_snort;
DROP TABLE if exists temp_alertas_legitimo_snort;

DROP VIEW if exists calculo_detecciones_snort;
DROP VIEW if exists calculo_detecciones_fortigate;

DROP TABLE if exists deteccion_snort;
DROP TABLE if exists deteccion_fortigate;
DROP TABLE if exists temp_deteccion_snort;
DROP TABLE if exists temp_deteccion_fortigate;

DROP TABLE if exists resumen;
DROP TABLE if exists temp_resumen;


DROP TABLE if exists caracterizacion_pcaps_ataque;
DROP TABLE if exists temp_caracterizacion_pcaps_ataque;
DROP TABLE if exists caracterizacion_pcaps_legitimo;
DROP TABLE if exists temp_caracterizacion_pcaps_legitimo;

CREATE TABLE resumen (
tactica varchar(1000),
tecnica varchar(1000),
idtecnica varchar(1000),
tactica_adicional varchar(1000),
tecnicaimplementada INTEGER,
subtecnica varchar(1000),
idsubtecnica varchar(1000),
tecnica_adicional varchar(1000),
detectablered INTEGER,
solodetectablered INTEGER,
detectableporpatrones varchar(1000),
mecanismodeteccion varchar(1000),
subtecnicaimplementada INTEGER,
PRIMARY KEY (tactica,tecnica,subtecnica)
);

CREATE TEXT TABLE temp_resumen (
tactica varchar(1000),
tecnica varchar(1000),
idtecnica varchar(1000),
tactica_adicional varchar(1000),
tecnicaimplementada INTEGER,
subtecnica varchar(1000),
idsubtecnica varchar(1000),
tecnica_adicional varchar(1000),
detectablered INTEGER,
solodetectablered INTEGER,
detectableporpatrones varchar(1000),
mecanismodeteccion varchar(1000),
subtecnicaimplementada INTEGER,
PRIMARY KEY (tactica,idtecnica,idsubtecnica)
);

CREATE TABLE caracterizacion_pcaps_ataque (
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
nflujosconataque INTEGER,
nmensajesconataque INTEGER,
ninstanciastotales INTEGER,
ninstanciasprincipales INTEGER,
ninstanciascolaterales INTEGER,
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
usado_analisis INTEGER
);

CREATE TEXT TABLE temp_caracterizacion_pcaps_ataque (
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
nflujosconataque INTEGER,
nmensajesconataque INTEGER,
ninstanciastotales INTEGER,
ninstanciasprincipales INTEGER,
ninstanciascolaterales INTEGER,
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
usado_analisis INTEGER
);

CREATE TABLE deteccion_snort (
ficheropcap varchar(1000) REFERENCES caracterizacion_pcaps_ataque(ficheropcap),
nflujosdetectados_snortv2 INTEGER,
nflujosdetectados_snortv3 INTEGER,
nalertas_rs1 INTEGER,
nflujosataquedetectados_rs1 INTEGER,
nmensajesataquedetectados_rs1 INTEGER,
nataquesdetectados_rs1 INTEGER,
nflujosataqueTPdetectados_rs1_manual INTEGER,
nmensajesataqueTPdetectados_rs1_manual INTEGER,
nataquesTPdetectados_rs1_manual INTEGER,
nflujosataqueTPdetectados_rs1_automatico INTEGER,
nmensajesataqueTPdetectados_rs1_automatico INTEGER,
nataquesTPdetectados_rs1_automatico INTEGER,

nalertas_rs2 INTEGER,
nflujosataquedetectados_rs2 INTEGER,
nmensajesataquedetectados_rs2 INTEGER,
nataquesdetectados_talos_rs2 INTEGER,
nataquesdetectados_etopen_rs2 INTEGER,
nataquesdetectados_rs2_manual INTEGER,
nflujosataqueTPdetectados_rs2_manual INTEGER,
nmensajesataqueTPdetectados_rs2_manual INTEGER,
nataquesTPdetectados_rs2_manual INTEGER,
nflujosataqueTPdetectados_rs2_automatico INTEGER,
nmensajesataqueTPdetectados_rs2_automatico INTEGER,
nataquesTPdetectados_talos_rs2_automatico INTEGER,
nataquesTPdetectados_etopen_rs2_automatico INTEGER,
nataquesTPdetectados_rs2_automatico_manual INTEGER,

nalertas_rs3 INTEGER,
nflujosataquedetectados_rs3 INTEGER,
nmensajesataquedetectados_rs3 INTEGER,
nataquesdetectados_talos_rs3 INTEGER,
nataquesdetectados_etopen_rs3 INTEGER,
nataquesdetectados_rs3_manual INTEGER,
nflujosataqueTPdetectados_rs3_manual INTEGER,
nmensajesataqueTPdetectados_rs3_manual INTEGER,
nataquesTPdetectados_rs3_manual INTEGER,
nflujosataqueTPdetectados_rs3_automatico INTEGER,
nmensajesataqueTPdetectados_rs3_automatico INTEGER,
nataquesTPdetectados_talos_rs3_automatico INTEGER,
nataquesTPdetectados_etopen_rs3_automatico INTEGER,
nataquesTPdetectados_rs3_automatico_manual INTEGER,

nalertas_rs4 INTEGER,
nflujosataquedetectados_rs4 INTEGER,
nmensajesataquedetectados_rs4 INTEGER,
nataquesdetectados_talos_rs4 INTEGER,
nataquesdetectados_etopen_rs4 INTEGER,
nataquesdetectados_rs4_manual INTEGER,
nflujosataqueTPdetectados_rs4_manual INTEGER,
nmensajesataqueTPdetectados_rs4_manual INTEGER,
nataquesTPdetectados_rs4_manual INTEGER,
nflujosataqueTPdetectados_rs4_automatico INTEGER,
nmensajesataqueTPdetectados_rs4_automatico INTEGER,
nataquesTPdetectados_talos_rs4_automatico INTEGER,
nataquesTPdetectados_etopen_rs4_automatico INTEGER,
nataquesTPdetectados_rs4_automatico_manual INTEGER

);

CREATE TEXT TABLE temp_deteccion_snort (
ficheropcap varchar(1000) REFERENCES caracterizacion_pcaps_ataque(ficheropcap),
nflujosdetectados_snortv2 INTEGER,
nflujosdetectados_snortv3 INTEGER,
nalertas_rs1 INTEGER,
nflujosataquedetectados_rs1 INTEGER,
nmensajesataquedetectados_rs1 INTEGER,
nataquesdetectados_rs1 INTEGER,
nflujosataqueTPdetectados_rs1_manual INTEGER,
nmensajesataqueTPdetectados_rs1_manual INTEGER,
nataquesTPdetectados_rs1_manual INTEGER,
nflujosataqueTPdetectados_rs1_automatico INTEGER,
nmensajesataqueTPdetectados_rs1_automatico INTEGER,
nataquesTPdetectados_rs1_automatico INTEGER,

nalertas_rs2 INTEGER,
nflujosataquedetectados_rs2 INTEGER,
nmensajesataquedetectados_rs2 INTEGER,
nataquesdetectados_talos_rs2 INTEGER,
nataquesdetectados_etopen_rs2 INTEGER,
nataquesdetectados_rs2_manual INTEGER,
nflujosataqueTPdetectados_rs2_manual INTEGER,
nmensajesataqueTPdetectados_rs2_manual INTEGER,
nataquesTPdetectados_rs2_manual INTEGER,
nflujosataqueTPdetectados_rs2_automatico INTEGER,
nmensajesataqueTPdetectados_rs2_automatico INTEGER,
nataquesTPdetectados_talos_rs2_automatico INTEGER,
nataquesTPdetectados_etopen_rs2_automatico INTEGER,
nataquesTPdetectados_rs2_automatico_manual INTEGER,

nalertas_rs3 INTEGER,
nflujosataquedetectados_rs3 INTEGER,
nmensajesataquedetectados_rs3 INTEGER,
nataquesdetectados_talos_rs3 INTEGER,
nataquesdetectados_etopen_rs3 INTEGER,
nataquesdetectados_rs3_manual INTEGER,
nflujosataqueTPdetectados_rs3_manual INTEGER,
nmensajesataqueTPdetectados_rs3_manual INTEGER,
nataquesTPdetectados_rs3_manual INTEGER,
nflujosataqueTPdetectados_rs3_automatico INTEGER,
nmensajesataqueTPdetectados_rs3_automatico INTEGER,
nataquesTPdetectados_talos_rs3_automatico INTEGER,
nataquesTPdetectados_etopen_rs3_automatico INTEGER,
nataquesTPdetectados_rs3_automatico_manual INTEGER,

nalertas_rs4 INTEGER,
nflujosataquedetectados_rs4 INTEGER,
nmensajesataquedetectados_rs4 INTEGER,
nataquesdetectados_talos_rs4 INTEGER,
nataquesdetectados_etopen_rs4 INTEGER,
nataquesdetectados_rs4_manual INTEGER,
nflujosataqueTPdetectados_rs4_manual INTEGER,
nmensajesataqueTPdetectados_rs4_manual INTEGER,
nataquesTPdetectados_rs4_manual INTEGER,
nflujosataqueTPdetectados_rs4_automatico INTEGER,
nmensajesataqueTPdetectados_rs4_automatico INTEGER,
nataquesTPdetectados_talos_rs4_automatico INTEGER,
nataquesTPdetectados_etopen_rs4_automatico INTEGER,
nataquesTPdetectados_rs4_automatico_manual INTEGER
);

CREATE TABLE deteccion_fortigate (
ficheropcap varchar(1000) REFERENCES caracterizacion_pcaps_ataque(ficheropcap),
nflujosidentificados INTEGER,
nflujosconataquedetectados INTEGER,
comentariosdetecciones varchar(4000)
);

CREATE TEXT TABLE temp_deteccion_fortigate (
ficheropcap varchar(1000) REFERENCES caracterizacion_pcaps_ataque(ficheropcap),
nflujosidentificados INTEGER,
nflujosconataquedetectados INTEGER,
comentariosdetecciones varchar(4000)
);

CREATE TABLE caracterizacion_pcaps_legitimo (
ficheropcap varchar(1000) PRIMARY KEY,
tipotrafico varchar(1000),
categoria varchar(1000),
tamanoreal_Mb numeric(10,5),
nflujos INTEGER,
ndirecciones INTEGER,
flujoscompletos INTEGER
);

CREATE TABLE alertas_ataque_snort (
ficheropcap varchar(1000) REFERENCES caracterizacion_pcaps_ataque(ficheropcap),
sid INTEGER,
ruleset INTEGER,
TP INTEGER,
);

CREATE TEXT TABLE temp_alertas_ataque_snort (
ficheropcap varchar(1000) REFERENCES caracterizacion_pcaps_ataque(ficheropcap),
sid INTEGER,
ruleset INTEGER,
TP INTEGER
);

CREATE TABLE alertas_legitimo_snort (
ficheropcap varchar(1000) REFERENCES caracterizacion_pcaps_legitimo(ficheropcap),
sid INTEGER,
ruleset INTEGER,

);

CREATE TEXT TABLE temp_alertas_legitimo_snort (
ficheropcap varchar(1000) REFERENCES caracterizacion_pcaps_legitimo(ficheropcap),
sid INTEGER,
ruleset INTEGER,

);

CREATE TABLE alertas_ataque_FG (
ficheropcap varchar(1000) REFERENCES caracterizacion_pcaps_ataque(ficheropcap),
attackid INTEGER,
TP INTEGER
);

CREATE TEXT TABLE temp_alertas_ataque_FG (
ficheropcap varchar(1000) REFERENCES caracterizacion_pcaps_ataque(ficheropcap),
attackid INTEGER,
TP INTEGER
);


CREATE TEXT TABLE temp_caracterizacion_pcaps_legitimo (
ficheropcap varchar(1000) PRIMARY KEY,
tipotrafico varchar(1000),
categoria varchar(1000),
tamanoreal_Mb numeric(10,5),
nflujos INTEGER,
ndirecciones INTEGER,
flujoscompletos INTEGER
);



CREATE VIEW calculo_detecciones_snort AS
SELECT
    captura.ficheropcap AS ficheropcap_captura,
    (CAST(snort.nflujosataquedetectados_rs1  AS DECIMAL(16, 4)) / 
     CAST(captura.nflujosconataque AS DECIMAL(16, 4))) AS deteccionflujos_rs1,
    (CAST(snort.nflujosataqueTPdetectados_rs1_automatico  AS DECIMAL(16, 4)) / 
     CAST(captura.nflujosconataque AS DECIMAL(16, 4))) AS deteccionflujosTP_rs1_automatico,
     (CAST(snort.nflujosataqueTPdetectados_rs1_manual  AS DECIMAL(16, 4)) / 
     CAST(captura.nflujosconataque AS DECIMAL(16, 4))) AS deteccionflujosTP_rs1_manual,

     (CAST(snort.nmensajesataquedetectados_rs1  AS DECIMAL(16, 4)) / 
     CAST(captura.nmensajesconataque AS DECIMAL(16, 4))) AS deteccionmensajes_rs1,
    (CAST(snort.nmensajesataqueTPdetectados_rs1_automatico  AS DECIMAL(16, 4)) / 
     CAST(captura.nmensajesconataque AS DECIMAL(16, 4))) AS deteccionmensajesTP_rs1_automatico,
     (CAST(snort.nmensajesataqueTPdetectados_rs1_manual  AS DECIMAL(16, 4)) / 
     CAST(captura.nmensajesconataque AS DECIMAL(16, 4))) AS deteccionmensajesTP_rs1_manual,

(CAST(snort.nataquesdetectados_rs1  AS DECIMAL(16, 4)) / 
     CAST(captura.ninstanciasprincipales AS DECIMAL(16, 4))) AS deteccioninstancias_rs1,
    (CAST(snort.nataquesTPdetectados_rs1_automatico  AS DECIMAL(16, 4)) / 
     CAST(captura.ninstanciasprincipales AS DECIMAL(16, 4))) AS deteccioninstanciasTP_rs1_automatico,
     (CAST(snort.nataquesTPdetectados_rs1_manual  AS DECIMAL(16, 4)) / 
     CAST(captura.ninstanciasprincipales AS DECIMAL(16, 4))) AS deteccioninstanciasTP_rs1_manual,


     (CAST(snort.nflujosataquedetectados_rs2  AS DECIMAL(16, 4)) / 
     CAST(captura.nflujosconataque AS DECIMAL(16, 4))) AS deteccionflujos_rs2,
    (CAST(snort.nflujosataqueTPdetectados_rs2_automatico  AS DECIMAL(16, 4)) / 
     CAST(captura.nflujosconataque AS DECIMAL(16, 4))) AS deteccionflujosTP_rs2_automatico,
     (CAST(snort.nflujosataqueTPdetectados_rs2_manual  AS DECIMAL(16, 4)) / 
     CAST(captura.nflujosconataque AS DECIMAL(16, 4))) AS deteccionflujosTP_rs2_manual,

     (CAST(snort.nmensajesataquedetectados_rs2  AS DECIMAL(16, 4)) / 
     CAST(captura.nmensajesconataque AS DECIMAL(16, 4))) AS deteccionmensajes_rs2,
    (CAST(snort.nmensajesataqueTPdetectados_rs2_automatico  AS DECIMAL(16, 4)) / 
     CAST(captura.nmensajesconataque AS DECIMAL(16, 4))) AS deteccionmensajesTP_rs2_automatico,
     (CAST(snort.nmensajesataqueTPdetectados_rs2_manual  AS DECIMAL(16, 4)) / 
     CAST(captura.nmensajesconataque AS DECIMAL(16, 4))) AS deteccionmensajesTP_rs2_manual,

     (CAST(snort.nataquesdetectados_rs2_manual  AS DECIMAL(16, 4)) / 
     CAST(captura.ninstanciasprincipales AS DECIMAL(16, 4))) AS deteccioninstancias_rs2_manual,
 (CAST(snort.nataquesTPdetectados_rs2_manual  AS DECIMAL(16, 4)) / 
     CAST(captura.ninstanciasprincipales AS DECIMAL(16, 4))) AS deteccioninstanciasTP_rs2_manual,
      (CAST(snort.nataquesTPdetectados_rs2_automatico_manual  AS DECIMAL(16, 4)) / 
     CAST(captura.ninstanciasprincipales AS DECIMAL(16, 4))) AS deteccioninstancias_rs2_automatico_manual,


(CAST(snort.nflujosataquedetectados_rs3  AS DECIMAL(16, 4)) / 
     CAST(captura.nflujosconataque AS DECIMAL(16, 4))) AS deteccionflujos_rs3,
    (CAST(snort.nflujosataqueTPdetectados_rs3_automatico  AS DECIMAL(16, 4)) / 
     CAST(captura.nflujosconataque AS DECIMAL(16, 4))) AS deteccionflujosTP_rs3_automatico,
     (CAST(snort.nflujosataqueTPdetectados_rs3_manual  AS DECIMAL(16, 4)) / 
     CAST(captura.nflujosconataque AS DECIMAL(16, 4))) AS deteccionflujosTP_rs3_manual,

     (CAST(snort.nmensajesataquedetectados_rs3  AS DECIMAL(16, 4)) / 
     CAST(captura.nmensajesconataque AS DECIMAL(16, 4))) AS deteccionmensajes_rs3,
    (CAST(snort.nmensajesataqueTPdetectados_rs3_automatico  AS DECIMAL(16, 4)) / 
     CAST(captura.nmensajesconataque AS DECIMAL(16, 4))) AS deteccionmensajesTP_rs3_automatico,
     (CAST(snort.nmensajesataqueTPdetectados_rs3_manual  AS DECIMAL(16, 4)) / 
     CAST(captura.nmensajesconataque AS DECIMAL(16, 4))) AS deteccionmensajesTP_rs3_manual,

     (CAST(snort.nataquesdetectados_rs3_manual  AS DECIMAL(16, 4)) / 
     CAST(captura.ninstanciasprincipales AS DECIMAL(16, 4))) AS deteccioninstancias_rs3_manual,
 (CAST(snort.nataquesTPdetectados_rs3_manual  AS DECIMAL(16, 4)) / 
     CAST(captura.ninstanciasprincipales AS DECIMAL(16, 4))) AS deteccioninstanciasTP_rs3_manual,
      (CAST(snort.nataquesTPdetectados_rs3_automatico_manual  AS DECIMAL(16, 4)) / 
     CAST(captura.ninstanciasprincipales AS DECIMAL(16, 4))) AS deteccioninstancias_rs3_automatico_manual,


(CAST(snort.nflujosataquedetectados_rs4  AS DECIMAL(16, 4)) / 
     CAST(captura.nflujosconataque AS DECIMAL(16, 4))) AS deteccionflujos_rs4,
    (CAST(snort.nflujosataqueTPdetectados_rs4_automatico  AS DECIMAL(16, 4)) / 
     CAST(captura.nflujosconataque AS DECIMAL(16, 4))) AS deteccionflujosTP_rs4_automatico,
     (CAST(snort.nflujosataqueTPdetectados_rs4_manual  AS DECIMAL(16, 4)) / 
     CAST(captura.nflujosconataque AS DECIMAL(16, 4))) AS deteccionflujosTP_rs4_manual,

     (CAST(snort.nmensajesataquedetectados_rs4  AS DECIMAL(16, 4)) / 
     CAST(captura.nmensajesconataque AS DECIMAL(16, 4))) AS deteccionmensajes_rs4,
    (CAST(snort.nmensajesataqueTPdetectados_rs4_automatico  AS DECIMAL(16, 4)) / 
     CAST(captura.nmensajesconataque AS DECIMAL(16, 4))) AS deteccionmensajesTP_rs4_automatico,
     (CAST(snort.nmensajesataqueTPdetectados_rs4_manual  AS DECIMAL(16, 4)) / 
     CAST(captura.nmensajesconataque AS DECIMAL(16, 4))) AS deteccionmensajesTP_rs4_manual,

     (CAST(snort.nataquesdetectados_rs4_manual  AS DECIMAL(16, 4)) / 
     CAST(captura.ninstanciasprincipales AS DECIMAL(16, 4))) AS deteccioninstancias_rs4_manual,
 (CAST(snort.nataquesTPdetectados_rs4_manual  AS DECIMAL(16, 4)) / 
     CAST(captura.ninstanciasprincipales AS DECIMAL(16, 4))) AS deteccioninstanciasTP_rs4_manual,
      (CAST(snort.nataquesTPdetectados_rs4_automatico_manual  AS DECIMAL(16, 4)) / 
     CAST(captura.ninstanciasprincipales AS DECIMAL(16, 4))) AS deteccioninstancias_rs4_automatico_manual
     
FROM
    caracterizacion_pcaps_ataque captura
JOIN
    deteccion_snort snort
ON
    captura.ficheropcap = snort.ficheropcap;


CREATE VIEW calculo_detecciones_fortigate AS
SELECT
    captura.ficheropcap AS ficheropcap_captura,
    (CAST(fortigate.nflujosconataquedetectados  AS DECIMAL(16, 4)) / 
     CAST(captura.nflujosconataque AS DECIMAL(16, 4))) AS deteccionflujos

FROM
    caracterizacion_pcaps_ataque captura
JOIN
    deteccion_fortigate fortigate
ON
    captura.ficheropcap = fortigate.ficheropcap;
