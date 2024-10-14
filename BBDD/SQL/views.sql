

CREATE VIEW calculo_detecciones_snort AS
SELECT
    captura.ficheropcap AS ficheropcap_captura,
    (CAST(snort.nflujosataquedetectados_rs1  AS DECIMAL(16, 4)) / 
     CAST(captura.nflujosconataque AS DECIMAL(16, 4))) AS deteccionflujos_rs1,
    (CAST(snort.nflujosataqueTPdetectados_rs1_automatico  AS DECIMAL(16, 4)) / 
     CAST(captura.nflujosconataque AS DECIMAL(16, 4))) AS deteccionflujosTP_rs1_automatico,
     (CAST(snort.nflujosataqueTPdetectados_rs1_manual  AS DECIMAL(16, 4)) / 
     CAST(captura.nflujosconataque AS DECIMAL(16, 4))) AS deteccionflujosTP_rs1_manual,

    (CAST(snort.nflujosataquecolateralTPdetectados_rs1_manual AS DECIMAL(16,4)) + 
CAST(snort.nflujosataqueTPdetectados_rs1_manual AS DECIMAL(16,4))) / 
(CAST(captura.nflujosconataque AS DECIMAL(16, 4)) + CAST(captura.nflujosconataquecolateral AS DECIMAL(16,4))) AS deteccioneficazflujosTP_rs1_manual,

CASE WHEN snort.nflujosataquecolateralTPdetectados_rs1_manual >=1 OR snort.nflujosataqueTPdetectados_rs1_manual>=1 THEN 1 ELSE 0 END AS deteccioneficazataquesTP_rs1_manual,

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

(CAST(snort.nflujosataquecolateralTPdetectados_rs2_manual AS DECIMAL(16,4)) + 
CAST(snort.nflujosataqueTPdetectados_rs2_manual AS DECIMAL(16,4))) / 
(CAST(captura.nflujosconataque AS DECIMAL(16, 4)) + CAST(captura.nflujosconataquecolateral AS DECIMAL(16,4))) AS deteccioneficazflujosTP_rs2_manual,

CASE WHEN snort.nflujosataquecolateralTPdetectados_rs2_manual >=1 OR snort.nflujosataqueTPdetectados_rs2_manual>=1 THEN 1 ELSE 0 END AS deteccioneficazataquesTP_rs2_manual,

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

(CAST(snort.nflujosataquecolateralTPdetectados_rs3_manual AS DECIMAL(16,4)) + 
CAST(snort.nflujosataqueTPdetectados_rs3_manual AS DECIMAL(16,4))) / 
(CAST(captura.nflujosconataque AS DECIMAL(16, 4)) + CAST(captura.nflujosconataquecolateral AS DECIMAL(16,4))) AS deteccioneficazflujosTP_rs3_manual,

CASE WHEN snort.nflujosataquecolateralTPdetectados_rs3_manual >=1 OR snort.nflujosataqueTPdetectados_rs3_manual>=1 THEN 1 ELSE 0 END AS deteccioneficazataquesTP_rs3_manual,

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

(CAST(snort.nflujosataquecolateralTPdetectados_rs4_manual AS DECIMAL(16,4)) + 
CAST(snort.nflujosataqueTPdetectados_rs4_manual AS DECIMAL(16,4))) / 
(CAST(captura.nflujosconataque AS DECIMAL(16, 4)) + CAST(captura.nflujosconataquecolateral AS DECIMAL(16,4))) AS deteccioneficazflujosTP_rs4_manual,

CASE WHEN snort.nflujosataquecolateralTPdetectados_rs4_manual >=1 OR snort.nflujosataqueTPdetectados_rs4_manual>=1 THEN 1 ELSE 0 END AS deteccioneficazataquesTP_rs4_manual,

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
    (CAST(fortigate.nflujosconataquedetectados_total  AS DECIMAL(16, 4)) / 
     CAST(captura.nflujosconataque AS DECIMAL(16, 4))) AS deteccionflujos,

     (CAST(fortigate.nflujosconataquedetectados_eficazmente AS DECIMAL(16,4))) / (CAST(captura.nflujosconataque AS DECIMAL(16, 4)) + CAST(captura.nflujosconataquecolateral AS DECIMAL(16,4))) AS deteccioneficazflujosTP,

     CASE WHEN fortigate.nflujosconataquedetectados_eficazmente >=1 THEN  1 ELSE 0 END AS deteccioneficazataquesTP

FROM
    caracterizacion_pcaps_ataque captura
JOIN
    deteccion_fortigate fortigate
ON
    captura.ficheropcap = fortigate.ficheropcap;


CREATE VIEW calculo_detecciones_paloalto AS
SELECT
    captura.ficheropcap AS ficheropcap_captura,
    (CAST(paloalto.nflujosconataquedetectados_total  AS DECIMAL(16, 4)) / 
     CAST(captura.nflujosconataque AS DECIMAL(16, 4))) AS deteccionflujos,

 (CAST(paloalto.nflujosconataquedetectados_eficazmente AS DECIMAL(16,4))) / (CAST(captura.nflujosconataque AS DECIMAL(16, 4)) + CAST(captura.nflujosconataquecolateral AS DECIMAL(16,4))) AS deteccioneficazflujosTP,

     CASE WHEN paloalto.nflujosconataquedetectados_eficazmente >=1 THEN  1 ELSE 0 END AS deteccioneficazataquesTP

FROM
    caracterizacion_pcaps_ataque captura
JOIN
    deteccion_paloalto paloalto
ON
    captura.ficheropcap = paloalto.ficheropcap;


