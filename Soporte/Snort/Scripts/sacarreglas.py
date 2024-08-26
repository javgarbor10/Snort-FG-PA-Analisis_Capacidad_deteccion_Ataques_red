import sys


#Saca cuáles son las reglas distintas que han saltado en un ataque

file = sys.argv[1]
f = open(file, "r")
numero = 0
alertas = []
for linea in f:
        tipo = linea.split("[**]")
        numero = numero + 1
        if tipo[1] not in alertas:
	        alertas.append(tipo[1])

print("Nº alertas = " + str(len(alertas)))

for y in alertas:
	print(y)

print("Nº de alertas totales: " + str(numero))
f.close()
