# ESPECIFICACIONES SISTEMA OPERATIVO EN EL QUE SE HA HECHO USO DE TRANALYZER 
#
#  Distributor ID: Ubuntu
#  Description: Ubuntu 22.04.4 LTS
#  Release: 22.04
#  Codename: jammy
#

cd /tmp
wget https://tranalyzer.com/download/tranalyzer/tranalyzer2-0.9.3lmw1.tar.gz
tar xzf tranalyzer2-0.9.3lmw1.tar.gz
cd tranalyzer2-0.9.3lmw1
./setup.sh -T
sudo ./install.sh all
