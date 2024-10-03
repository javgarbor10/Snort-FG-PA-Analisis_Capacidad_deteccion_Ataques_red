
############################

### Añadir la opción "--fragroute" a tcprewrite


wget http://prdownloads.sourceforge.net/libdnet/libdnet-1.11.tar.gz?download
tar xfvz libdnet-1.11.tar.gz
cd libdnet-1.11
apt -y install make gcc g++
./configure
make
sudo make install

cd ..
wget https://www.tcpdump.org/release/libpcap-1.6.2.tar.gz
tar xfvz libpcap-1.6.2.tar.gz
libpcap-1.6.2
./configure
apt -y install flex grammar yacc bison
./configure
make
sudo make install

cd ..
wget http://downloads.sourceforge.net/levent/libevent-2.1.12-stable.tar.gz
tar xfvz libevent-2.1.12-stable.tar.gz
./configure
make
sudo make install
ln -s /usr/local/lib/libdnet.1 /usr/lib/x86_64-linux-gnu/libdnet.1

cd ..
wget https://codeload.github.com/ajkeeton/fragroute/zip/refs/heads/master
# https://github.com/ajkeeton/fragroute
unzip fragroute-master.zip
cd fragroute-master
apt -y install putmsg strlcat libbsd libbsd-dev openssl
./configure --disable-openssl
make
sudo make install

cd ..
wget
https://github.com/appneta/tcpreplay/releases/download/v4.3.4/tcpreplay-4.3.4.tar.gz
tar xfvz tcpreplay-4.3.4.tar.gz
cd tcpreplay-4.3.4
./configure --enable-dynamic-link
make
sudo make install

echo "Estará accesible en: /usr/local/bin/tcprewrite"
