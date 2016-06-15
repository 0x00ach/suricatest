if [ "$(id -u)" != 0 ]; then
	echo "You must be root."
	exit 4
fi

echo "Installing suricata"
apt-get update
# FROM https://redmine.openinfosecfoundation.org/projects/suricata/wiki/Debian_Installation
apt-get -y install libpcre3 libpcre3-dbg libpcre3-dev build-essential autoconf automake libtool libpcap-dev libnet1-dev libyaml-0-2 libyaml-dev zlib1g zlib1g-dev libmagic-dev libcap-ng-dev libjansson-dev pkg-config
wget http://www.openinfosecfoundation.org/download/suricata-3.0.tar.gz
tar -xvzf suricata-3.0.tar.gz
cd suricata-3.0
./configure --sysconfdir=/etc --localstatedir=/var --enable-unix-socket
make
make install
cd ..
apt-get -y install libjansson4 libjansson-dev python-simplejson
echo "Installing python librairies"
apt-get -y install python-flask python-sqlite
echo "Generating config"
SURIDIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
mkdir suricatalogs
mkdir rules
mkdir suricataconf
cp defaultconf/classification.config suricataconf/
cp defaultconf/reference.config suricataconf/
cp defaultconf/suricata.initdconf suricataconf/
sed s?\<\!\>REPLACEFOLDER\<\!\>?"${SURIDIR}"? defaultconf/suricata.defaultconf > suricataconf/suricata.defaultconf
sed s?\<\!\>REPLACEFOLDER\<\!\>?"${SURIDIR}"? defaultconf/suricata.yaml > suricataconf/suricata.yaml
sed s?\<\!\>REPLACEFOLDER\<\!\>?"${SURIDIR}"? defaultconf/suricata_norules.yaml > suricataconf/suricata_norules.yaml
echo "Copying service files"
cp suricataconf/suricata.initdconf /etc/init.d/suricata
chmod 755 /etc/init.d/suricata
cp suricataconf/suricata.defaultconf /etc/default/suricata
chmod 644 /etc/default/suricata
echo "Starting suricata"
/etc/init.d/suricata start
echo "Starting web service"
python worker.py


