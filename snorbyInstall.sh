#!/bin/sh
#
# Snorby/Snort install script for FreeBSD
#
# Version: 0.4.6
#
# Prereqs
# Minimal FreeBSD 9.1 install with ports
# Static IP defined on an interface (in rc.conf)
# freebsd-update fetch install (then reboot the system to make sure the system binaries are up to date)
#
# Run the following to update the ports tree:
# portsnap fetch extract
# portaudit -Fda
# portupgrade -fa --batc
#
# Install Versions
# OS: FreeBSD 9.1-RC3 amd64
# Snort: 2.9.2
# DAQ: 0.6.2
# PulledPork: 0.6.1
# Snorby: 2.5.1
#
UID=`id -u`;

if [ $UID -ne "0" ];
then
	echo "Error: This script must run as root";
	exit 13;
fi


if [ ! $1 ];
then
	echo "Usage snorbyInstall.sh <oinkcode>";
	echo "";
	echo "You need to supply a correct oinkcode.";
	echo "You can retrieve an oinkcode by registering at";
	echo "http://www.snort.org";
	exit 13;
fi


FBSD_IPADDRESS=`cat /etc/rc.conf|grep ifconfig|awk '{print $2}'`

if [ ! $FBSD_IPADDRESS ] || [ "$FBSD_IPADDRESS" == "inet" ];
then
	echo "Error: a static IP is required for setting up Snorby";
	echo "";
	exit 13;
fi

FBSD_INTERFACE=`cat /etc/rc.conf|grep ifconfig|awk -F\_ '{print $2}' | awk -F\= '{print $1}'`

if [ ! $FBSD_INTERFACE ];
then
	echo "Error: an interface has not been configured with a static IP which is required for Snorby";
	echo "";
	exit 13;
fi

LOCALHOST=`hostname`

# Install the necessary ports

cd /usr/ports/ftp/wget
make -DBATCH install clean
cd /usr/ports/textproc/flex
make -DBATCH install clean
cd /usr/ports/devel/pcre
make -DBATCH install clean
cd /usr/ports/net/libdnet/
make -DBATCH install clean
cd /usr/ports/www/apache22
make -DBATCH THREADS=on PROXY=on PROXY_HTTP=on install clean
cd /usr/ports/textproc/libxml2
make -DBATCH install clean
cd /usr/ports/textproc/libxslt
make -DBATCH install clean
echo "WITHOUT_X11=yes" >> /etc/make.conf
cd /usr/ports/graphics/ImageMagick
make -DBATCH install clean
cd /usr/ports/databases/mysql55-server/
make -DBATCH OPENSSL=yes install clean
chown -R mysql:mysql /var/db/mysql
cd /usr/ports/devel/lwp
make -DBATCH install clean
cd /usr/ports/www/p5-LWP-UserAgent-WithCache/
make -DBATCH install clean
cd /usr/ports/security/p5-Crypt-SSLeay
make -DBATCH install clean
cd /usr/ports/www/p5-LWP-Protocol-https
make -DBATCH install clean
echo "RUBY_DEFAULT_VER=1.9" >> /etc/make.conf
cd /usr/ports/devel/ruby-gems/
make -DBATCH install clean
rehash
echo "Packages Installed" >> /root/log.install


#Pulled pork
mkdir -p /usr/local/etc/snort
mkdir -p /usr/local/lib/snort_dynamicrules/
mkdir -p /usr/local/etc/snort
mkdir -p /usr/local/etc/snort/rules
mkdir -p /usr/local/etc/snort/so_rules
mkdir -p /usr/local/etc/snort/preproc_rules
mkdir -p /var/log/snort
mkdir -p /var/log/barnyard2
touch /usr/local/etc/snort/rules/local.rules
touch /usr/local/etc/snort/rules/white_list.rules
touch /usr/local/etc/snort/rules/black_list.rules
touch /var/log/snort/barnyard2.waldo


cd /usr/src/snort
/usr/local/bin/wget http://pulledpork.googlecode.com/files/pulledpork-0.6.1.tar.gz
tar -xzf pulledpork*
cd /usr/src/snort/pulledpork-0.6.1
sed -i '' -e 's/|<oinkcode>/|'"$OINKCODE"'/g' /usr/src/snort/pulledpork-0.6.1/etc/pulledpork.conf
sed -i '' -e "s/rule_url=https:\/\/rules.emergingthreats.net\/|/#/g" /usr/src/snort/pulledpork-0.6.1/etc/pulledpork.conf
sed -i '' -e "s/distro=FreeBSD-8.0/distro=FreeBSD-8-1/g" /usr/src/snort/pulledpork-0.6.1/etc/pulledpork.conf
/usr/src/snort/pulledpork-0.6.1/pulledpork.pl -c /usr/src/snort/pulledpork-0.6.1/etc/pulledpork.conf
rehash

echo "PulledPork Installed" >> /root/log.install

#Snort and Barnyard install
mkdir /usr/src/snort
cd /usr/src/snort
/usr/local/bin/wget http://www.snort.org/dl/snort-current/snort-2.9.2.1.tar.gz -O snort.tar.gz
/usr/local/bin/wget http://www.snort.org/dl/snort-current/daq-0.6.2.tar.gz -O daq.tar.gz
tar -xvf snort.tar.gz 
tar -xzf daq.tar.gz
cd daq-0.6.2
./configure
make
make install

echo "DAQ Installed" >> /root/log.install

cd ../snort-2.9.2.1
./configure --enable-sourcefire
#./configure --enable-ipv6 --enable-gre --enable-mpls --enable-targetbased --enable-decoder-prepocessor-rules \
#--enable-ppm --enable-perfprofiling --enable-zlib --enable-active-response --enable-normalizer --enable-reload \
#--enable-react --enable-flexresp3
make
make install

#new snort.conf required from ruleset before continuing.
cd /tmp
tar -xzf snortrules-snapshot-2921.tar.gz
cp /tmp/etc/*.conf /usr/local/etc/snort
cp /tmp/etc/*.map /usr/local/etc/snort

#cp /usr/src/snort/snort-2.9.2.1/etc/*.conf* /usr/local/etc/snort/
#cp /usr/src/snort/snort-2.9.2.1/etc/*.map /usr/local/etc/snort/

sed -i '' "s/ipvar HOME_NET any/ipvar HOME_NET \[${FBSD_IPADDRESS}\/32\]/" /usr/local/etc/snort/snort.conf
sed -i '' 's/ipvar EXTERNAL_NET any/ipvar EXTERNAL_NET \[!\$HOME_NET\]/' /usr/local/etc/snort/snort.conf
sed -i '' 's/var RULE_PATH \.\.\/rules/var RULE_PATH rules/' /usr/local/etc/snort/snort.conf
sed -i '' 's/var WHITE_LIST_PATH \.\.\/rules/var WHITE_LIST_PATH rules/' /usr/local/etc/snort/snort.conf
sed -i '' 's/var BLACK_LIST_PATH \.\.\/rules/var BLACK_LIST_PATH rules/' /usr/local/etc/snort/snort.conf
sed -i '' 's/var SO_RULE_PATH \.\.\/so_rules/var SO_RULE_PATH so_rules/' /usr/local/etc/snort/snort.conf
sed -i '' 's/var PREPROC_RULE_PATH \.\.\/preproc_rules/var PREPROC_RULE_PATH preproc_rules/' /usr/local/etc/snort/snort.conf
sed -i '' '/^include \$RULE_PATH\/.*.rules$/d' /usr/local/etc/snort/snort.conf
echo "output unified2: filename snortunified2.log, limit 128" >> /usr/local/etc/snort/snort.conf
echo "include \$RULE_PATH/local.rules" >> /usr/local/etc/snort/snort.conf
echo "include \$RULE_PATH/snort.rules" >> /usr/local/etc/snort/snort.conf
grep '^[^#]' /usr/local/etc/snort/snort.conf > /usr/local/etc/snort/temp.conf
mv -f /usr/local/etc/snort/temp.conf /usr/local/etc/snort/snort.conf

rehash
echo "Snort Installed" >> /root/log.install

cd /usr/src/snort
wget http://www.securixlive.com/download/barnyard2/barnyard2-1.9.tar.gz
tar -xzf barnyard2-1.9*
cd barnyard2-1.9
./configure --with-mysql
make
make install
rehash

#barnyard conf
cat << EOF > /usr/local/etc/barnyard2.conf
config reference_file:	    /usr/local/etc/snort/reference.config
config classification_file: /usr/local/etc/snort/classification.config
config gen_file:            /usr/local/etc/snort/gen-msg.map
config sid_file:	        /usr/local/etc/snort/sid-msg.map
config hostname: 	${LOCALHOST}
config interface:	${FBSD_INTERFACE}
input unified2
output database: log, mysql, user=snorby password=s3cr3tsauce dbname=snorby host=localhost

EOF

rehash
echo "Barnyard Installed" >> /root/log.install




#Snorby stuff
cd /usr/ports/devel/git
make -DBATCH install clean
rehash

gem update --system

/usr/local/bin/gem install prawn thor i18n bundler tzinfo builder memcache-client rack rack-test erubis mail text-format sqlite3 --no-rdoc --no-ri
/usr/local/bin/gem install rake --no-rdoc --no-ri
/usr/local/bin/gem install mysql --no-rdoc --no-ri
/usr/local/bin/gem install rack-mount --no-rdoc --no-ri
/usr/local/bin/gem install rails --no-rdoc --no-ri
#/usr/local/bin/gem install passenger --no-rdoc --no-ri
sleep 5 
#/usr/local/bin/passenger-install-apache2-module -a

cd /usr/src/snort/
wget --no-check-certificate https://github.com/Snorby/snorby/zipball/v2.5.1
tar -xzf v2.5.1
mv Snorby-* Snorby
mv /usr/src/snort/Snorby /usr/local/www/Snorby


pkg_add -r wkhtmltopdf


cd /usr/local/www/Snorby/config/
cp database.example.yml database.yml
sed -i '' -e 's/password: # Example: //g' database.yml

cat << EOF > snorby_config.yml 
development:
  domain: localhost:3000
  wkhtmltopdf: /usr/local/bin/wkhtmltopdf
  mailer_sender: 'snorby@snorby.org'
  rules: 
    - "/Users/mephux/.snort/rules"
    - "/Users/mephux/.snort/so_rules"

test:
  domain: localhost:3000
  wkhtmltopdf: /usr/local/bin/wkhtmltopdf
  mailer_sender: 'snorby@snorby.org'

#
# Production
#
# Change the production configuration for your environment.
#
production:
  domain: localhost
  wkhtmltopdf: /usr/local/bin/wkhtmltopdf
  mailer_sender: 'snorby@snorby.org'
  geoip_uri: "http://geolite.maxmind.com/download/geoip/database/GeoLiteCountry/GeoIP.dat.gz"
  rules:
   - "/usr/local/etc/snort/rules"
   - "/usr/local/etc/snort/so_rules"
   - "/usr/local/etc/snort/preproc_rules"
  authentication_mode: database
EOF

/usr/local/etc/rc.d/mysql-server onestart
mysqladmin -u root password 's3cr3tsauce'

rehash
chown -R www:www /usr/local/www/Snorby
cd /usr/local/www/Snorby
bundle pack
bundle install --path vender/cache
bundle exec rake snorby:setup 
mysql -uroot -ps3cr3tsauce -e "GRANT ALL ON snorby.* TO snorby@localhost IDENTIFIED BY 's3cr3tsauce';"
mysql -uroot -ps3cr3tsauce -e "FLUSH PRIVILEGES;"
chown -R www:www /usr/local/www/Snorby


echo "MySQL and Snorby SETUP done" >> /root/log.install

#Apache
sed -i '' -e 's/"\/usr\/local\/www\/apache22\/data"/"\/usr\/local\/www\/Snorby\/public"/g' /usr/local/etc/apache22/httpd.conf
sed -i '' -e 's/#Include etc\/apache22\/extra\/httpd-vhosts.conf/Include etc\/apache22\/extra\/httpd-vhosts.conf/g' /usr/local/etc/apache22/httpd.conf

echo "LoadModule passenger_module  /usr/local/lib/ruby/gems/1.9/gems/passenger-3.0.11/ext/apache2/mod_passenger.so" >> /usr/local/etc/apache22/httpd.conf
echo "PassengerRoot  /usr/local/lib/ruby/gems/1.9/gems/passenger-3.0.11" >> /usr/local/etc/apache22/httpd.conf
echo "PassengerRuby /usr/local/bin/ruby19" >> /usr/local/etc/apache22/httpd.conf
echo "" >> /usr/local/etc/apache22/httpd.conf
echo "ServerTokens Prod" >> /usr/local/etc/apache22/httpd.conf 
echo "ServerName  ${LOCALHOST}:80" >> /usr/local/etc/apache22/httpd.conf

cat << EOF > /usr/local/etc/apache22/extra/httpd-vhosts.conf
<VirtualHost *:80>
 ServerName ${LOCALHOST}
 DocumentRoot /usr/local/www/Snorby/public
 #RailsBaseURI /
 <Directory "/usr/local/www/Snorby/public">
 AllowOverride all
 Order deny,allow
 Allow from all
 Options -MultiViews
 </Directory>
</VirtualHost>
EOF

echo "Apache setup done" >> /root/log.install



cat << EOF > /usr/local/etc/snorbyfix.sh;
#!/bin/sh
#Local fixes for Snorby with Apache
#
TEST=\`ps aux|grep delayed_job\`;

if [ ! \$TEST ];
then
	cd /usr/local/www/Snorby;
	/usr/local/bin/ruby script/delayed_job start;
fi
EOF

chmod 700 /usr/local/etc/snorbyfix.sh;

cat << EOF >> /etc/crontab;
#
#Cronjob for snorby fix.
*/5      *       *       *       *       root    /usr/local/etc/snorbyfix.sh
EOF


echo 'accf_http_load="YES"' >> /boot/loader.conf
echo "$FBSD_IPADDRESS   $LOCALHOST    $LOCALHOST.localdomain" >> /etc/hosts

cat << EOF > /usr/local/etc/rc.d/snort;
#!/bin/sh

# \$FreeBSD\$
#
# PROVIDE: snort
# REQUIRE: LOGIN
# KEYWORD: shutdown
#
# Add the following lines to /etc/rc.conf.local or /etc/rc.conf
# to enable this service:
#
# snort_enable (bool):   Set to NO by default.
#               Set it to YES to enable snort.
# snort_config (path):   Set to /usr/local/etc/snort/snort.conf
#               by default.
#

. /etc/rc.subr

name="snort"
rcvar=\${name}_enable

command=/usr/local/bin/\${name}
pidfile=/var/run/\${name}_${FBSD_INTERFACE}.pid

load_rc_config \$name

: \${snort_enable="NO"}
: \${snort_config="/usr/local/etc/snort/snort.conf"}

command_args="--pid-path \$pidfile -c \$snort_config -D not arp"

run_rc_command "\$1"

EOF
chmod 555 /usr/local/etc/rc.d/snort;

cat << EOF > /usr/local/etc/rc.d/barnyard2;
#!/bin/sh

# \$FreeBSD\$
#
# PROVIDE: barnyard2
# REQUIRE: mysql LOGIN
# KEYWORD: shutdown
#
# Add the following lines to /etc/rc.conf.local or /etc/rc.conf
# to enable this service:
#
# barnyard2_enable (bool):   Set to NO by default.
#               Set it to YES to enable barnyard2.
# barnyard2_config (path):   Set to /usr/local/etc/barnyard2.conf
#               by default.
#

. /etc/rc.subr

name="barnyard2"
rcvar=\${name}_enable

command=/usr/local/bin/\${name}
pidfile=/var/run/\${name}_${FBSD_INTERFACE}.pid

load_rc_config \$name

: \${barnyard2_enable="NO"}
: \${barnyard2_config="/usr/local/etc/barnyard2.conf"}

command_args="-c \$barnyard2_config -d /var/log/snort -f snortunified2.log -w /var/log/snort/barnyard2.waldo --pid-path \$pidfile -D"

run_rc_command "\$1"

EOF
chmod 555 /usr/local/etc/rc.d/barnyard2;


echo 'mysql_enable="YES"' >> /etc/rc.conf.local
echo 'apache22_enable="YES"' >> /etc/rc.conf.local
echo 'snort_enable="YES"' >> /etc/rc.conf.local
echo 'barnyard2_enable="YES"' >> /etc/rc.conf.local

echo "rc.conf/rc.conf.local and system config done" >> /root/log.install


echo 
echo 
echo "Setup is complete: type reboot and when the system comes back up "
echo "you should be able to open a browser from another computer to the following address:"
echo "http://${FBSD_IPADDRESS}/"
echo
echo "Username: snorby@snorby.org"
echo "Password: snorby"
echo
exit 0;

