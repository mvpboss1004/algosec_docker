FROM centos:6
LABEL author="mvpboss1004"
ADD ./crack /root/crack
ADD ./fa-6.11.390-150.x86_64.run /root/
WORKDIR /root
RUN curl -o /etc/yum.repos.d/CentOS-Base.repo http://mirrors.aliyun.com/repo/Centos-6.repo;\
curl -o /etc/yum.repos.d/mongodb-org-3.0.repo https://mirrors.aliyun.com/mongodb/yum/redhat/mongodb-org-3.0.repo;\
curl -o /etc/yum.repos.d/mono-centos6-stable.repo https://download.mono-project.com/repo/centos6-stable.repo;\
curl -o /etc/yum.repos.d/epel.repo http://mirrors.aliyun.com/repo/epel-6.repo;\
yum makecache;\
yum install -y cronie httpd mod_ssl sudo postgresql mongodb-org php compat-libtermcap uuid json-c php-ldap php-mbstring php-pdo php-pgsql php-soap php-xml php-xmlrpc mono-devel syslog-ng;\
./fa-6.11.390-150.x86_64.run;\
echo 'Create License...';\
ISSUED=`date +"%m-%b-%Y"`;\
HOSTID=`ifconfig eth0 | awk '/^[a-z]/ { iface=$1; mac=$NF; next } /inet addr:/ { print toupper(mac) }'|awk 'gsub(/:/,"",$1)'`;\
echo "LICENSE_VER=7.0\n\
EXP_DATE=01-Jan-2050\n\
HOSTID=$HOSTID\n\
ISSUER=root\n\
ISSUED=$ISSUED\n\
LICENSE_INFO1=PerFW;3;test;12345678\n\
LICENSE_INFO2=Core;Optimization;Risk\n\
SIGN=12345678" > test.lic;\
cat test.lic;\
mv /usr/share/fa/bin/fa_usage /usr/share/fa/bin/fa_usage.bak;\
chmod +x crack/fa_usage;\
mv crack/fa_usage /usr/share/fa/bin/fa_usage;\
mv /usr/share/fa/perl_lib/FwaLic.pm /usr/share/fa/perl_lib/FwaLic.pm.bak;\
mv crack/FwaLic.pm /usr/share/fa/perl_lib/FwaLic.pm;\
/usr/share/fa/bin/fa_usage -i test.lic
EXPOSE 443