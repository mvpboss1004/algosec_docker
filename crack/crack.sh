echo 'Create License...'
ISSUED=`date +"%m-%b-%Y"`
HOSTID=`ifconfig eth0 | awk '/^[a-z]/ { iface=$1; mac=$NF; next } /inet addr:/ { print toupper(mac) }'|awk 'gsub(/:/,"",$1)'`
echo "LICENSE_VER=7.0
EXP_DATE=01-Jan-2050
HOSTID=$HOSTID
ISSUER=root
ISSUED=$ISSUED
LICENSE_INFO1=PerFW;3;your_organization;your_license_id
LICENSE_INFO2=Core;Optimization;Risk
SIGN=12345678" > test.lic
cat test.lic