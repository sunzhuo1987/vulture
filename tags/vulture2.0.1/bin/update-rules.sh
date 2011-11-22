#!/bin/bash

#######################################
#### DEFINE YOUR HTTP PROXY IF ANY ####
#######################################
#PROXY="http://<ip>:<port>/"

#######################################
#######################################

BASEDIR="/var/www/vulture"
CONFDIR=$BASEDIR/conf
FETCH_SCRIPT=$BASEDIR/bin/rules-updater.pl

#FETCH latest Modesecurity CRS
mkdir /tmp/vulture$$ || exit

echo "Fetching rules... "
if [ -n "$PROXY" ]; then
	perl $FETCH_SCRIPT -x$PROXY -rhttp://www.modsecurity.org/autoupdate/repository/ -p/tmp/vulture$$ -Smodsecurity-crs 2> /dev/null || exit 
else
	perl $FETCH_SCRIPT -rhttp://www.modsecurity.org/autoupdate/repository/ -p/tmp/vulture$$ -Smodsecurity-crs 2> /dev/null || exit 
fi


echo "Deflate... "
cd /tmp/vulture$$/modsecurity-crs/
RULEFILE=`ls *.zip`
unzip $RULEFILE > /dev/null || exit

echo "Install... "
mkdir -p $CONFDIR/security-rules
cp -rf base_rules $CONFDIR/security-rules/
cp -rf optional_rules  $CONFDIR/security-rules/
cp -rf slr_rules $CONFDIR/security-rules/
cp -rf experimental_rules $CONFDIR/security-rules/

echo "Dumping rules into database... "
rm -f /tmp/.vulture-rules
#WE ARE IGNORING inbound and outbound blocking rules 'cause they are managed trough Vulture
for i in `find $CONFDIR/security-rules/base_rules/ -name *.conf |grep -v bound_blocking`; do
	echo "Include $i" >> /tmp/.vulture-rules
done
data=`cat /tmp/.vulture-rules`
BASE_RULE=`sqlite3 $BASEDIR/admin/db "SELECT count(*) from modsecurity where name='RULES: OWASP ModSecurity Core - BASE'"`
if [ $BASE_RULE = 0 ]; then
	CMD="INSERT INTO modsecurity (name, rules) VALUES ('RULES: OWASP ModSecurity Core - BASE','$data')";
else
	CMD="UPDATE modsecurity SET rules='$data' WHERE name='RULES: OWASP ModSecurity Core - BASE'";
fi
sqlite3 $BASEDIR/admin/db "$CMD" || exit

rm -f /tmp/.vulture-rules
for i in `find $CONFDIR/security-rules/optional_rules/ -name *.conf`; do
	echo "Include $i" >> /tmp/.vulture-rules
done
data=`cat /tmp/.vulture-rules`
OPT_RULE=`sqlite3 $BASEDIR/admin/db "SELECT count(*) from modsecurity where name='RULES: OWASP ModSecurity Core - OPTIONAL'"`
if [ $BASE_RULE = 0 ]; then
	CMD="INSERT INTO modsecurity (name, rules) VALUES ('RULES: OWASP ModSecurity Core - OPTIONAL','$data')";
else
	CMD="UPDATE modsecurity SET rules='$data' WHERE name='RULES: OWASP ModSecurity Core - OPTIONAL'";
fi
sqlite3 $BASEDIR/admin/db "$CMD" || exit

rm -f /tmp/.vulture-rules
for i in `find $CONFDIR/security-rules/slr_rules/ -name *.conf`; do
	echo "Include $i" >> /tmp/.vulture-rules
done
data=`cat /tmp/.vulture-rules`
SLR_RULE=`sqlite3 $BASEDIR/admin/db "SELECT count(*) from modsecurity where name='RULES: OWASP ModSecurity Core - SpiderLabs Research'"`
if [ $SLR_RULE = 0 ]; then
	CMD="INSERT INTO modsecurity (name, rules) VALUES ('RULES: OWASP ModSecurity Core - SpiderLabs Research','$data')";
else
	CMD="UPDATE modsecurity SET rules='$data' WHERE name='RULES: OWASP ModSecurity Core - SpiderLabs Research'";
fi
sqlite3 $BASEDIR/admin/db "$CMD" || exit

rm -f /tmp/.vulture-rules
for i in `find $CONFDIR/security-rules/experimental_rules/ -name *.conf`; do
	echo "Include $i" >> /tmp/.vulture-rules
done
data=`cat /tmp/.vulture-rules`
EXP_RULE=`sqlite3 $BASEDIR/admin/db "SELECT count(*) from modsecurity where name='RULES: OWASP ModSecurity Core - EXPERIMENTAL'"`
if [ $EXP_RULE = 0 ]; then
	CMD="INSERT INTO modsecurity (name, rules) VALUES ('RULES: OWASP ModSecurity Core - EXPERIMENTAL','$data')";
else
	CMD="UPDATE modsecurity SET rules='$data' WHERE name='RULES: OWASP ModSecurity Core - EXPERIMENTAL'";
fi
sqlite3 $BASEDIR/admin/db "$CMD" || exit

rm -rf /tmp/vulture$$
rm -f /tmp/.vulture-rules

echo "Ok !"


