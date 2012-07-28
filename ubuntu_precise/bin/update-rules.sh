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

rm -rf /tmp/vulture$$
rm -f /tmp/.vulture-rules

echo "Ok !"


