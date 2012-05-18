#!/bin/bash
# check-perls.sh
# Checks all perl dependencies for vulture and eventually install them with cpan
# this script must be updated each time we add/remove perl deps to vulture

perl_deps="
Apache2::Access
Apache2::Connection
Apache2::Const
Apache2::Filter
Apache2::Log
Apache2::Reload
Apache2::Request
Apache2::RequestIO
Apache2::RequestRec
Apache2::RequestUtil
Apache2::Response
Apache2::ServerRec
Apache2::URI
Apache::Session::Flex
Apache::Session::Generate::MD5
APR::SockAddr
APR::Table
APR::URI
Authen::Radius
Authen::Simple::Kerberos
Apache::Session::Store::Memcached
Authen::Smb
Cache::Memcached
Crypt::CBC
Crypt::OpenSSL::AES
Cwd
Data::Dumper
Digest::MD5
Digest::SHA1
Getopt::Std
HTML::Entities
HTML::Form
HTTP::Date
HTTP::Request
LWP::Debug
LWP::UserAgent
MIME::Base64
Net::IP::Match::Regexp
Net::LDAP
Net::LDAP::Util
Sys::Hostname
URI
URI::Escape
WWW::Mechanize
WWW::Mechanize::GZip
"

if ( [ `id -u` -ne 0 ] ) ; then 
       	echo "[-] this script must must be run as root" ; 
	exit 1 ;
fi;
install_all=0;
exit_st=0
for mod in $perl_deps ; do 
	got_dep=1
	if ! ( perl -e "use $mod"  2>/dev/null ); then (
		got_dep=0;
		install_it=0;
		if ( [ $install_all -ne 1 ] ) ; then

			echo -n "[-] Module \"$mod\" missing, try to install it ?[all|yes|no] (yes) : ";
			read opt;
			case $opt in
				all) install_all=1 ;;
				no);;
				yes) install_it=1;;
				*) install_it=1 ;;
			esac;
		fi;
		[ $install_all -eq 1 ] && install_it=1;
		[ $install_it -eq 1 ] && ( ( cpan -fi $mod && got_dep=1 ) || ( echo "[-] Failed to install module $mod" && mod_ok=0 ) );
	)
	[ $got_dep -ne 1 ] && exit_st=1
	fi;
done;
exit $exit_st
