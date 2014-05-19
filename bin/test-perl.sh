#!/bin/bash
# Checks all perl dependencies for vulture and eventually install them with cpan
# this script must be updated each time we add/remove perl deps to vulture


perl_deps="
YAML
namespace::clean
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
Authen::Krb5
Authen::Radius
Authen::Simple::Kerberos
Apache::Session::Store::Memcached
Authen::Smb
Cache::Memcached
CGI
Crypt::CBC
Crypt::OpenSSL::AES
Cwd
Data::Dumper
DBI
Digest::MD5
Digest::SHA1
Encode
Email::MIME
Email::Sender
Exporter
Getopt::Std
GSSAPI
HTML::Entities
HTML::Form
HTTP::Date
HTTP::Request
IPC::Semaphore
IPC::SysV
LWP
LWP::Debug
LWP::UserAgent
Math::Random::Secure
MIME::Base64
MIME::Types
Net::LDAP
Net::LDAP::Util
POSIX
Socket
String::ShellQuote
Sys::Hostname
Try::Tiny
List::Util
URI
URI::Escape
XML::LibXML
WWW::Mechanize
WWW::Mechanize::GZip
"
RED="\\033[1;31m"
GREEN="\\033[1;32m"
WHITE="\\033[0;39m"
if ( [ `id -u` -ne 0 ] ) ; then 
        echo "[-] This script must must be run as root" ; 
    exit 1 ;
fi;
for mod in $perl_deps ; do 
    got_dep=0
    if ! ( perl -I/opt/vulture/lib/ -I/opt/vulture/lib/Vulture -I/opt/vulture/lib/x86_64-linux-gnu-thread-multi -I/opt/vulture/lib/x86_64-linux-thread-multi/ -e "use $mod"  2>/dev/null ); then (
        echo -e "$RED[FAIL]$WHITE - Module \"$mod\" is missing. Please install it before using Vulture"          
    )
    else
        echo -e "$GREEN[OK]$WHITE - Module \"$mod\" is present"         
        got_dep=1
    fi
    if [ $got_dep -ne 1 ]; then
        exit_st=1
    fi 
done;

if [ ! -f /opt/vulture/lib/x86_64-linux-gnu-thread-multi/Apache/SSLLookup.pm ] && [ ! -f /opt/vulture/lib/x86_64-linux-thread-multi/Apache/SSLLookup.pm ]; then
    echo -e "$RED[FAIL]$WHITE - Module \"Apache::SSLLookup\" is missing. Please install it before using Vulture"  
    exit_st=1
else
    echo -e "$GREEN[OK]$WHITE - Module \"Apache::SSLLookup\" is present" 
fi

exit $exit_st
