#!/usr/bin/perl
#
#
# SAMPLE SCRIPT TO DEMONSTRATE HOW TO FILTER APACHE LOGS
# 
# Apache will pipe logs into this script
# The script will be called with one argument: The type of log (error, access or modsecurity)
#
# Everything that is printed on STDOUT in this script will then be stored (>>) by Apache into /var/log/Vulture*<anything_log> (to be configured via the GUI)
#
#
use strict;

$|=1;                       # Use unbuffered output
my $log_level=$ARGV[0];     # Vulture will send: error, access or security

print while <STDIN>;
