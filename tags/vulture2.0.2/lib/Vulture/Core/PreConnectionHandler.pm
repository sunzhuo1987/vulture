#file:Core/PreConnectionHandler.pm
#-------------------------
#!/usr/bin/perl
package Core::PreConnectionHandler;

use strict;
use warnings;

use Apache2::Connection ();
use Apache2::Reload;

use DBI;

use Apache2::Const -compile => qw(FORBIDDEN OK);

use Net::IP::Match::Regexp qw( create_iprange_regexp match_ip );

#General IP blacklisting
sub handler {
	warn "########## PreConnectionHandler ##########";
	my $c = shift;
	
	#if we can't get the remote IP, refuse connection
	unless (defined $c and $c->remote_ip){
	    warn "Can't read remote ip\n";
	    return Apache2::Const::FORBIDDEN;
	}

	#Querying database
	my $dbh = DBI->connect("dbi:SQLite:dbname=/var/www/vulture/admin/db");
    my $query = "SELECT ip FROM blackip WHERE app_id IS NULL";
	my $sth = $dbh->prepare($query);
	$sth->execute();
	while (my $ip = $sth->fetchrow) {
        my @IP = split / /, $ip;
		foreach my $ip (@IP){
			my $regexp = Net::IP::Match::Regexp::create_iprange_regexp($ip);
			#refused connection from global BlackIP
			if (Net::IP::Match::Regexp::match_ip($c->remote_ip, $regexp)) {
				warn('IP '.$c->remote_ip.' is blocked by PreConnectionHandler\n');
				return Apache2::Const::FORBIDDEN;
			}
		}
    }
    warn('White IP '.$c->remote_ip.' by PreConnectionHandler\n');
    return Apache2::Const::OK;
}

1;
