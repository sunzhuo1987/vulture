#file:Core/AccessHandler.pm
#-------------------------
#!/usr/bin/perl
package Core::AccessHandler;

use strict;
use warnings;

use Apache2::RequestRec ();
use Apache2::Reload;
use Apache2::Log;

use DBI;

use Apache2::Const -compile => qw(FORBIDDEN OK);

use Net::IP::Match::Regexp qw( create_iprange_regexp match_ip );

#Particular IP blacklisting (in Application) (different from PreConnectionHandler (global blacklisting))
sub handler {
	my $r = shift;
	my $log = $r->pnotes('log');

	$log->debug("########## AccessHandler ##########");

	my $c = $r->connection(); 
	
	#check if we have remote ip, if not we refuse access
	unless (defined $c and $c->remote_ip){
	    $log->warn("Can't read remote ip");
	    return Apache2::Const::FORBIDDEN;
	}
	
	my $dbh = $r->pnotes('dbh');
	my $app_id = $r->pnotes('app')->{'id'} if defined($r->pnotes('app'));

	#we get BlackIP related to an app
	my $query = "SELECT ip FROM blackip WHERE app_id=?";
	my $sth = $dbh->prepare($query);
	$sth->execute($app_id);
	my $ip = $sth->fetchrow_array;
	if (not $dbh or not $app_id or $ip) {
		my @IP = split / /, $ip;
		foreach my $ip (@IP){
			my $regexp = create_iprange_regexp($ip);
			#refused connection from BlackIP
			if (match_ip($c->remote_ip, $regexp)) {
				$log->warn('IP '.$c->remote_ip.' is blocked');
				return Apache2::Const::FORBIDDEN;
			}
		}
	} else {
		$log->warn('White IP '.$c->remote_ip);
		$r->status(200);
		return Apache2::Const::OK;
	}
}
1;