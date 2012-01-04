#file:Auth/Auth_KERBERPS.pm
#---------------------------------
#!/usr/bin/perl
package Auth::Auth_KERBEROS;

use strict;
use warnings;

use Apache2::RequestRec ();
use Apache2::RequestIO ();
use Apache2::Connection ();
use Apache2::Log;
use Apache2::Reload;
use Authen::Simple::Kerberos;

use Apache2::Const -compile => qw(OK FORBIDDEN);

sub checkAuth{
	my ($package_name, $r, $log, $dbh, $app, $user, $password, $id_method) = @_;	

	$log->debug("########## Auth_KERBEROS ##########");

    #Get infos
	my $query = "SELECT * FROM kerberos WHERE id= ?";
    $log->debug($query);
    my $sth = $dbh->prepare($query);
    $sth->execute($id_method);
    my $ref = $sth->fetchrow_hashref;
    $sth->finish();

    my $realm = $ref->{'realm'};

    my $kerberos = Authen::Simple::Kerberos->new(realm => $realm );
    if ( $kerberos->authenticate( $user, $password ) ) {
 		return Apache2::Const::OK;	
    } else {
		return Apache2::Const::FORBIDDEN;
	}
}
1;
