#file:Auth/Auth_KERBERPS.pm
#---------------------------------
#!/usr/bin/perl
package Auth::Auth_KERBEROS;

use strict;
use warnings;

BEGIN {
    use Exporter ();
    our @ISA       = qw(Exporter);
    our @EXPORT_OK = qw(&checkAuth);
}

use Apache2::RequestRec ();
use Apache2::RequestIO  ();
use Apache2::Connection ();
use Apache2::Log;
use Apache2::Reload;
use Authen::Simple::Kerberos;

use Apache2::Const -compile => qw(OK FORBIDDEN);

sub checkAuth {
    my ( $package_name, $r, $log, $dbh, $app, $user, $password, $id_method, $session, $class, $csrf_ok ) =
      @_;

    $log->debug("########## Auth_KERBEROS ##########");
    return Apache2::Const::FORBIDDEN unless $csrf_ok and $user ne '';

    #Get infos
    my $query = "SELECT * FROM kerberos WHERE id= ?";
    $log->debug($query);
    my $sth = $dbh->prepare($query);
    $sth->execute($id_method);
    my $ref = $sth->fetchrow_hashref;
    $sth->finish();

    my $realm = $ref->{'realm'};

    my @realms = ();
    while ( $realm =~ /.*?([^;\s]+)/g){
        push (@realms, $1);
    }
    if (not scalar @realms){
        $log->error("Invalid kerberos realm in configuration\n");
        return Apache2::Const::FORBIDDEN;
    }

    my $user_name = $user;
    my $user_realm = $realms[0];

    if ($user =~ /([^@]+)@(.*)/){
        $user_name = $1;
        $user_realm = '';
        foreach my $r (@realms){
            if ($2 eq $r){
                $user_realm = $2;
                last;
            }
        }
        if ($user_realm eq ''){
            $log->error("Invalid realm for user $user\n");
            return Apache2::Const::FORBIDDEN;
        }
    }

    my $kerberos = Authen::Simple::Kerberos->new( realm => $user_realm );
    if ( $kerberos->authenticate( $user_name, $password ) ) {
        $r->pnotes( 'username' => "$user_name" );
        return Apache2::Const::OK;
    }
    else {
        return Apache2::Const::FORBIDDEN;
    }
}
1;
