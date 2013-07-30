#file:Auth/Auth_EXAMPLE.pm
#---------------------------------
#!/usr/bin/perl
package Auth::Auth_EXAMPLE;

use strict;
use warnings;

BEGIN {
    use Exporter ();
    our @ISA       = qw(Exporter);
    our @EXPORT_OK = qw(&checkAuth);
}

use Apache2::Reload;
use Apache2::Log;

use Apache2::Const -compile => qw(OK FORBIDDEN);

sub checkAuth {
    my ( $package_name, $r, $log, $dbh, $app, $user, 
        $password, $id_method,$session_sso, $class, $csrf_ok
 ) = @_;

    $log->debug("########## Auth_EXAMPLE ##########");

    if ($user eq 'toto' and $password eq '1111' and $csrf_ok) {
        $r->pnotes( 'username' => $user );
        return Apache2::Const::OK;
    }
    else {
        return Apache2::Const::FORBIDDEN;
    }
}
1;
