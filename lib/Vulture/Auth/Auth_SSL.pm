#file:Auth/Auth_SSL.pm
#---------------------------------
#!/usr/bin/perl
package Auth::Auth_SSL;

use strict;
use warnings;

BEGIN {
    use Exporter ();
    our @ISA       = qw(Exporter);
    our @EXPORT_OK = qw(&checkAuth);
}

use Apache::SSLLookup;
use Apache2::Reload;
use Apache2::Log;

use Apache2::Const -compile => qw(OK FORBIDDEN);

sub checkAuth {
    my ( $package_name, $r, $log, $dbh, $app, $user, 
        $password, $id_method,$session_sso, $class ) = @_;

    my $req = Apache::SSLLookup->new($r);

    $log->debug("########## Auth_SSL ##########");
    if (defined $req->ssl_lookup('SSL_CLIENT_S_DN_CN')){
        my $ssl_user = $req->ssl_lookup('SSL_CLIENT_S_DN_CN');
        unless ($ssl_user){
            $log->error("no client dn cn in ssl auth");
        }
        else{
            $log->debug("SSL mode '$ssl_user'");
            $r->pnotes(username=>$ssl_user);
            return Apache2::Const::OK;
        }
    }
    return Apache2::Const::FORBIDDEN;
}
1;
