#file:ACL/ACL_EXAMPLE.pm
#---------------------------------
#!/usr/bin/perl
package ACL::ACL_EXAMPLE;

use strict;
use warnings;

BEGIN {
    use Exporter ();
    our @ISA       = qw(Exporter);
    our @EXPORT_OK = qw(&checkACL);
}

use Apache2::Reload;
use Apache2::Log;

use Apache2::Const -compile => qw(OK FORBIDDEN);

sub checkACL {
    my ( $package_name, $r, $log, $dbh, $app, $user, $id_method ) = @_;

    $log->debug("########## ACL_EXAMPLE ##########");

    if ($USER_OK) {
        return Apache2::Const::OK;
    }
    else {
        return Apache2::Const::FORBIDDEN;
    }
}
1;
