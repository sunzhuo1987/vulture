#file:Core/CleanupHandler.pm
#---------------------------------
#!/usr/bin/perl
package Core::CleanupHandler;

use strict;
use warnings;

use Apache2::Access ();
use Apache2::Reload;
use Apache2::Log;

use Apache2::Const -compile => qw(OK);

use DBI;

sub handler {
    my $r   = shift;
    my $log = $r->pnotes('log');
    my $dbh = $r->pnotes('dbh');

    $log->debug("########## CleanupHandler ##########");

    if ($dbh) {
        $log->debug("Cleaning DB connection");
        $dbh->disconnect();
    }

    return Apache2::Const::OK;
}
1;
