#file:Plugin/Plugin_SAML.pm
#-------------------------
#!/usr/bin/perl
package Plugin::Plugin_SAML;

use strict;
use warnings;

BEGIN {
    use Exporter ();
    our @ISA       = qw(Exporter);
    our @EXPORT_OK = qw(&plugin);
}

use Apache2::Log;
use Apache2::Reload;

use Core::VultureUtils qw(&session &get_memcached &set_memcached);

use Apache2::Const -compile => qw(OK FORBIDDEN);

sub plugin {
    my ( $package_name, $r, $log, $dbh, $intf, $app, $options ) = @_;

    $log->debug("########## Plugin_SAML ##########");

}

1;
