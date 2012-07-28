#file:Plugin/Plugin_REWRITE_CONTENT.pm
#-------------------------
#!/usr/bin/perl
package Plugin::Plugin_REWRITE_CONTENT;

use strict;
use warnings;

BEGIN {
    use Exporter ();
    our @ISA       = qw(Exporter);
    our @EXPORT_OK = qw(&plugin);
}

use Apache2::Log;
use Apache2::Reload;

use Apache2::Const -compile => qw(DECLINED);
use base qw(Apache2::Filter);
use Apache2::Const qw(OK DECLINED FORBIDDEN :conn_keepalive);
use Apache2::Connection ();
use Apache2::RequestRec;
use Apache2::RequestUtil;
use APR::Table;
use APR::URI;
use constant BUFF_LEN => 8000;
use Apache2::ServerRec;
use Apache2::URI;
use Data::Dumper;
use Apache2::Filter();
use Plugin::Plugin_OutputFilterHandler;

sub plugin {
    my ( $package_name, $r, $log, $dbh, $intf, $app ) = @_;
    $log->debug("########## Plugin_REWRITE_CONTENT ##########");

    $r->add_output_filter( \&Plugin::Plugin_OutputFilterHandler::handler );

    return undef;
}

1;
