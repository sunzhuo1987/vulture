#file:Plugin/Plugin_LOGOUT.pm
#-------------------------
#!/usr/bin/perl
package Plugin::Plugin_LOGOUT;

use strict;
use warnings;

BEGIN {
    use Exporter ();
    our @ISA       = qw(Exporter);
    our @EXPORT_OK = qw(&plugin);
}

use Apache2::Log;
use Apache2::Reload;

use Core::VultureUtils
  qw(&get_cookie &session &get_memcached &set_memcached &log_auth_event &get_translations &get_style &parse_set_cookie);

use Apache2::Const -compile => qw(OK FORBIDDEN REDIRECT);

use DBI;

sub plugin {
    my ( $package_name, $r, $log, $dbh, $intf, $app, $options ) = @_;

    my $mc_conf = $r->pnotes('mc_conf');
    $log->debug("########## Plugin_LOGOUT ##########");

    #Taking user identity
    my (%session_app);
    my ($id_app) = get_cookie( $r->headers_in->{Cookie},
        $r->dir_config('VultureAppCookieName') . '=([^;]*)' )
      || return Apache2::Const::FORBIDDEN;

    session( \%session_app, undef, $id_app, undef, $mc_conf );
    return Apache2::Const::FORBIDDEN unless $session_app{is_auth};

    $session_app{'is_auth'} = undef;
    log_auth_event($log, $app->{id}, $session_app{username}, 'deconnection', "LOGOUT");

    #Destroy useless handlers
    $r->set_handlers( PerlAccessHandler => undef );
    $r->set_handlers( PerlAuthenHandler => undef );
    $r->set_handlers( PerlAuthzHandler  => undef );
    $r->set_handlers( PerlFixupHandler  => undef );
#    my $translations = get_translations( $r, $log, $dbh, "DISCONNECTED" );

#If no html, send form
#my $html = get_style($r, $log, $dbh, $app, 'LOGOUT', 'Logout from Vulture', {FORM => ''}, $translations);
    $options ||= '/';

    $r->pnotes( 'response_content' =>
            "<html><head><meta http-equiv=\"Refresh\" content=\"0; url='" 
          . $options
          . "'\"/></head></html>");
    $r->pnotes( 'response_content_type' => 'text/html' );
    return Apache2::Const::OK;
}
1;
