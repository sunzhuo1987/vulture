#file:Plugin/Plugin_LOGOUT_ALL2.pm
#-------------------------
#!/usr/bin/perl

package Plugin::Plugin_LOGOUT_ALL2;

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
  qw(&get_cookie &session &get_memcached &set_memcached &notify);

use Apache2::Const -compile => qw(OK FORBIDDEN REDIRECT);

use APR::URI;
use DBI;

sub plugin {
    my ( $package_name, $r, $log, $dbh, $intf, $app, $options ) = @_;
    my $mc_conf = $r->pnotes('mc_conf');
    my ($logoutbro_url, $final_url) = split(/;/, $options); 
    $log->debug("urls bro : $logoutbro_url, final : $final_url");

    $log->debug("########## Plugin_LOGOUT_ALLv2 ##########");

    #Taking user identity
    my ($id_app,$id_sso);
    my (%session_app,%session_SSO);
    $id_app = get_cookie( $r->headers_in->{Cookie},
        $r->dir_config('VultureAppCookieName') . '=([^;]*)' );
    if (defined $id_app){
        session( \%session_app, undef, $id_app, undef, $mc_conf );
        $id_sso = $session_app{SSO};
    }
    else{
        $id_sso = get_cookie($r->headers_in->{Cookie},
           $r->dir_config('VultureProxyCookieName').'=([^;]*)'); 
    }
    session( \%session_SSO, undef, $id_sso, undef, $mc_conf );
    my $app_list = '';
    my $app_cnt = 0;
    #Foreach app where user is currently logged in
    foreach my $key ( keys %session_SSO ) {
        my @wrong_keys =
          qw/is_auth username url_to_redirect password SSO last_access_time _session_id random_token/;
        unless ( grep $_ eq $key, @wrong_keys ) {
            my $id_app = $session_SSO{$key};
            my (%current_app) = ();
            session( \%current_app, undef, $id_app, undef, $mc_conf );
            next if not $current_app{app_name};
            my $parsed_apn = APR::URI->parse($r->pool, "//" . $current_app{app_name});
            $app_cnt ++;
            my $deco_url = ( "//" . $parsed_apn->hostname 
                            . ":".$intf->{port} 
                            . $parsed_apn->path . "/$logoutbro_url" );
            $app_list .= "\"$deco_url\",";
        }
    }

    my $resp_content;

    if ( $app_cnt == 0){
        my (%users);
        %users = %{ get_memcached( 'vulture_users_in', $mc_conf ) || {} };
        delete $users{ $session_SSO{username} };
        set_memcached( 'vulture_users_in', \%users, undef, $mc_conf );
        notify( $dbh, undef, $session_SSO{username}, 'deconnection', scalar( keys %users ) );
        #Logout from SSO
        tied(%session_SSO)->delete();
        $options ||= "/";
        $resp_content = ( "<html><head><meta http-equiv=\"Refresh\" content=\"0; url='" 
              . $final_url
              . "'\"/></head></html>");

    }
    else {
        foreach my $k (keys(%session_SSO)){
                if ($k =~ /^auth_infos_/){
                        delete $session_SSO{$k};
                }
        }
        my $parsed_itf = APR::URI->parse($r->pool, "//" . $intf->{sso_portal});
        my ($ihost, $ipath)=($parsed_itf->hostname, $parsed_itf->path||'' );
        $session_SSO{is_auth} = 0;
        $log->debug("deco list : $app_list");
        $resp_content = <<RESP_BODY
<!DOCTYPE html>
<html>
<head>
<script src="/static/logout.js"></script>
<script>
var deco_idx = 0;
var deco_urls = [ $app_list ];
function start(ifr){
    if(deco_idx < deco_urls.length){
        ifr.src = deco_urls[deco_idx++];  
    }
    else {
        var path = window.location.pathname.split("/");
        path = path[path.length-1];
        window.location = "//$ihost:$intf->{port}$ipath/"+path;
    }
}
</script>
</head>
<body>
    <iframe id="ifr" style="visibility:hidden" onload="start(this)" src="/static/empty.html"></iframe>
</body>
</html>
RESP_BODY
;
    }

    #Destroy useless handlers
    $r->set_handlers( PerlAccessHandler => undef );
    $r->set_handlers( PerlAuthenHandler => undef );
    $r->set_handlers( PerlAuthzHandler  => undef );
    $r->set_handlers( PerlFixupHandler  => undef );


    $r->pnotes( 'response_content' => $resp_content);
    $r->pnotes( 'response_content_type' => 'text/html' );
    return Apache2::Const::OK;
}

1;
