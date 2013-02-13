#file:Core/ResponseHandlerv2.pm
#---------------------------------
#!/usr/bin/perl
package Core::ResponseHandlerv2;

use strict;
use warnings;

use Apache2::Access ();
use Apache2::Reload;
use Apache2::RequestUtil ();
use Apache2::Log;
use Apache2::Request;
use DBI;

use Apache2::Const -compile => qw(OK DECLINED REDIRECT HTTP_UNAUTHORIZED);

use Core::VultureUtils
  qw(&session &get_style &get_translations &generate_random_string &load_module);
use SSO::ProfileManager qw(&get_profile);

use Apache::SSLLookup;
use HTML::Entities qw(&encode_entities);

sub handler {
    my $r = Apache::SSLLookup->new(shift);

    my $log = $r->pnotes('log');
    $log->debug("########## ResponseHandlerv2 ##########");

    #Getting data from pnotes
    my $app     = $r->pnotes('app');
    my $dbh     = $r->pnotes('dbh');
    my $intf    = $r->pnotes('intf');
    my $mc_conf = $r->pnotes('mc_conf');

    #$user may not be set if Authentication is done via Apache (ex: mod_auth_kerb)
    my $user = $r->pnotes('username') || $r->user;
    my $password = $r->pnotes('password');

    my (%session_app);
    Core::VultureUtils::session( \%session_app, $app->{timeout},
        $r->pnotes('id_session_app'),
        $log, $mc_conf, $app->{update_access_time} );
    my (%session_SSO);
    Core::VultureUtils::session( \%session_SSO, $intf->{timeout},
        $r->pnotes('id_session_SSO'),
        $log, $mc_conf, $app->{update_access_time} );
#Query counter
#my $query = "UPDATE stats SET value=value+1 WHERE var='responsehandler_counter'";
#$log->debug($query);
#$dbh->do($query) or $log->error($dbh->errstr);


    #Bypass everything to display custom message (ex : custom auth)
    if (   $r->pnotes('response_content')
        or $r->pnotes('response_headers')
        or $r->pnotes('response_content_type') )
    {
        return Core::ResponseHandlerv2::display_custom_response( $log, $r );
    }

    #SSO Forwarding
    if ( exists $session_app{SSO_Forwarding} ) {
        if ( defined $session_app{SSO_Forwarding} ) {
            my $module_name = "SSO::SSO_" . uc( $session_app{SSO_Forwarding} );
            Core::VultureUtils::load_module( $module_name, 'forward' );
            #Get return
            $module_name->forward( $r, $log, $dbh, $app, $user, $password );
        }
        delete $session_app{SSO_Forwarding};
        $session_app{SSO_Forwarding} = $r->pnotes('SSO_Forwarding')
          if defined $r->pnotes('SSO_Forwarding');

        return Apache2::Const::OK;
    }
    #No user set before. Need to display Vulture auth
    if (not $user){
        #Display Vulture auth
        if ( $app and !$app->{'auth_basic'} and not $r->pnotes('static') ) {
            $r->content_type('text/html');
            $r->print(
                Core::ResponseHandlerv2::display_auth_form(
                    $r, $log, $dbh, $app, $intf, \%session_SSO
                )
            );
            return Apache2::Const::OK;
        }
        $log->debug("Serving static file");
        return Apache2::Const::DECLINED;
    }
    #If user is logged
    #SSO Forwarding once
    if ( not defined $session_app{SSO_Forwarding} and $app->{sso_forward} )
    {
        my $query =
"SELECT count(*) FROM field, sso, app WHERE field.sso_id = sso.id AND sso.id = app.sso_forward_id AND app.id=?";
        $log->debug($query);
        my $href =
          SSO::ProfileManager::get_profile( $r, $log, $dbh, $app, $user );

        my $length1 = $dbh->selectrow_array( $query, undef, $app->{id} );

        #            my $length2 = grep { $_ ne "" } values %$href;
        my $length2 = 0;
        while ( my ( $key, @vals ) = each(%$href) ) {
            my ( $value, $type ) = ( $vals[0][0], $vals[0][1] );
            $length2 = $length2 + 1 if ( $value ne "" );
        }

        $log->debug( $length1 . "vs" . $length2 );

        my $query_type =
"SELECT sso.type FROM sso, app WHERE app.id = ? AND sso.id = app.sso_forward_id";
        $log->debug($query_type);
        my $type = $dbh->selectrow_array( $query_type, undef, $app->{id} );

#Learning ok or no need of learning
#If results are the same, it means user has already complete the SSO Learning phase
        if (   $length1 == 0
            or $type eq 'sso_forward_htaccess'
            or $length2 == $length1 )
        {
            $log->debug("Getting pass for SSO Forward");
            $session_app{SSO_Forwarding} = 'FORWARD';
        }
        else {
            #Learning was not done yet
            my $sso_learning_ext = '';
            $sso_learning_ext = $app->{'sso_learning_ext'};
            $log->debug( "#######" . $sso_learning_ext . "#####" );

            if ( ( $sso_learning_ext ne '' ) ) {
                $log->debug( "REDIRECTING SSO LEARNING TO EXTERNAL APP"
                      . $sso_learning_ext );
                #TODO : do_redirect
                my $html;
                $html =
                  '<html><head><meta http-equiv="Refresh" content="0; url='
                  . $sso_learning_ext
                  . '"/></head></html>';
                $r->content_type('text/html');
                $r->print($html);
                return Apache2::Const::OK;
            }
            else {
                $log->debug("Getting pass for SSO Learning");
                $session_app{SSO_Forwarding} = 'LEARNING';
            }
        }
    }
    #Display portal instead of redirect user
    if ( $app->{'display_portal'} ) {
        $log->debug("Display portal with all applications");
        #Getting all app info
        my $portal =
          Core::ResponseHandlerv2::display_portal( $r, $log, $dbh, $app );
        $r->content_type('text/html');
        $r->print($portal);
        return Apache2::Const::OK;
    }
    elsif ( defined( $session_app{url_to_redirect} ) ) {
        return Core::ResponseHandlerv2::url_redirect($log,$r,$app,$session_app{url_to_redirect});
    }
    elsif ( defined $r->pnotes('url_to_redirect') ) {
        return Core::ResponseHandlerv2::do_redirect($log,$r,$r->pnotes('url_to_redirect'));
    }
    else {
        #Redirect to CAS
        return Core::ResponseHandlerv2::cas_redirect($log,$r,$dbh,$intf,$app);
    }
}
sub url_redirect{
    my ($log,$r,$app,$url) = @_;
    #Redirect user
    my $incoming_uri = $app->{name};
    if ( $incoming_uri !~ /^(http|https):\/\/(.*)/ ) {

        #Fake scheme for making APR::URI parse
        $incoming_uri = 'http://' . $incoming_uri;
    }
    #Rewrite URI with scheme, port, path,...
    my $rewrite_uri = APR::URI->parse( $r->pool, $incoming_uri );
    $rewrite_uri->scheme('http');
    $rewrite_uri->scheme('https') if $r->is_https;
    $rewrite_uri->port( $r->get_server_port() );
    $rewrite_uri->path($url);
    return Core::ResponseHandlerv2::do_redirect($log,$r,$rewrite_uri->unparse);
}
sub do_redirect{
    my ($log,$r,$url) = @_;
    $r->status(302);
    $r->err_headers_out->set( 'Location' => $url );
    $log->debug( 'Redirecting to ' . $url );
    return Apache2::Const::REDIRECT;
}
sub cas_redirect{
    my ($log,$r,$dbh,$intf,$app)=@_;
    my $html;
    if ( $intf->{'cas_display_portal'} ) {
        $html = Core::ResponseHandlerv2::display_portal( $r, $log, $dbh,
            $app );
    }
    # TODO: do_redirect
    elsif ( $intf->{'cas_redirect'} ) {
        $html =
            '<html><head><meta http-equiv="Refresh" content="0; url='
          . $intf->{'cas_redirect'}
          . '"/></head></html>';
    }
    else {
        $html =
"<html><head><title>Successful login</title></head><body>You are successfull loged on SSO</body></html>";
    }
    $r->print($html);
    $r->content_type('text/html');
    return Apache2::Const::OK;

}
sub display_custom_response {
    my ( $log, $r ) = @_;
    $log->debug("Bypass ResponseHandler because we have a response to display");
    if ( $r->pnotes('response_headers') ) {
        my @headers = split /\n/, $r->pnotes('response_headers');

        foreach my $header (@headers) {
            $log->debug('Parse header');
            if ( $header =~ /^([^:]+):(.*)$/ ) {
                $log->debug( 'Find header ' . $1 . ' => ' . $2 );
                $r->err_headers_out->set( $1 => $2 );
            }
        }
        $r->status(Apache2::Const::REDIRECT);
    }
    $r->print( $r->pnotes('response_content') )
      if defined $r->pnotes('response_content');
    $r->content_type( $r->pnotes('response_content_type') )
      if defined $r->pnotes('response_content_type');

    #Force headers to be send out
    $r->rflush;
    return Apache2::Const::OK;
}

sub display_auth_form {
    my ( $r, $log, $dbh, $app, $intf, $session_SSO ) = @_;
    my $req     = Apache2::Request->new($r);
    my $mc_conf = $r->pnotes('mc_conf');
    $log->debug("display auth form");

    my $uri     = $r->unparsed_uri;
    my $message = $r->pnotes("auth_message")||'';
    my $auth_name = $r->pnotes("auth_name");

    #CAS
    my $service = $req->param('service');

    #Get translations
    my $translations =
      Core::VultureUtils::get_translations( $r, $log, $dbh, $message );

    # token
    my $token;
    if (defined $session_SSO->{random_token}){
	$token = $session_SSO->{random_token};
    }
    else{
	$token = Core::VultureUtils::generate_random_string(32);
	$session_SSO->{random_token} = $token;
    }
    #Get style
    my $form =
"<div id=\"form_vulture\"><form method=\"POST\" name=\"auth_form\" action=\""
      . HTML::Entities::encode_entities($uri)
      . "\"><table>";
    $form .=
"<tr class=\"row\"><td></td><td class=\"hidden\" name=\"service\" value=\""
      . HTML::Entities::encode_entities($service)
      . "\"></td></tr>"
        if defined $service;
    if ($session_SSO->{otp_step1}){
        $form .= <<FOO
        <input type="hidden" name="vulture_login" value="$session_SSO->{otp_user}"/>
FOO
        ;
    }
    else{
        $form .= <<FOO
<tr class="row">
    <td class="input">$translations->{'USER'}{'translation'}</td>
    <td><input type="text" name="vulture_login"></td>
</tr>
FOO
        ;
    }
    $form .=<<FOO
<tr class="row">
    <td class="input">$translations->{'PASSWORD'}{'translation'}</td>
    <td><input type="password" autocomplete="off" name="vulture_password"></td>
</tr>
<tr class="row"><td></td>
    <td align="right">
        <input type="hidden" name="vulture_token" value="$token">
    </td>
</tr>
<tr class="row">
    <td></td><td align="right"><input type="submit" value="submit"></td></tr>
</table>
</form>
</div>
FOO
    ;
    my $style_arg = { FORM => $form };
    if ( defined $translations->{$message} ) {
        $style_arg->{ERRORS} = $translations->{$message}{'translation'};
    }
    if ( defined $auth_name){
        $style_arg->{AUTH_NAME} = $auth_name;
    }
    return Core::VultureUtils::get_style(
        $r, $log, $dbh, $app, 'LOGIN',
        'Please authenticate',
        $style_arg,
        $translations
    );
}

sub display_portal {
    my ( $r, $log, $dbh, $app ) = @_;

    my $intf_id = $r->dir_config('VultureID');
    my $query =
"SELECT app.name FROM app, app_intf WHERE app_intf.intf_id=? AND app.id = app_intf.app_id";
    my $all_apps = $dbh->selectall_arrayref( $query, undef, $intf_id );
    #Get translations
    my $translations =
      Core::VultureUtils::get_translations( $r, $log, $dbh, 'APPLICATION' );

    #Get all apps
    my $html_apps = "<ul>";
    foreach my $app (@$all_apps) {
        my $incoming_uri = @$app[0];
        if ( $incoming_uri !~ /^(http|https):\/\/(.*)/ ) {

            #Fake scheme for making APR::URI parse
            $incoming_uri = 'http://' . $incoming_uri;
        }

        #Rewrite URI with scheme, port, path,...
        my $rewrite_uri = APR::URI->parse( $r->pool, $incoming_uri );

        $rewrite_uri->scheme('http');
        $rewrite_uri->scheme('https') if $r->is_https;
        $rewrite_uri->port( $r->get_server_port() );
        $html_apps .=
            "<li><a href='"
          . $rewrite_uri->unparse
          . "'><h3>Application "
          . @$app[0]
          . "</h3></a></li>";
    }
    $html_apps .= "</ul>";

    #Get style
    my $html =
      Core::VultureUtils::get_style( $r, $log, $dbh, $app, 'DISPLAY_PORTAL',
        'SSO portal', { APPS => $html_apps },
        $translations );
    $html ||= '';
    return $html =~ /<body>.+<\/body>/s ? $html : $html_apps;
}
1;
