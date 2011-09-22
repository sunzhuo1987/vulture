#file:Core/ResponseHandlerv2.pm
#---------------------------------
package Core::ResponseHandlerv2;

use Apache2::Access ();
use Apache2::Reload;
use Apache2::RequestUtil ();
use Apache2::Log;

use DBI;

use Apache2::Const -compile => qw(OK DECLINED REDIRECT HTTP_UNAUTHORIZED);

use Core::VultureUtils qw(&session &getStyle &getTranslations &generate_random_string);

use Apache::SSLLookup;

use Module::Load;

sub handler {
  	my $r = Apache::SSLLookup->new(shift);

	my $log = $r->pnotes('log');
	
	#Getting data from pnotes
	my $app = $r->pnotes('app');
	
	my $dbh = $r->pnotes('dbh');
	my $user = $r->pnotes('username');

	#$user may not be set if Authentication is done via APache (ex: mod_auth_kerb)
	$user = $r->user unless ($user);
	my $password = $r->pnotes('password');

	my (%session_app);
	session(\%session_app, $app->{timeout}, $r->pnotes('id_session_app'), $log, $app->{update_access_time});
	my (%session_SSO);
	session(\%session_SSO, $app->{timeout}, $r->pnotes('id_session_SSO'), $log, $app->{update_access_time});

	#Query counter
	#my $query = "UPDATE stats SET value=value+1 WHERE var='responsehandler_counter'";
	#$log->debug($query);
	#$dbh->do($query) or $log->error($dbh->errstr);

	$log->debug("########## ResponseHandlerv2 ##########");
       	    
	#Bypass everything to display custom message (ex : custom auth)
	if($r->pnotes('response_content') or $r->pnotes('response_headers') or $r->pnotes('response_content_type')){
	    $log->debug("Bypass ResponseHandler because we have a response to display");
		if($r->pnotes('response_headers')){
			@headers = split /\n/, $r->pnotes('response_headers');
			foreach my $header (@headers){
				if($header =~ /^([^:]+):\s+?(.*)$/){
					$r->err_headers_out->set($1 => $2);
				}
			}
		}
		$r->print($r->pnotes('response_content')) if defined $r->pnotes('response_content_type');
		$r->content_type($r->pnotes('response_content_type')) if defined $r->pnotes('response_content_type');
		return Apache2::Const::OK;
	}

	#SSO Forwarding
	if(exists $session_app{SSO_Forwarding}){
		if(defined $session_app{SSO_Forwarding}){
			my $module_name = "SSO::SSO_".uc($session_app{SSO_Forwarding});

			load $module_name;
			
			#Get return
			$ret = $module_name->forward($r, $log, $dbh, $app, $user, $password);
		}
		delete $session_app{SSO_Forwarding};
		$session_app{SSO_Forwarding} = $r->pnotes('SSO_Forwarding') if defined $r->pnotes('SSO_Forwarding');

		return Apache2::Const::OK;
	}
	
	#If user is logged, then redirect
	if($user){

		#SSO Forwarding once
		if(not defined $session_app{SSO_Forwarding} and $app->{sso_forward}){
			#If results are the same, it means user has already complete the SSO Learning phase
			my $query = "SELECT count(*) FROM post, sso, app WHERE post.sso_id = sso.id AND sso.id = app.sso_forward_id AND app.id=? AND field_type != 'autologon_password' AND field_type != 'autologon_user' AND field_type != 'hidden'";
			my $query2 = "SELECT count(*) FROM profile WHERE app_id = ? AND user = ?";
			my $result1 = $dbh->selectrow_array($query, undef, $app->{id});
			my $result2 = $dbh->selectrow_array($query2, undef, $app->{id}, $user);

            my $query_type = "SELECT sso.type FROM sso, app WHERE app.id = ? AND sso.id = app.sso_forward_id";
			my $type = $dbh->selectrow_array($query_type, undef, $app->{id});

		#Learning ok or no need of learning
            if ($result1 == 0 or $type eq 'sso_forward_htaccess' or $result2 == 1){
                $log->debug("Getting pass for SSO Forward Forward");
                $session_app{SSO_Forwarding} = 'FORWARD';

            #Learning was not done yet
            } elsif ($result2 == 0) {
                $log->debug("Getting pass for SSO Learning");
                $session_app{SSO_Forwarding} = 'LEARNING';
            } else {
                $log->debug("Getting pass for SSO : nothing to forward or to learn");
            }
		}
        #Display portal instead of redirect user
	    if($app->{display_portal}){
            $log->debug("Display portal with all applications");
		    #Getting all app info
            my $portal = display_portal($r,$log, $dbh);
            $log->debug($portal);
		    $r->content_type('text/html');
		    $r->print($portal);
		    return Apache2::Const::OK;
		    
        } else {
		#Redirect user
		    $r->status(200);

		    my $url = $r->is_https ? 'https://' : 'http://';
		    $url .= $app->{name}.':'.$app->{port}.$session_app{url_to_redirect};
		    $r->err_headers_out->set('Location' => $url);
		    $log->debug('Redirecting to '.$url);

		    return Apache2::Const::REDIRECT;
        }
    
    #No user set before. Need to display Vulture auth
	} else {
        #Display Vulture auth
        if($app and !$app->{'auth_basic'} and not $r->pnotes('static')) {
	        $log->debug("Display auth form");
	        $r->content_type('text/html');
	        $r->print(display_auth_form($r, $log, $dbh, $app));
	        return Apache2::Const::OK;
        }
	    $log->debug("Serving static file");
    }
	return Apache2::Const::DECLINED;
}

sub display_auth_form {
	my ($r, $log, $dbh, $app) = @_;
	my $raw = $r->unparsed_uri;
	my $uri = $r->unparsed_uri;
	my $message = $r->pnotes("auth_message");    
    my $translated_message;

    #Get session SSO for filling random token
        my (%session_SSO);
        session(\%session_SSO, $app->{timeout}, $r->pnotes('id_session_SSO'), $log, $app->{update_access_time});

	if($r->unparsed_uri =~ /vulture_app=([^;]*)/){
		$uri = $1;
	}
    
    #Get translations
    my $translated_messages = getTranslations($r, $log, $dbh, $message);
    my %translations = %$translated_messages;
    my $html = '<html><head><meta http-equiv="Content-Type" content="text/html; charset=utf-8"><title>Please authenticate</title>';
    
    #Get style
    my $ref = getStyle($r, $log, $dbh, $app, 'LOGIN');
	
    #Including css
    if (defined $ref->{css}){
        $html .= "<style type=\"text/css\">".$ref->{css}."</style>";
    } else {
        $html .= <<BAR
    <STYLE type="text/css">

body,th,td,p,div,span,a,ul,ol,dl,li,select,input,textarea,blockquote{font-size:11px;}
table { margin : 10px auto auto auto; }

input {
         border-bottom: solid 1px #cccccc;
         border-right: solid 1px #cccccc;
         margin: 5px;
         padding: 2px;
}

#custom {
          width: 502px;
          height: 217px;
          background-repeat: no-repeat;
          background-image: url('/static/img/bg.png');
}

</STYLE>
BAR
;
    }
    
    $html .= "</head><body>";

    #Avoid bot request
    my $token = generate_random_string(32);
    $session_SSO{random_token} = $token;
    
    $form = <<FOO
<div id="form_vulture">
<form method="POST" name="auth_form" action="$raw">
<table>
<tr class="row"><td class="input">$translations{'USER'}{'translation'}</td><td><input type="text" name="vulture_login"></td></tr>
<tr class="row"><td class="input">$translations{'PASSWORD'}{'translation'}</td><td><input type="password" autocomplete="off" name="vulture_password"></td></tr>
<tr class="row"><td></td><td align="right"><input type="hidden" name="vulture_token" value="$token"></td></tr>
<tr class="row"><td></td><td align="right"><input type="submit"></td></tr>
</table>
</form>
</div>
FOO
;

    #Parsing template if exists
    if(defined $ref->{tpl}){
        $html .= join "",map {
            my ($directive) = $_ =~ /__(.+)__/s;
            if ($directive){
                if ($directive eq "IMAGE"){
                    $_ = "<img id=\"logo\" src=\"/static/".$ref->{image}."\" />";
                } elsif ($directive eq "ERRORS"){
                    if ($message and defined $translations{$message} and defined $translations{$message}{'translation'}){
                        $_ = $translations{$message}{'translation'};
                    }
                } elsif ($directive eq "FORM"){
                    $_ = $form
                } else {
                }
            } else {
                $_ = $_;        
            }
        } split (/(__.*?__)/s, $ref->{tpl});
    
    #Template was undefined
    } else {
        $html .= "<center><div style = \"position: absolute; top:25%; left:25%;\">";
        $html .= "<div id=\"custom\" style=\"margin: 0; padding: 60 30;\">";
        $html .= "<h2><font color=\"red\">$translations{$message}{'translation'}</font></h2>" if defined $translations{$message}{'translation'};
        $html .= $form."</div>";
    }
    $html .= '</body></html>';
	return $html;
}

sub display_portal {
	my ($r,$log,$dbh) = @_;

    my $intf_id = $r->dir_config('VultureID');
	my $query = "SELECT app.name FROM app WHERE app.intf_id='".$intf_id."'";
    $log->debug($query);

    my $all_apps = $dbh->selectall_arrayref($query);
	my $html;
	foreach my $app (@$all_apps) {
        $html .= "<a href='".$r->is_https ? 'https://' : 'http://'.@$app[0]."'><h3>Application ".@$app[0]."</h3></a>";
	}
	return $html;
}

1;
