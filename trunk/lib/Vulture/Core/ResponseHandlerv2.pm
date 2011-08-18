#file:Core/ResponseHandlerv2.pm
#---------------------------------
package Core::ResponseHandlerv2;

use Apache2::Access ();
use Apache2::Reload;
use Apache2::RequestUtil ();
use Apache2::Log;

use DBI;

use Apache2::Const -compile => qw(OK DECLINED REDIRECT HTTP_UNAUTHORIZED);

use Core::VultureUtils qw(&session);

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
	session(\%session_app, $app->{timeout}, $r->pnotes('id_session_app'));
	my (%session_SSO);
	session(\%session_SSO, $app->{timeout}, $r->pnotes('id_session_SSO'));

	#Query counter
	#my $query = "UPDATE stats SET value=value+1 WHERE var='responsehandler_counter'";
	#$log->debug($query);
	#$dbh->do($query) or $log->error($dbh->errstr);

	$log->debug("########## ResponseHandlerv2 ##########");

	#Bypass everything to display custom message (ex : custom auth)
	if($r->pnotes('response_content')){
		if($r->pnotes('response_headers')){
			@headers = split /\n/, $r->pnotes('response_headers');
			foreach my $header (@headers){
				if($header =~ /^([^:]+):\s+?(.*)$/){
					$r->err_headers_out->set($1 => $2);
				}
			}
		}
		$r->print($r->pnotes('response_content'));
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
		$session_app{SSO_Forwarding} = $r->pnotes('SSO_Forwarding');

		return Apache2::Const::OK;
	}
	
	#If user is logged, then redirect
	if($user){

		#SSO Forwarding once
		if(not defined $session_app{SSO_Forwarding}){
			#If results are the same, it means user has already complete the SSO Learning phase
			my $query = "SELECT count(*) FROM post, component_app WHERE post.component_id = component_app.components_id AND component_app.app_id = ?";
			my $query2 = "SELECT count(*) FROM profile WHERE app_id = ? AND user = ?";
			my $result1 = $dbh->selectrow_array($query, undef, $app->{id});
			my $result2 = $dbh->selectrow_array($query2, undef, $app->{id}, $user);
			if ($result1 != $result2){
                $log->debug("Getting pass for SSO Forward Learning");
                $session_app{SSO_Forwarding} = 'LEARNING';
			} elsif ($result1 == $result2 and $result1 != 0) {
                $log->debug("Getting pass for SSO Forward POST");
                $session_app{SSO_Forwarding} = 'POST';
			} else {
                $log->debug("Getting pass for SSO : nothing to forward or to learn");            
			 }

		}
        #Display portal instead of redirect user
	    if($app->{display_portal}){
            $log->debug("Display portal with all applications");
		    #Getting all app info
            my $portal = display_portal($r,$dbh,$log);
            $log->debug($portal);
		    $r->content_type('text/html');
		    $r->print($portal);
		    return Apache2::Const::OK;
        } else {
		#Redirect user
		    $r->status(200);

		    my $url = $r->is_https ? 'https://' : 'http://';
		    $url .= $app->{name}.':'.$r->get_server_port.$session_app{url_to_redirect};
		    $r->err_headers_out->set('Location' => $url);
		    $log->debug('Redirecting to '.$url);

		    return Apache2::Const::REDIRECT;
        }
	}
    my $auths = $app->{'auth'};
    #Display portal instead of redirect user
	if($app->{display_portal} and (not defined @$auths or not @$auths)){
        $log->debug("Display portal with all applications");
		#Getting all app info
        my $portal = display_portal($r,$dbh,$log);
        $log->debug($portal);
		$r->content_type('text/html');
		$r->print($portal);
		return Apache2::Const::OK;
    }

	#Display Vulture auth
	if($app and !$app->{'auth_basic'} ) {
		$log->debug("Display auth form");
		$r->content_type('text/html');
		$r->print(display_auth_form($r));
		return Apache2::Const::OK;
	}
	
	return Apache2::Const::OK;
}

sub display_auth_form {
	my ($r) = @_;
	my $raw = $r->unparsed_uri;
	my $uri = $r->unparsed_uri;
	my $message = $r->pnotes("auth_message");
	if($r->unparsed_uri =~ /vulture_app=([^;]*)/){
		$uri = $1;
	}
	my $form = <<EOF
		<h1>Welcome on Vulture 2</h1>
		<h2><font color="red">$message</font></h2>
		<form method="POST" name="auth_form" action="$raw">
		<input type=hidden name=vulture_app value="$uri">
		<table>
		<tr><td>Utilisateur</td><td><input type="text" name="vulture_login"></td></tr>
		<tr><td>Mot de passe</td><td><input type="password" autocomplete="off" name="vulture_password"></td></tr>
		<tr><td></td><td align="right"><input type="submit"></td></tr>
		</form>
		</table>
EOF
;
	return $form;
}

sub display_portal {
	my ($r,$dbh,$log) = @_;

    my $intf_id = $r->dir_config('VultureID');
	my $query = "SELECT app.name, app.url FROM app WHERE app.intf_id='".$intf_id."'";
    $log->debug($query);

    my $all_apps = $dbh->selectall_arrayref($query);
	my $html;
	foreach my $app (@$all_apps) {
        $html .= "<a href='http://".@$app[0].":".$r->get_server_port."'><h3>Application ".@$app[0]."</h3></a>";
	}
	return $html;
}

1;
