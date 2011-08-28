#file:Plugin/SSO_POST.pm
#-------------------------
package SSO::SSO_POST;

use Apache2::RequestRec ();
use Apache2::RequestIO ();

use Apache2::Log;
use Apache2::Reload;

use LWP::UserAgent;
use HTTP::Request;

use Apache2::Const -compile => qw(OK DECLINED REDIRECT HTTP_UNAUTHORIZED);

use Core::VultureUtils qw(&session);

use Apache::SSLLookup;

sub forward{
	my ($package_name, $r, $log, $dbh, $app, $user, $password) = @_;

    my $r = Apache::SSLLookup->new($r);

	my (%session_app);
	session(\%session_app, undef, $r->pnotes('id_session_app'));

	$log->debug("########## SSO_POST ##########");

	$log->debug("LWP::UserAgent is emulating post request on ".$app->{name});

	#Getting SSO type
	$log->debug("Getting data from database");
	my $query = "SELECT components.id, components.type FROM component_app, components WHERE component_app.app_id=".$app->{id}.
	  " AND components.id=component_app.components_id".
	    " AND (components.type='sso_forward' OR components.type='sso_forward_htaccess' OR components.type='sso_forward_autologon')";

	my $sth = $dbh->prepare($query);
	$sth->execute;
	my ($component_id, $sso_forward_type) = $sth->fetchrow;
	$sth->finish();
	$log->debug("SSO_FORWARD_TYPE=".$sso_forward_type);

	#Getting fields to send	
	my $sql = "SELECT field_var, value FROM profile WHERE app_id = ? AND user = ?";
	
	my $sth = $dbh->prepare($sql);
	$sth->execute($app->{id}, $user);
	
	#Adding data to post variable
	my $post;
	foreach my $row (@{$sth->fetchall_arrayref}) {
		my ($var, $value) = @$row;
	    $post .= $var."=".$value."&";
		$log->debug($post);
	}
	$sth->finish();

    #Getting specials fields like "autologon_*"
    my $sql = "SELECT field_type, field_var, field_value FROM post, component_app WHERE post.component_id = component_app.components_id AND component_app.app_id = ? AND (field_type = 'autologon_password' OR field_type = 'autologon_user')";
	my $sth = $dbh->prepare($sql);
	$sth->execute($app->{id});
	
	#Adding data to post variable
	foreach my $row (@{$sth->fetchall_arrayref}) {
        my ($type, $var, $value) = @$row;
		if($type eq 'autologon_user'){
            $post .= $var."=".$user."&";
        } elsif($type eq 'autologon_password'){
            $post .= $var."=".$password."&";
        } else {        
        }
		$log->debug($post);
	}

	#Setting browser
	my ($ua, $response, $request);
	$ua = LWP::UserAgent->new;

	#Setting proxy if needed
	if ($app->{remote_proxy} ne ''){
		$ua->proxy(['http', 'https'], $app->{remote_proxy});
	}

	#Setting request
	$request = HTTP::Request->new('POST', $app->{url}.$app->{logon_url}, undef, $post);

	#Setting headers
	$request->push_header('Content-Type' => 'application/x-www-form-urlencoded');
	$request->push_header('Cookie' => $r->headers_in->{'Cookie'});
	$request->push_header('User-Agent' => $r->headers_in->{'User-Agent'});
	$request->push_header('Host' => $r->headers_in->{'Host'});

    #Sending Authorization header if needed by SSO forward type
    if($sso_forward_type eq 'sso_forward_htaccess'){
        $request->push_header('Authorization' => "Basic " . encode_base64($user.':'.$password));    
    }

	#Getting response
	$response = $ua->request($request);

    #$log->debug($response->as_string);	

	#Cookie coming from response
	my %cookies_app;
	if ($response->headers->header('Set-Cookie')) {
		# Adding new couples (name, value) thanks to POST response
		foreach ($response->headers->header('Set-Cookie')) {
			if (/([^,; ]+)=([^,; ]+)/) {
				$cookies_app{$1} = $2;		# adding/replace
				$log->debug("ADD/REPLACE ".$1."=".$2);
				
			}
		}
		$session_app{cookie} = $response->headers->header('Set-Cookie');
	}
	foreach my $k (keys %cookies_app) {
		$r->err_headers_out->add('Set-Cookie' => $k."=".$cookies_app{$k}."; domain=".$r->hostname."; path=/");  # Send cookies to browser's client
		$log->debug("PROPAG ".$k."=".$cookies_app{$k});
	}

    # 30x headers
	if ($response->code =~ /^30(.*)/ ) { 
        $log->debug("Redirecting after SSO");
        $url = $response->headers->header('Location');
        if($r->is_https) {
            $url =~ s{^http://}{https://}g;
        } else {
            $url =~ s{^https://}{http://}g;
        }
		$r->headers_out->add('Location' => $url);
        $r->pnotes('SSO_Forwarding' => undef);
        
        #Redirecting        
        $r->content_type('text/html');

		$r->headers_out->add('Location' => $r->unparsed_uri);	

		#Set status
		$r->status(302);
        return Apache2::Const::REDIRECT;
    
    #Response was successful
	#} elsif ($response->is_success()) {
    #    $log->debug("SSO was a success but we don't know what to do right now");	
    #    $r->pnotes('SSO_Forwarding' => undef);
    #    return Apache2::Const::OK;

    #Fail. Redirecting to SSO Learning
    } else {
        $log->debug("SSO fails. Delete old profile values. Redirecting to SSO Learning");	
        $r->pnotes('SSO_Forwarding' => 'LEARNING');

        #Delete old values which don't work
        my $sql = "DELETE FROM profile WHERE app_id = ? AND user = ?";
	    my $sth = $dbh->prepare($sql);
        $sth->execute($app->{id}, $user);
        
        #Redirecting to SSO Learning
        $r->content_type('text/html');
		$r->pnotes('SSO_Forwarding' => 'LEARNING');

		$r->headers_out->add('Location' => $r->unparsed_uri);	

		#Set status
		$r->status(302);

	    return Apache2::Const::REDIRECT;
    }	
}

1;
