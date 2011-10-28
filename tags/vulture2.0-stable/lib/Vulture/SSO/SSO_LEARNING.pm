#file:SSO/SSO_LEARNING.pm
#-------------------------
package SSO::SSO_LEARNING;

use Apache2::RequestRec ();
use Apache2::RequestIO ();
use Apache2::Request;

use Apache2::Log;
use Apache2::Reload;

use LWP;

use Apache2::Const -compile => qw(OK DECLINED);

use Core::VultureUtils qw(&session);
use SSO::ProfileManager qw(&setProfile &getProfile);

sub forward{
	my ($package_name, $r, $log, $dbh, $app, $user, $password) = @_;

	my (%session_SSO);
	session(\%session_SSO, $app->{timeout}, $r->pnotes('id_session_SSO'), $log, $app->{update_access_time});

	$log->debug("########## SSO_Learning ##########");

	#Getting fields to send	
	my $sql = "SELECT post.field_var, post.field_mapped, post.field_type, post.field_encrypted, post.field_value, post.field_prefix, post.field_suffix, post.field_desc FROM post, sso, app WHERE post.sso_id = sso.id AND sso.id = app.sso_forward_id AND app.id=? AND post.field_type != 'autologon_user' AND post.field_type != 'autologon_password' AND post.field_type != 'hidden'";
	
	my $sth = $dbh->prepare($sql);
	$sth->execute($app->{id});
	
	my @fields =  @{$sth->fetchall_arrayref};

    #Nothing to learn
    if(not scalar(@fields)){
        $r->content_type('text/html');
		$log->debug("Nothing to learn");
		$r->pnotes('SSO_Forwarding' => 'FORWARD');

		$r->headers_out->add('Location' => $r->unparsed_uri);	

		#Set status
		$r->status(302);

	    return Apache2::Const::REDIRECT;
    }


	#Getting values posted & set it into profile
	my $req = Apache2::Request->new($r);
	
	#Adding data to post variable
	my $form = "<h3>To access to this app, you must specify the following fields</h3><table>";
	$form .= "<form method=\"POST\" name='app_form' action=\"\">";
	$form .= "<input type=hidden name=vulture_learning value=1>";
	foreach my $field (@fields) {
		my ($var, $mapped, $type, $need_encryption, $default_value, $prefix, $suffix, $desc) = @$field;

		#Set form
		if($type ne 'autologon_user' and $type ne 'autologon_password' and $type ne "hidden"){
			$form .= "<tr><td>$desc</td><td><input type=\"$type\" name=\"$var\" value=\"$default_value\"></td></tr>";
		} else {
		    next;
		}
	}
	$form .= "<tr><td></td><td><input type=\"submit\"></td></tr>";
	$form .= "</form></table>";

	$sth->finish();
	
	#Print form
	if(not $req->param('vulture_learning')){
		$r->pnotes('SSO_Forwarding' => 'LEARNING');
		$r->content_type('text/html');	
		$r->print($form);
		
	#Learning was ok, move on SSO Forward
	} elsif(setProfile($r, $log, $dbh, $app, $user, $req, @fields)) {
		$r->content_type('text/html');
		$log->debug("Learning was a huge success");
		$r->pnotes('SSO_Forwarding' => 'FORWARD');

		$r->headers_out->add('Location' => $r->unparsed_uri);	

		#Set status
		$r->status(302);

	    return Apache2::Const::REDIRECT;
	} else {
	    $log->debug("Something went wrong in SSO Learning");
	}

	
}

1;
