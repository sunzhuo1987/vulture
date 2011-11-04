#file:SSO/SSO_LEARNING.pm
#-------------------------
package SSO::SSO_LEARNING;

use Apache2::RequestRec ();
use Apache2::RequestIO ();

use Apache2::Log;
use Apache2::Reload;

use LWP;

use Apache2::Const -compile => qw(OK DECLINED);

use Core::VultureUtils qw(&session &getTranslations &getStyle);
use SSO::ProfileManager qw(&setProfile &getProfile);

sub forward{
	my ($package_name, $r, $log, $dbh, $app, $user, $password) = @_;

	my (%session_SSO);
	session(\%session_SSO, $app->{timeout}, $r->pnotes('id_session_SSO'), $log, $app->{update_access_time});

	$log->debug("########## SSO_Learning ##########");

	#Getting fields to send	
	my $sql = "SELECT field.field_var, field.field_mapped, field.field_type, field.field_encrypted, field.field_value, field.field_prefix, field.field_suffix, field.field_desc FROM field, sso, app WHERE field.sso_id = sso.id AND sso.id = app.sso_forward_id AND app.id=? AND field.field_type != 'autologon_user' AND field.field_type != 'autologon_password' AND field.field_type != 'hidden'";
	$log->debug($sql);
    
	my $sth = $dbh->prepare($sql);
	$sth->execute($app->{id});
	my @fields =  @{$sth->fetchall_arrayref};
    $sth->finish();
    
    #Nothing to learn
    if(not scalar(@fields)){
        $r->content_type('text/html');
		$log->debug("Nothing to learn");
		$r->pnotes('SSO_Forwarding' => 'FORWARD');

        #Redirect user
		$r->headers_out->add('Location' => $r->unparsed_uri);	
		$r->status(302);
	    return Apache2::Const::REDIRECT;
    }
	
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
    my $translations = getTranslations($r, $log, $dbh, "SSO_LEARNING");
    
    #If no html, send form
    my $html = getStyle($r, $log, $dbh, $app, 'LEARNING', 'Please fill these fields', {FORM => $form}, $translations);
	
    #Print form
	if(not param('vulture_learning')){
		$r->pnotes('SSO_Forwarding' => 'LEARNING');
		$r->content_type('text/html');	
		$r->print($html =~ /<body>.+<\/body>/ ? $html : $form);
		
	#Learning was ok, move on SSO Forward
	} elsif(setProfile($r, $log, $dbh, $app, $user, @fields)) {
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
