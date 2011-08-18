#file:Plugin/SSO_LEARNING.pm
#-------------------------
package SSO::SSO_LEARNING;

use Apache2::RequestRec ();
use Apache2::RequestIO ();
use Apache2::Request;

use Apache2::Log;
use Apache2::Reload;

use LWP;
use HTML::Form;

use Apache2::Const -compile => qw(OK DECLINED);

use Core::VultureUtils qw(&session);

sub forward{
	my ($package_name, $r, $log, $dbh, $app, $user, $password) = @_;

	my (%session_SSO);
	session(\%session_SSO, $app->{timeout}, $r->pnotes('id_session_SSO'));

	$log->debug("########## SSO_Learning ##########");

	#Getting fields to send	
	my $sql = "SELECT post.field_type, post.field_var, post.field_value AS default_value, post.field_prefix, post.field_suffix, post.field_desc FROM post, component_app WHERE post.component_id = component_app.components_id AND component_app.app_id = ? AND post.field_type != 'autologon_user' AND post.field_type != 'autologon_password'";
	
	my $sth = $dbh->prepare($sql);
	$sth->execute($app->{id});


	#Getting values posted
	my $req = Apache2::Request->new($r);	
		
	
	#Adding data to post variable
	my $form = "<h3>To access to this app, you must specify the following fields</h3><table>";
	$form .= "<form method=\"POST\" name='app_form' action=\"\">";
	$form .= "<input type=hidden name=vulture_learning value=1>";
	foreach my $row (@{$sth->fetchall_arrayref}) {
		my ($type, $var, $default_value, $prefix, $suffix, $desc) = @$row;

		#Getting values posted
		if($req->param('vulture_learning') and $req->param($var) and ($type ne 'autologon_user' and $type ne 'autologon_password')){
			$log->debug("Setting value for $var => ".$req->param($var));
			my $sql = "INSERT INTO profile (app_id, user, field_var, value) VALUES (".$app->{id}.", '".$user."', '".$var."', '".$prefix.$req->param($var).$suffix."')";
			$log->debug($sql);
			$dbh->do($sql);
		}

		#Display form
		if($type ne 'autologon_user' or $type ne 'autologon_password'){
			if($type eq 'hidden'){
				$form .= "<input type=\"hidden\" name=\"$var\" value=\"$default_value\">";
			} else {
				$form .= "<tr><td>$desc</td><td><input type=\"$type\" name=\"$var\" value=\"$default_value\"></td></tr>";
			}
		}
	}
	$form .= "<tr><td></td><td><input type=\"submit\"></td></tr>";
	$form .= "</form></table>";

	$sth->finish();
	if(not $req->param('vulture_learning')){
		$r->pnotes('SSO_Forwarding' => 'Learning');
		$r->content_type('text/html');	
		$r->print($form);
	} else {
		$r->content_type('text/html');
		$log->debug("Learning was a huge success");
		$r->pnotes('SSO_Forwarding' => 'POST');

		$r->headers_out->add('Location' => $r->unparsed_uri);	

		#Set status
		$r->status(302);

	return Apache2::Const::REDIRECT;
	}

	
}

1;
