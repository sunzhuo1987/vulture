#file:Auth/Auth_LDAP.pm
#---------------------------------
package Auth::Auth_LDAP;

use Apache2::Reload;
use Apache2::Log;

use DBI;

use Net::LDAP;

use Apache2::Const -compile => qw(OK FORBIDDEN);

use Core::VultureUtils qw(&getLDAP_object);

sub checkAuth{
	my ($package_name, $r, $log, $dbh, $app, $user, $password, $id_method) = @_;

	$log->debug("########## Auth_LDAP ##########");

	my ($ldap, $ldap_url_attr, $ldap_uid_attr, $ldap_user_ou, $ldap_group_ou, $ldap_user_filter, $ldap_group_filter, $ldap_user_scope, $ldap_group_scope, $ldap_base_dn, $ldap_group_member, $ldap_group_is_dn, $ldap_group_attr) = getLDAP_object($log, $dbh, $id_method);
	return Apache2::Const::FORBIDDEN if (!$ldap);

	my $mesg = $ldap->search(base => $ldap_user_ou ? $ldap_user_ou : $ldap_base_dn,
				 scope => $ldap_user_scope,
				 filter => "(&" . $ldap_user_filter . "(" . $ldap_uid_attr . "=" . $user . "))"
			     );

	$log->debug("[LDAP SEARCH] (&" . $ldap_user_filter . "(" . $ldap_uid_attr . "=" . $user . "))");
	my $object = $mesg->entry(0);
	if ($mesg->code or !$object) {
		$log->error($user .
			    " not found [base=$ldap_base_dn, scope=$ldap_user_scope, filter=(&".
			    $ldap_user_filter . "(" . $ldap_uid_attr . "=" . $user . "))]");
        $ldap->unbind;
		return Apache2::Const::FORBIDDEN;
	}

	$mesg = $ldap->bind($object->dn, password => $password);
	if ($mesg->code) {
		$log->error("LDAP bind failed with ". $object->dn);
        $ldap->unbind;
		return Apache2::Const::FORBIDDEN;
	}
    
	#my $need_change_password = $object->get_value($ldap_chpass_attr) if ($ldap_chpass_attr);
    #    return 2 if (defined($need_change_password) and $need_change_password == 1);

	if ($ldap_url_attr && (my ($url) = $object->get_value($ldap_url_attr))) {
		$r->pnotes('url_to_mod_proxy' => $url);
		$log->debug($user . " routed to ". $url ." via mod_proxy");
	}

    $ldap->unbind;
	return Apache2::Const::OK;
}

1;
