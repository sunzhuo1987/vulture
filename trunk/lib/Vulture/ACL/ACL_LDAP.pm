#file:ACL/ACL_LDAP.pm
#---------------------------------
package ACL::ACL_LDAP;

use Apache2::Reload;
use Apache2::Log;

use DBI;

use Net::LDAP;

use Apache2::Const -compile => qw(OK FORBIDDEN);

use Core::VultureUtils qw(&getLDAP_object);

sub checkACL{
	my ($package_name, $r, $log, $dbh, $app, $user, $id_method) = @_;

	$log->debug("########## ACL_LDAP ##########");

    my $query = "SELECT count(*) FROM userok,acl_userok WHERE acl_userok.acl_id = ? AND userok.user=?";
	$log->debug($query);

	if ($dbh->selectrow_array(($query, undef, $app->{'acl'}->{'id'}, $user))){
		return Apache2::Const::OK;

    #User is not in user_ok. It doesn't matter. Maybe he is in group ok
	} else {
		my ($ldap, $ldap_url_attr, $ldap_uid_attr, $ldap_user_filter, $ldap_group_filter, $ldap_user_scope, $ldap_group_scope, $ldap_base_dn, $ldap_group_member, $ldap_group_is_dn, $ldap_group_attr) = getLDAP_object($log, $dbh, $id_method);

	    return Apache2::Const::FORBIDDEN if (!$ldap);

	    my $mesg = $ldap->search(base   => $ldap_base_dn,
				     scope => $ldap_user_scope,
				     filter => "(&" . $ldap_user_filter . "(" . $ldap_uid_attr . "=" . $user . "))"
				    );
	    $log->debug("[LDAP SEARCH] (&" . $ldap_user_filter . "(" . $ldap_uid_attr . "=" . $user . "))");
	    $mesg->code and return Apache2::Const::FORBIDDEN;
	    my $object = $mesg->entry(0) or return Apache2::Const::FORBIDDEN;
	    my $dnuser = $object->dn;

	    my $filter_member;
	    if ($ldap_group_is_dn) { # Active Directory or RFC2307bis
		    $filter_member = $ldap_group_member . "=" . $dnuser;
	    }
	    else {
		    $filter_member = $ldap_uid_attr . "=" . $user;
	    }

	    $mesg = $ldap->search(base   => $ldap_group_base ? $ldap_group_base : $ldap_base_dn,
			          scope => $ldap_group_scope,
			          filter => "(&". $ldap_group_filter . "(".$filter_member."))"
			         );
	    $log->debug("[LDAP SEARCH] (&" . $ldap_group_filter . "(".$filter_member."))");
	    $mesg->code and return Apache2::Const::FORBIDDEN;
	    $object = $mesg->entry(0);
	    $ldap->unbind;
	    return Apache2::Const::OK if ($object and $object->dn);
	}

	
}
1;
