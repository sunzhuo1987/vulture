#file:ACL/ACL_LDAP.pm
#---------------------------------
package ACL::ACL_LDAP;

use Apache2::Reload;
use Apache2::Log;

use DBI;

use Net::LDAP;

use Apache2::Const -compile => qw(OK FORBIDDEN);

use Core::VultureUtils qw(&get_LDAP_object);

sub checkACL{
	my ($package_name, $r, $log, $dbh, $app, $user, $id_method) = @_;

	$log->debug("########## ACL_LDAP ##########");

    my $query = "SELECT count(*) FROM userok,acl_userok WHERE acl_userok.acl_id = ? AND userok.user=?";
	$log->debug($query);

	if ($dbh->selectrow_array(($query, undef, $app->{'acl'}->{'id'}, $user))){
		return Apache2::Const::OK;

    #User is not in user_ok. It doesn't matter. Maybe he is in group ok
	} else {
        
        #Get LDAP object
		my ($ldap, $ldap_url_attr, $ldap_uid_attr, $ldap_user_ou, $ldap_group_ou, $ldap_user_filter, $ldap_group_filter, $ldap_user_scope, $ldap_group_scope, $ldap_base_dn, $ldap_group_member, $ldap_group_is_dn, $ldap_group_attr, $ldap_chpass_attr) = get_LDAP_object($log, $dbh, $id_method);
        
        #If not LDAP, return FORBIDDEN 
	    return Apache2::Const::FORBIDDEN unless ($ldap);

	    my $mesg = $ldap->search(base => $ldap_user_ou ? $ldap_user_ou : $ldap_base_dn,
				     scope => $ldap_user_scope,
				     filter => "(&" . $ldap_user_filter . "(" . $ldap_uid_attr . "=" . $user . "))"
				    );
	    $log->debug("[LDAP SEARCH] (&" . $ldap_user_filter . "(" . $ldap_uid_attr . "=" . $user . "))");
	    $mesg->code and return Apache2::Const::FORBIDDEN;
	    my $object = $mesg->entry(0) or return Apache2::Const::FORBIDDEN;
	    my $dnuser = $object->dn;

        #Get LDAP groups
        my $sql = "SELECT `group` FROM groupok, acl_groupok WHERE acl_groupok.acl_id = ? AND groupok.id = acl_groupok.groupok_id";
        my $sth = $dbh->prepare($sql);
        $sth->execute($app->{'acl'}->{'id'});

        my $filter_groups;
        while (my ($group) = $sth->fetchrow) {
            $filter_groups .= "(".$ldap_group_attr."=".$group.")";
        }
        $sth->finish();
        
        # Active Directory or RFC2307bis
	    my $filter_member;
	    if ($ldap_group_is_dn) { 
		    $filter_member = $ldap_group_member . "=" . $dnuser;
	    } else {
		    $filter_member = $ldap_uid_attr . "=" . $user;
	    }

	    $mesg = $ldap->search(base => $ldap_group_ou ? $ldap_group_ou : $ldap_base_dn,
			          scope => $ldap_group_scope,
			          filter => "(&". $ldap_group_filter . "(|".$filter_groups.")(".$filter_member."))"
			         );
	    $log->debug("[LDAP SEARCH] (&" . $ldap_group_filter . "(|".$filter_groups.")(".$filter_member."))");
	    $mesg->code and return Apache2::Const::FORBIDDEN;
	    $object = $mesg->entry(0);
	    $ldap->unbind;
	    return Apache2::Const::OK if ($object and $object->dn);	
    }
}
1;
