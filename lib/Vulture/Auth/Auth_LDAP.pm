#file:Auth/Auth_LDAP.pm
#---------------------------------
package Auth::Auth_LDAP;

use Apache2::Reload;
use Apache2::Log;

use DBI;

use Net::LDAP;

use Apache2::Const -compile => qw(OK FORBIDDEN);

sub checkAuth{
	my ($package_name, $r, $log, $dbh, $app, $user, $password, $id_method) = @_;

	$log->debug("########## Auth_LDAP ##########");

	my ($ldap, $ldap_url_attr, $ldap_uid_attr, $ldap_user_filter, $ldap_group_filter, $ldap_user_scope, $ldap_group_scope, $ldap_base_dn,
	   $ldap_group_base, $ldap_group_member, $ldap_group_is_dn, $ldap_group_attr, $ldap_pass_attr, $ldap_chpass_attr) = ldap_obj($log, $app, $dbh);
	return Apache2::Const::FORBIDDEN if (!$ldap);

	my $mesg = $ldap->search(base => $ldap_base_dn,
				 scope => $ldap_user_scope,
				 filter => "(&" . $ldap_user_filter . "(" . $ldap_uid_attr . "=" . $user . "))"
			     );

	$log->debug("[LDAP SEARCH] (&" . $ldap_user_filter . "(" . $ldap_uid_attr . "=" . user . "))");
	my $object = $mesg->entry(0);
	if ($mesg->code or !$object) {
		$log->error($user .
			    " not found [base=$ldap_base_dn, scope=$ldap_user_scope, filter=(&".
			    $ldap_user_filter . "(" . $ldap_uid_attr . "=" . $user . "))]");
		return Apache2::Const::FORBIDDEN;
	}

	$mesg = $ldap->bind($object->dn, password => $password);
	if ($mesg->code) {
		$log->error("LDAP bind failed with ". $object->dn);
		return Apache2::Const::FORBIDDEN;
	}

	my $need_change_password = $object->get_value($ldap_chpass_attr) if ($ldap_chpass_attr);
        return 2 if (defined($need_change_password) and $need_change_password == 1);

	if ($ldap_url_attr && (my ($url) = $object->get_value($ldap_url_attr))) {
		$r->pnotes('url_to_mod_proxy' => $url);
		$log->debug($user . " routed to ". $url ." via mod_proxy");
	}
	return Apache2::Const::OK;
}

sub getLDAP_object{
	my ($log, $app, $dbh) = @_;

	my $query = "SELECT ldap_addr, ldap_port, ldap_encrypt, ldap_cacert_path, ldap_dn, ".
	  "ldap_password, ldap_base_dn, ldap_user_scope, ldap_user_attr, ldap_user_filter, ".
	  "ldap_group_base, ldap_group_scope, ldap_group_attr, ldap_group_filter, ".
	  "ldap_group_member, ldap_group_is_dn, ldap_url_attr, ldap_protocol, ldap_pass_attr, ldap_chpass_attr ".
	    "FROM ldap, app, auth ".
	      "WHERE app.id_auth='".$app->{auth_id}."' AND auth.id_method=ldap.id AND auth.id=app.id_auth";
	$log->debug($query);
	my $sth = $dbh->prepare($query);
	$sth->execute;
	my ($ldap_server, $ldap_port, $ldap_encrypt, $ldap_cacert_path, $ldap_bind_dn,
	    $ldap_bind_password, $ldap_base_dn, $ldap_user_scope, $ldap_uid_attr,
	    $ldap_user_filter, $ldap_group_base, $ldap_group_scope, $ldap_group_attr,
	    $ldap_group_filter, $ldap_group_member, $ldap_group_is_dn,
	    $ldap_url_attr, $ldap_protocol, $ldap_pass_attr, $ldap_chpass_attr) = $sth->fetchrow;

	$ldap_cacert_path="/var/www/vulture/conf/cacerts" if ($ldap_cacert_path eq '');
	$ldap_user_filter = "(|(objectclass=posixAccount)(objectclass=inetOrgPerson)(objectclass=person))"
	  if ($ldap_user_filter eq '');
	$ldap_group_filter = "(|(objectclass=posixGroup)(objectclass=group)(objectclass=groupofuniquenames))"
	  if ($ldap_group_filter eq '');

	my @servers;
	foreach (split(/,\s*/, $ldap_server)) {
		push @servers, ($ldap_encrypt eq "ldaps" ? "ldaps://" : "") . $_ ;
	}

	my $ldap;
	if ( $ldap_encrypt eq "ldaps") {
		$ldap = Net::LDAP->new(\@servers,
				       port => $ldap_port,
				       version => $ldap_protocol,
				       capath => $ldap_cacert_path
				      );
	}
	else {
		$ldap = Net::LDAP->new(\@servers,
				       port => $ldap_port,
				       version => $ldap_protocol
				      );
	}
	if ($ldap_encrypt eq "start-tls") {
		$ldap->start_tls(
				verify => 'require',
				capath => $ldap_cacert_path
				);
	}
	if (!$ldap) {
		$log->error("LDAP connection to $ldap_server failed");
		return ;
	}
	my $mesg = $ldap->bind($ldap_bind_dn, password => $ldap_bind_password);

	if ($mesg->code) {
		$log->error("Unable to bind with $ldap_bind_dn on $ldap_server");
		return ;
	}
	($ldap, $ldap_url_attr, $ldap_uid_attr, $ldap_user_filter, $ldap_group_filter, $ldap_user_scope, $ldap_group_scope, $ldap_base_dn, $ldap_group_base,
	 $ldap_group_member, $ldap_group_is_dn, $ldap_group_attr, $ldap_pass_attr, $ldap_chpass_attr);
}

1;
