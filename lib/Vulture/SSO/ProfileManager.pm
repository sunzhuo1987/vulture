#file:SSO/ProfileManager.pm
#-------------------------
package SSO::ProfileManager;

use Apache2::RequestRec ();
use Apache2::RequestIO ();
use Apache2::Request;

use Apache2::Log;
use Apache2::Reload;

use LWP;

use Crypt::CBC;
use Crypt::OpenSSL::AES;

use Core::VultureUtils qw(&getDB_object &getLDAP_object);

use Net::LDAP;
use DBI;

BEGIN {
    use Exporter ();
    @ISA = qw(Exporter);
    @EXPORT_OK = qw(&getProfile &setProfile &deleteProfile &encrypt &decrypt);
}

sub getProfile{
    my ($r, $log, $dbh, $app, $user) = @_;
    
    $log->debug("########## Profile Manager ##########");
    
    #Getting auth type related to profile manager
    my $sth = $dbh->prepare("SELECT auth.auth_type AS type, auth.id_method, sso.table_mapped, sso.base_dn_mapped, sso.app_mapped, sso.user_mapped FROM auth, sso, app WHERE app.id='".$app->{id}."' AND sso.id = app.sso_forward_id AND auth.id = sso.auth_id");
    $sth->execute;
    my $result = $sth->fetchrow_hashref;
    $sth->finish();
    
    #Getting fields to retrieve
    my $sql = "SELECT field.field_var, field.field_mapped, field.field_encrypted FROM field, sso, app WHERE field.sso_id = sso.id AND sso.id = app.sso_forward_id AND app.id=? AND field.field_type != 'autologon_user' AND field.field_type != 'autologon_password' AND field.field_type != 'hidden'";
	my $sth = $dbh->prepare($sql);
	$sth->execute($app->{id});
	my @fields =  @{$sth->fetchall_arrayref};
    $sth->finish();
    
    #If fields exists (i.e. not just autologon_ or hidden fields)
    if (@fields) {
        #SQL Database
        if($result->{type} eq 'sql'){
            my ($new_dbh, $ref) = getDB_object($log, $dbh, $result->{id_method});
            my $query = "SELECT * FROM ".$result->{table_mapped}." WHERE ".$result->{app_mapped}."='".$app->{id}."' AND ".$result->{user_mapped}."='".$user."'";
	        my $sth = $new_dbh->prepare($query);
            $log->debug($query);
            $sth->execute;
            
            #Return hashref
            my $ref = $sth->fetchrow_hashref;
            $sth->finish();
            $new_dbh->disconnect;
            
            my $return = {};

	        foreach my $field (@fields) {
	            my ($var, $mapping, $need_decryption) = @$field;
	            
	            if(defined $ref->{$mapping}){
	                #Decryption is needed
	                if($need_decryption){
	                    $return->{$var} = decrypt($r, $ref->{$mapping});
	                } else {
	                    $return->{$var} = $ref->{$mapping};
	                }
                }
	        }
	        
            return $return;
            
        #LDAP
        } elsif ($result->{type} eq 'ldap') {
            
            #Getting LDAP object from Vulture Utils
            my ($ldap, $ldap_url_attr, $ldap_uid_attr, $ldap_user_ou, $ldap_group_ou, $ldap_user_filter, $ldap_group_filter, $ldap_user_scope, $ldap_group_scope, $ldap_base_dn, $ldap_group_member, $ldap_group_is_dn, $ldap_group_attr) = getLDAP_object($log, $dbh, $result->{id_method});
	        return Apache2::Const::FORBIDDEN if (!$ldap);

            #Looking for entry
	        my $mesg = $ldap->search(base => $ldap_user_ou,
				         scope => $ldap_user_scope,
				         filter => "(&" . $ldap_user_filter . "(" . $ldap_uid_attr . "=" . $user . "))"
			             );

	        $log->debug("[LDAP SEARCH] (&" . $ldap_user_filter . "(" . $ldap_uid_attr . "=" . $user . "))");
	        my $entry = $mesg->entry(0);
	        if ($mesg->code or !$entry) {
		        $log->error($user .
			            " not found [base=".$result->{base_dn_mapped}.", scope=$ldap_user_scope, filter=(&" . $ldap_user_filter . "(" . $ldap_uid_attr . "=" . $user . "))]");
                $ldap->unbind;
		        return Apache2::Const::FORBIDDEN;
	        }
            
            #User found. Get property and return ref
            my %return_hash;
            foreach my $field (@fields) {
                my ($var, $mapping, $need_decryption) = @$field;
                $log->debug("Checking access for property $mapping");
                if($entry->exists($mapping)){
                    $return_hash{$var} = $entry->get_value($mapping);
                }
            }
            return \%return_hash;
        } else {
        
        }
    } else {
        return undef;
    }
}

sub setProfile{
    my($r, $log, $dbh, $app, $user, $req, @fields) = @_;

    $log->debug("########## Profile Manager ##########");
    
    #Getting auth type related to profile manager
    my $sth = $dbh->prepare("SELECT auth.auth_type AS type, auth.id_method, sso.table_mapped, sso.base_dn_mapped, sso.app_mapped, sso.user_mapped FROM auth, sso, app WHERE app.id='".$app->{id}."' AND sso.id = app.sso_forward_id AND auth.id = sso.auth_id");
    $sth->execute;
    my $result = $sth->fetchrow_hashref;
    $sth->finish();
    
    #SQL Database
    if($result->{type} eq 'sql'){
        #I'm so sorry for this kind of hack. Please forgive me
        my ($new_dbh, $ref) = getDB_object($log, $dbh, $result->{id_method});#Pushing values into mapped columns
        
        #Making 2 arrays : columns and values for query
        my $columns;
        my $values;
        foreach my $field (@fields) {
		    my ($var, $mapped, $type, $need_encryption, $default_value, $prefix, $suffix, $desc) = @$field;

		    #Getting values posted
		    if($req->param('vulture_learning') and $req->param($var) and ($type ne 'hidden' and $type ne 'autologon_user' and $type ne 'autologon_password')){
		        my $value = $req->param($var);
		        if($need_encryption){
                    $log->debug("Encrypting $var");
                    $value = encrypt($r, $value);
                }
                $log->debug("Pushing ".$prefix.$value.$suffix." into column $mapped");
                $columns .= ", ".$mapped;
                $values .= ", '".$prefix.$value.$suffix."'";
		    }
	    }
        my $query = "SELECT id FROM ".$result->{table_mapped}." WHERE ".$result->{user_mapped}."='".$user."' AND ".$result->{app_mapped}." = '".$app->{id}."'";
        $log->debug($query);
        my $res = $new_dbh->selectrow_array($query);
        #Delete the row before inserting a new one
        if($res){
            $query = 'DELETE FROM '.$result->{table_mapped}.' WHERE id = '.$res;
            $new_dbh->do($query);
        }
        #Insert a row
        $query = 'INSERT INTO '.$result->{table_mapped}.' ( '.$result->{app_mapped}.', '.$result->{user_mapped};
        $query .= $columns;
        $query .= ") VALUES ( '".$app->{id}."', '".$user."'";
        $query .= $values;
        $query .= ")";

        $log->debug($query);
        
        #Return result of insert
        return $new_dbh->do($query);
        
    #LDAP
    } elsif($result->{type} eq 'ldap') {
        
        #Getting LDAP object from Vulture Utils
        my ($ldap, $ldap_url_attr, $ldap_uid_attr, $ldap_user_ou, $ldap_group_ou, $ldap_user_filter, $ldap_group_filter, $ldap_user_scope, $ldap_group_scope, $ldap_base_dn, $ldap_group_member, $ldap_group_is_dn, $ldap_group_attr) = getLDAP_object($log, $dbh, $result->{id_method});
	    return Apache2::Const::FORBIDDEN if (!$ldap);

        my $mesg = $ldap->search(base => $ldap_user_ou,
				         scope => $ldap_user_scope,
				         filter => "(&" . $ldap_user_filter . "(" . $ldap_uid_attr . "=" . $user . "))"
			             );

        $log->debug("[LDAP SEARCH] (&" . $ldap_user_filter . "(" . $ldap_uid_attr . "=" . $user . "))");
	    my $entry = $mesg->entry(0);
	    if ($mesg->code or !$entry) {
		    $log->error($user .
			            " not found [base=".$result->{base_dn_mapped}.", scope=$ldap_user_scope, filter=(&" . $ldap_user_filter . "(" . $ldap_uid_attr . "=" . $user . "))]");
            $ldap->unbind;
		    return Apache2::Const::FORBIDDEN;
	    }
	    
        foreach my $field (@fields) {
		    my ($var, $mapped, $type, $need_encryption, $default_value, $prefix, $suffix, $desc) = @$field;

		    #Getting values posted
		    if($req->param('vulture_learning') and $req->param($var) and ($type ne 'hidden' and $type ne 'autologon_user' and $type ne 'autologon_password')){
		        my $value = $req->param($var);
		        if($need_encryption){
                    $log->debug("Encrypting $var");
                    $value = encrypt($r, $value);
                }
                $log->debug("Replacing ".$prefix.$value.$suffix." into $mapped");
                
                if($entry->exists($mapped)){
                    $entry->delete($mapped => undef);
                }
                $entry->add($mapped => $value);
            }
        }
        $entry->update($ldap);
        
        #Close LDAP
        $ldap->unbind;
    } else {
        return;
    }
}

#Delete profile from specific user and specific app
sub deleteProfile{
    my($r, $log, $dbh, $app, $user) = @_;
    
    $log->debug("########## Profile Manager ##########");
    
    #Getting auth type related to profile manager
    my $sth = $dbh->prepare("SELECT auth.auth_type AS type, auth.id_method, sso.table_mapped, sso.app_mapped, sso.user_mapped FROM auth, sso, app WHERE app.id='".$app->{id}."' AND sso.id = app.sso_forward_id AND auth.id = sso.auth_id");
    $sth->execute;
    my $result = $sth->fetchrow_hashref;
    $sth->finish();
    
    #SQL Database
    if($result->{type} eq 'sql'){
        my ($new_dbh, $ref) = getDB_object($log, $dbh, $result->{id_method});
        $log->debug("Deleting values for $user");
        my $sql = "DELETE FROM ".$result->{table_mapped}." WHERE ".$result->{app_mapped}."='".$app->{id}."' AND ".$result->{user_mapped}."='".$user."'";
        $log->debug($sql);
        return $dbh->do($sql);
    } elsif($result->{type} eq 'ldap') {
        
    } else {
        return;
    }
}

sub encrypt{
    my ($r, $value_to_encrypt) = @_;
    #Opening key file for encryption
	my $conf = $r->dir_config('VultureConfPath');
    open(my $fh, "<", $conf.'aes-encrypt-key.key') or die "cannot open < $conf aes-encrypt-key.key : $!";
    my @lines = <$fh>;
    my $key = $lines[0];
    
    #Encrypting
    $cipher = Crypt::CBC->new(
                        -key    => $key,
                        -cipher => "Crypt::OpenSSL::AES"
#			-header => 'none'
                );             
    $value = $cipher->encrypt($value_to_encrypt);
    close $fh or die $!;
    return $value;
}

sub decrypt{
    my ($r, $value_to_decrypt) = @_;
    #Opening key file for encryption
	my $conf = $r->dir_config('VultureConfPath');
    open(my $fh, "<", $conf.'aes-encrypt-key.key') or die "cannot open < $conf aes-encrypt-key.key : $!";
    my @lines = <$fh>;
    my $key = $lines[0];
    
    #Encrypting
    $cipher = Crypt::CBC->new(
                        -key    => $key,
                        -cipher => "Crypt::OpenSSL::AES"
#			-header => 'none'
                );             
    $value = $cipher->decrypt($value_to_decrypt);
    close $fh or die $!;
    return $value;

}
1;
