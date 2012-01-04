#file:SSO/ProfileManager.pm
#-------------------------
#!/usr/bin/perl
package SSO::ProfileManager;

use strict;
use warnings;

use Apache2::RequestRec ();
use Apache2::RequestIO ();
use CGI qw/:standard/;

use Apache2::Log;
use Apache2::Reload;

use LWP;

use Crypt::CBC;
use Crypt::OpenSSL::AES;

use Core::VultureUtils qw(&get_DB_object &get_LDAP_object);

use Net::LDAP;
use DBI;
use MIME::Base64;

use Data::Dumper;

BEGIN {
    use Exporter ();
    my @ISA = qw(Exporter);
    my @EXPORT_OK = qw(&get_profile &set_profile &delete_profile &encrypt &decrypt);
}

sub get_profile{
    my ($r, $log, $dbh, $app, $user) = @_;
    
    $log->debug("########## Profile Manager ##########");
    
    $user = $r->pnotes('username') || $r->user;
	my $password = $r->pnotes('password');
    
    #Return hash with all values (profile + fields like autologon_ or hidden)
    my $return = {};
    
    #Getting specials fields like "autologon_* or hidden fields"
    #my $query = "SELECT field_var, field_type, field_encrypted, field_value, field_prefix, field_suffix FROM field, sso, app WHERE field.sso_id = sso.id AND sso.id = app.sso_forward_id AND app.id=? AND (field_type = 'autologon_password' OR field_type = 'autologon_user' OR field_type = 'hidden')";
	my $query = "SELECT field_var, field_type, field_encrypted, field_value, field_prefix, field_suffix FROM field JOIN  sso ON field.sso_id=sso.id JOIN  app ON sso.id = app.sso_forward_id WHERE app.id=? AND (field_type = 'autologon_password' OR field_type = 'autologon_user' OR field_type = 'hidden')"; 
	$log->debug($query);
    my $sth = $dbh->prepare($query);
	$sth->execute($app->{id});
    
	#Adding data to post variable
    #URI encoding is needed
	my $ref = $sth->fetchall_arrayref;
    $sth->finish();
	foreach my $row (@{$ref}) {
        $log->debug(Dumper($row));
        my ($var, $type, $need_decryption, $value, $field_prefix, $field_suffix) = @$row;
		if($type eq 'autologon_user'){
            $return->{$var} = $field_prefix.$user.$field_suffix;
        } elsif($type eq 'autologon_password'){
            $return->{$var} = $field_prefix.$password.$field_suffix;
        } else {
		    if($need_decryption){
		        $log->debug("Decrypting $var");
                $value = decrypt(decode_base64($value));
		    }
            $return->{$var} = $field_prefix.$value.$field_suffix;        
        }
	}
    
    #Getting auth type related to profile manager
    $sth = $dbh->prepare("SELECT auth.auth_type AS type, auth.id_method, sso.table_mapped, sso.base_dn_mapped, sso.app_mapped, sso.user_mapped FROM auth, sso, app WHERE app.id = ? AND sso.id = app.sso_forward_id AND auth.id = sso.auth_id");
    $sth->execute($app->{id});
    my $result = $sth->fetchrow_hashref;
    $sth->finish();
    
    #Getting fields to retrieve
    $query = "SELECT field_var, field_mapped, field_encrypted, field_value, field_prefix, field_suffix FROM field, sso, app WHERE field.sso_id = sso.id AND sso.id = app.sso_forward_id AND app.id=? AND field.field_type != 'autologon_user' AND field.field_type != 'autologon_password' AND field.field_type != 'hidden'";
	$sth = $dbh->prepare($query);
	$sth->execute($app->{id});
	my @fields =  @{$sth->fetchall_arrayref};
    $sth->finish();
    
    #If fields exists (i.e. not just autologon_ or hidden fields)
    if (@fields) {
        #SQL Database
        if($result->{type} eq 'sql'){
            my ($new_dbh, $ref) = get_DB_object($log, $dbh, $result->{id_method});
            my $query = "SELECT * FROM ".$result->{table_mapped}." WHERE ".$result->{app_mapped}."='".$app->{id}."' AND ".$result->{user_mapped}."='".$user."'";
	        my $sth = $new_dbh->prepare($query);
            $log->debug($query);
            $sth->execute;
            
            $ref = $sth->fetchrow_hashref;
            $sth->finish();
            $new_dbh->disconnect;

            #Parse fields to get values
	        foreach my $field (@fields) {
	            my ($var, $mapping, $need_decryption, $value, $field_prefix, $field_suffix) = @$field;
	            
	            if(defined $ref->{$mapping}){
	                #Decryption is needed
	                if($need_decryption){
	                    $return->{$var} = $field_prefix.decrypt($r, decode_base64($ref->{$mapping})).$field_suffix;
	                } else {
	                    $return->{$var} = $field_prefix.$ref->{$mapping}.$field_suffix;
	                }
                } else {
                    $return->{$var} = $field_prefix.$value.$field_suffix;
                }
	        }
            return $return;
            
        #LDAP
        } elsif ($result->{type} eq 'ldap') {
            
            #Getting LDAP object from Vulture Utils
            my ($ldap, $ldap_url_attr, $ldap_uid_attr, $ldap_user_ou, $ldap_group_ou, $ldap_user_filter, $ldap_group_filter, $ldap_user_scope, $ldap_group_scope, $ldap_base_dn, $ldap_group_member, $ldap_group_is_dn, $ldap_group_attr) = get_LDAP_object($log, $dbh, $result->{id_method});
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
            foreach my $field (@fields) {
                my ($var, $mapping, $need_decryption, $value, $field_prefix, $field_suffix) = @$field;
                $log->debug("Checking access for property $mapping");
                if($entry->exists($mapping)){
                    #Decryption is needed
	                if($need_decryption){
	                    $return->{$var} = $field_prefix.decrypt($r, decode_base64($entry->get_value($mapping))).$field_suffix;
	                } else {
	                    $return->{$var} = $field_prefix.$entry->get_value($mapping).$field_suffix;
	                }
                } else {
                    $return->{$var} = $field_prefix.$value.$field_suffix;
                }
            }
            return $return;
        } else {
        
        }
        
    # Only hidden fields or autologon_
    } else {
        return $return;
    }
}

sub set_profile{
    my($r, $log, $dbh, $app, $user, @fields) = @_;

    $log->debug("########## Profile Manager ##########");
    
    #Getting auth type related to profile manager
    my $sth = $dbh->prepare("SELECT auth.auth_type AS type, auth.id_method, sso.table_mapped, sso.base_dn_mapped, sso.app_mapped, sso.user_mapped FROM auth, sso, app WHERE app.id = ? AND sso.id = app.sso_forward_id AND auth.id = sso.auth_id");
    $sth->execute($app->{id});
    my $result = $sth->fetchrow_hashref;
    $sth->finish();
    
    #SQL Database
    if($result->{type} eq 'sql'){
        #I'm so sorry for this kind of hack. Please forgive me
        my ($new_dbh, $ref) = get_DB_object($log, $dbh, $result->{id_method});#Pushing values into mapped columns
        
        #Making 2 arrays : columns and values for query
        my $columns;
        my $values;
        foreach my $field (@fields) {
		    my ($var, $mapped, $type, $need_encryption, $default_value, $prefix, $suffix, $desc) = @$field;

		    #Getting values posted
		    if(param('vulture_learning') and param($var) and ($type ne 'hidden' and $type ne 'autologon_user' and $type ne 'autologon_password')){
		        my $value = param($var);
		        if($need_encryption){
                    $log->debug("Encrypting $var");
                    $value = encode_base64(encrypt($r, $value));
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
        my ($ldap, $ldap_url_attr, $ldap_uid_attr, $ldap_user_ou, $ldap_group_ou, $ldap_user_filter, $ldap_group_filter, $ldap_user_scope, $ldap_group_scope, $ldap_base_dn, $ldap_group_member, $ldap_group_is_dn, $ldap_group_attr) = get_LDAP_object($log, $dbh, $result->{id_method});
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
		    if(param('vulture_learning') and param($var) and ($type ne 'hidden' and $type ne 'autologon_user' and $type ne 'autologon_password')){
		        my $value = param($var);
		        if($need_encryption){
                    $log->debug("Encrypting $var");
                    $value = encode_base64(encrypt($r, $value));
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
sub delete_profile{
    my($r, $log, $dbh, $app, $user) = @_;
    
    $log->debug("########## Profile Manager ##########");
    
    #Getting auth type related to profile manager
    my $sth = $dbh->prepare("SELECT auth.auth_type AS type, auth.id_method, sso.table_mapped, sso.app_mapped, sso.user_mapped FROM auth, sso, app WHERE app.id='".$app->{id}."' AND sso.id = app.sso_forward_id AND auth.id = sso.auth_id");
    $sth->execute;
    my $result = $sth->fetchrow_hashref;
    $sth->finish();
    
    #SQL Database
    if($result->{type} eq 'sql'){
        my ($new_dbh, $ref) = get_DB_object($log, $dbh, $result->{id_method});
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
    my $cipher = Crypt::CBC->new(
                        -key    => $key,
                        -cipher => "Crypt::OpenSSL::AES"
#			-header => 'none'
                );             
    my $value = $cipher->encrypt($value_to_encrypt);
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
    my $cipher = Crypt::CBC->new(
                        -key    => $key,
                        -cipher => "Crypt::OpenSSL::AES"
#			-header => 'none'
                );             
    my $value = $cipher->decrypt($value_to_decrypt);
    close $fh or die $!;
    return $value;

}
1;
