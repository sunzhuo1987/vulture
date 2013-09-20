#file:SSO/ProfileManager.pm
#-------------------------
#!/usr/bin/perl
package SSO::ProfileManager;

use strict;
use warnings;

use Apache2::RequestRec ();
use Apache2::RequestIO  ();
use CGI qw/:standard/;

use Apache2::Log;
use Apache2::Reload;

use Apache2::Const -compile => qw(OK REDIRECT FORBIDDEN);
use LWP;

use Core::VultureUtils qw(&get_DB_object &get_LDAP_object &encrypt &decrypt);

use Net::LDAP;
use Net::LDAP::Util;
use DBI;

use String::ShellQuote;

BEGIN {
    use Exporter ();
    my @ISA = qw(Exporter);
    my @EXPORT_OK =
      qw(&get_profile &set_profile &delete_profile);
}

sub get_profile {
    my ( $r, $log, $dbh, $app, $user ) = @_;

    $log->debug("########## Profile Manager (get_profile) ##########");

    $user = $r->pnotes('username') || $r->user;
    my $password = $r->pnotes('password');

    #Return hash with all values (profile + fields like autologon_ or hidden)
    my $return = {};

#Getting specials fields like "autologon_* or hidden fields"
#my $query = "SELECT field_var, field_type, field_encrypted, field_value, field_prefix, field_suffix FROM field, sso, app WHERE field.sso_id = sso.id AND sso.id = app.sso_forward_id AND app.id=? AND (field_type = 'autologon_password' OR field_type = 'autologon_user' OR field_type = 'hidden')";
    my $query = "SELECT field_var, field_type, field_encrypted, field_value,field_prefix, field_suffix FROM field JOIN  sso ON field.sso_id=sso.id JOIN  app ON sso.id = app.sso_forward_id WHERE app.id=? AND field_type IN ('autologon_password','autologon_user','hidden','script','script-cookie')";
    $log->debug($query);
    my $sth = $dbh->prepare($query);
    $sth->execute( $app->{id} );

    #Adding data to post variable
    #URI encoding is needed
    my $ref = $sth->fetchall_arrayref;
    $sth->finish();
    foreach my $row ( @{$ref} ) {
        my ( $var, $type, $need_decryption, $value, $field_prefix,
            $field_suffix )
          = @$row;
        if ( $type eq 'autologon_user' ) {
		    #$return->{$var} = $field_prefix.$user.$field_suffix;
		    $return->{$var} = [$field_prefix.$user.$field_suffix,$type];
        }
        elsif ( $type eq 'autologon_password' ) {
		    #$return->{$var} = $field_prefix.$password.$field_suffix;
		    $return->{$var} = [$field_prefix.$password.$field_suffix,$type];
        }
	elsif($type eq 'script') {
		    $log->debug("sso type is script");
            my $script = "$value " . shell_quote $user;
		    $value = `$script`;
		    #return->{$var} = $field_prefix.$value.$field_suffix;
		    $return->{$var} = [$field_prefix.$value.$field_suffix,$type];
	}
        else {
            if ($need_decryption) {
                $log->debug("Decrypting $var");
                $value = Core::VultureUtils::decrypt($r, $value );
            }
		    #$return->{$var} = $field_prefix.$value.$field_suffix;        
		    $return->{$var} = [$field_prefix.$value.$field_suffix,$type];
        }
    }

    #Getting auth type related to profile manager
    $sth = $dbh->prepare(
"SELECT auth.auth_type AS type, auth.id_method, sso.table_mapped, sso.base_dn_mapped, sso.app_mapped, sso.user_mapped FROM auth, sso, app WHERE app.id = ? AND sso.id = app.sso_forward_id AND auth.id = sso.auth_id"
    );
    $sth->execute( $app->{id} );
    my $result = $sth->fetchrow_hashref;
    $sth->finish();

    #Getting fields to retrieve
    $query =
"SELECT field_var, field_mapped, field_encrypted, field_value, field_prefix, field_suffix, field_type FROM field, sso, app WHERE field.sso_id = sso.id AND sso.id = app.sso_forward_id AND app.id=? AND field.field_type NOT IN ('autologon_user','autologon_password','hidden','script','script-cookie')";
    $sth = $dbh->prepare($query);
    $sth->execute( $app->{id} );
    my @fields = @{ $sth->fetchall_arrayref };
    $sth->finish();

    #If fields exists (i.e. not just autologon_ or hidden fields)
    if (@fields) {
        $log->debug( "result type: " . $result->{type} );

        #SQL Database
        if ( $result->{type} eq 'sql' ) {
            my ( $new_dbh, $ref ) =
              Core::VultureUtils::get_DB_object( $log, $dbh,
                $result->{id_method} );
            my $query =
                "SELECT * FROM "
              . $result->{table_mapped}
              . " WHERE "
              . $result->{app_mapped}
              . "= ? AND "
              . $result->{user_mapped} . "= ? ";
            my $sth = $new_dbh->prepare($query);
            $log->debug($query);
            $sth->execute( $app->{id}, $user );

            $ref = $sth->fetchrow_hashref;
            $sth->finish();
            $new_dbh->disconnect;

            #Parse fields to get values
            foreach my $field (@fields) {
                my ( $var, $mapping, $need_decryption, $value, $field_prefix,
                    $field_suffix ,$type)
                  = @$field;

                if ( defined $ref->{$mapping} ) {

                    #Decryption is needed
                    if ($need_decryption) {
	                    #$return->{$var} = $field_prefix.decrypt($r, decode_base64($ref->{$mapping})).$field_suffix;
			    $return->{$var} = [$field_prefix.Core::VultureUtils::decrypt($r, $ref->{$mapping}).$field_suffix,$type];
                    }
                    else {
	                    #$return->{$var} = $field_prefix.$ref->{$mapping}.$field_suffix;
			    $return->{$var} = [$field_prefix.$ref->{$mapping}.$field_suffix,$type];
                    }
                }
                else {
                        $return->{$var} = [$field_prefix.$value.$field_suffix || '',$type]
                }
            }
            return $return;

            #LDAP
        }
        elsif ( $result->{type} eq 'ldap' ) {

            #Getting LDAP object from Vulture Utils
            my (
                $ldap,              $ldap_url_attr,     $ldap_uid_attr,
                $ldap_user_ou,      $ldap_group_ou,     $ldap_user_filter,
                $ldap_group_filter, $ldap_user_scope,   $ldap_group_scope,
                $ldap_base_dn,      $ldap_group_member, $ldap_group_is_dn,
                $ldap_group_attr
              )
              = Core::VultureUtils::get_LDAP_object( $log, $dbh,
                $result->{id_method} );
            return Apache2::Const::FORBIDDEN if ( !$ldap );
            $user = Net::LDAP::Util::escape_filter_value($user);

            #Looking for entry
            my $mesg = $ldap->search(
                base => $ldap_user_ou ? $ldap_user_ou : $ldap_base_dn,
                scope  => $ldap_user_scope,
                filter => "(&"
                  . $ldap_user_filter . "("
                  . $ldap_uid_attr . "="
                  . $user . "))"
            );

            $log->debug( "[LDAP SEARCH] (&"
                  . $ldap_user_filter . "("
                  . $ldap_uid_attr . "="
                  . $user
                  . "))" );
            my $entry = $mesg->entry(0);
            if ( $mesg->code or !$entry ) {
                $log->error( $user
                      . " not found [base="
                      . $result->{base_dn_mapped}
                      . ", scope=$ldap_user_scope, filter=(&"
                      . $ldap_user_filter . "("
                      . $ldap_uid_attr . "="
                      . $user
                      . "))]" );
                $ldap->unbind;
                return Apache2::Const::FORBIDDEN;
            }

            #User found. Get property and return ref
            foreach my $field (@fields) {
                my ( $var, $mapping, $need_decryption, $value, $field_prefix,
                    $field_suffix, $type )
                  = @$field;
                $log->debug("Checking access for property $mapping");
                if ( $entry->exists($mapping) ) {

                    #Decryption is needed
                    if ($need_decryption) {
	                    #$return->{$var} = $field_prefix.decrypt($r, decode_base64($entry->get_value($mapping))).$field_suffix;
	                    $return->{$var} = [$field_prefix.Core::VultureUtils::decrypt($r, $entry->get_value($mapping)).$field_suffix,$type];
                    }
                    else {
	                    #$return->{$var} = $field_prefix.$entry->get_value($mapping).$field_suffix;
	                    $return->{$var} = [$field_prefix.$entry->get_value($mapping).$field_suffix,$type];
                    }
                }
                else {
                    $return->{$var} = [ $field_prefix . $value . $field_suffix, $type];
                }
            }
            return $return;
        }
        else {
            $log->error( "Bad SSO type in SSO_Forward : " . $result->{type} );
        }

        # Only hidden fields or autologon_
    }
    else {
        return $return;
    }
}

sub set_profile {
    my ( $r, $log, $dbh, $app, $user, @fields ) = @_;

    $log->debug("########## Profile Manager (set) ##########");

    #Getting auth type related to profile manager
    my $sth = $dbh->prepare(
"SELECT auth.auth_type AS type, auth.id_method, sso.table_mapped, sso.base_dn_mapped, sso.app_mapped, sso.user_mapped FROM auth, sso, app WHERE app.id = ? AND sso.id = app.sso_forward_id AND auth.id = sso.auth_id"
    );
    $sth->execute( $app->{id} );
    my $result = $sth->fetchrow_hashref;
    $sth->finish();

    #SQL Database
    if ( $result->{type} eq 'sql' ) {
        my ( $new_dbh, $ref ) =
          Core::VultureUtils::get_DB_object( $log, $dbh, $result->{id_method} )
          ;    #Pushing values into mapped columns

        #Making 2 arrays : columns and values for query
        my $columns;
        my $values;
        my @arr_vals = ( $app->{id}, $user );
        foreach my $field (@fields) {
            my ( $var, $mapped, $type, $need_encryption, $default_value,
                $prefix, $suffix, $desc )
              = @$field;

            #Getting values posted
            if (
                    param('vulture_learning')
                and param($var)
                and (   $type ne 'hidden'
                    and $type ne 'autologon_user'
                    and $type ne 'autologon_password' )
              )
            {
                my $value = param($var);
                if ($need_encryption) {
                    $log->debug("Encrypting $var");
                    $value =  Core::VultureUtils::encrypt( $r, $value );
                }

         #$log->debug("Pushing ".$prefix.$value.$suffix." into column $mapped");
                $log->debug( "Pushing " . $var . " into column $mapped" );
                $columns .= ", " . $mapped;
                $values  .= ", ?";
                push @arr_vals, ( $prefix . $value . $suffix );

                #$values .= ", '".$prefix.$value.$suffix."'";
            }
        }

        #Delete the row before inserting a new one
        my $query =
            "DELETE FROM "
          . $result->{table_mapped}
          . " WHERE "
          . $result->{user_mapped}
          . "= ? AND "
          . $result->{app_mapped} . " = ?";
        $log->debug($query);
        $new_dbh->do( $query, undef, $user, $app->{id} );

        #Insert a row
        $query =
            'INSERT INTO '
          . $result->{table_mapped} . ' ( '
          . $result->{app_mapped} . ', '
          . $result->{user_mapped};
        $query .= $columns;
        $query .= ") VALUES ( ?, ? ";
        $query .= $values;
        $query .= ")";

        $log->debug($query);
        my $sth = $new_dbh->prepare($query);
        my $c   = 1;
        foreach my $par (@arr_vals) {
            $sth->bind_param( $c, $par );
            $c++;
        }

        #Return result of insert
        $sth->execute();
        my $toret = $sth->rows;
        $sth->finish();
        return $toret;

        #LDAP
    }
    elsif ( $result->{type} eq 'ldap' ) {

        #Getting LDAP object from Vulture Utils
        my (
            $ldap,              $ldap_url_attr,     $ldap_uid_attr,
            $ldap_user_ou,      $ldap_group_ou,     $ldap_user_filter,
            $ldap_group_filter, $ldap_user_scope,   $ldap_group_scope,
            $ldap_base_dn,      $ldap_group_member, $ldap_group_is_dn,
            $ldap_group_attr
          )
          = Core::VultureUtils::get_LDAP_object( $log, $dbh,
            $result->{id_method} );
        return Apache2::Const::FORBIDDEN if ( !$ldap );
        $user = Net::LDAP::Util::escape_filter_value($user);

        my $mesg = $ldap->search(
            base => $ldap_user_ou ? $ldap_user_ou : $ldap_base_dn,
            scope  => $ldap_user_scope,
            filter => "(&"
              . $ldap_user_filter . "("
              . $ldap_uid_attr . "="
              . $user . "))"
        );

        $log->debug( "[LDAP SEARCH] (&"
              . $ldap_user_filter . "("
              . $ldap_uid_attr . "="
              . $user
              . "))" );
        my $entry = $mesg->entry(0);
        if ( $mesg->code or !$entry ) {
            $log->error( $user
                  . " not found [base="
                  . $result->{base_dn_mapped}
                  . ", scope=$ldap_user_scope, filter=(&"
                  . $ldap_user_filter . "("
                  . $ldap_uid_attr . "="
                  . $user
                  . "))]" );
            $ldap->unbind;
            return Apache2::Const::FORBIDDEN;
        }

        foreach my $field (@fields) {
            my ( $var, $mapped, $type, $need_encryption, $default_value,
                $prefix, $suffix, $desc )
              = @$field;

            #Getting values posted
            if (
                    param('vulture_learning')
                and param($var)
                and (   $type ne 'hidden'
                    and $type ne 'autologon_user'
                    and $type ne 'autologon_password' )
              )
            {
                my $value = param($var);
                if ($need_encryption) {
                    $log->debug("Encrypting $var");
                    $value = Core::VultureUtils::encrypt( $r, $value );
                }
                $log->debug( "Replacing " 
                      . $prefix 
                      . $value 
                      . $suffix
                      . " into $mapped" );

                if ( $entry->exists($mapped) ) {
                    $entry->delete( $mapped => undef );
                }
                $entry->add( $mapped => $value );
            }
        }
        $entry->update($ldap);

        #Close LDAP
        $ldap->unbind;
    }
    else {
        return;
    }
}

#Delete profile from specific user and specific app
sub delete_profile {
    my ( $r, $log, $dbh, $app, $user ) = @_;

    $log->debug("########## Profile Manager ##########");

    #Getting auth type related to profile manager
    my $sth = $dbh->prepare(
"SELECT auth.auth_type AS type, auth.id_method, sso.table_mapped, sso.app_mapped, sso.user_mapped FROM auth, sso, app WHERE app.id='"
          . $app->{id}
          . "' AND sso.id = app.sso_forward_id AND auth.id = sso.auth_id" );
    $sth->execute;
    my $result = $sth->fetchrow_hashref;
    $sth->finish();

    #SQL Database
    if ( $result->{type} eq 'sql' ) {
        my ( $new_dbh, $ref ) =
          Core::VultureUtils::get_DB_object( $log, $dbh, $result->{id_method} );
        $log->debug("Deleting values for $user");
        my $sql =
            "DELETE FROM "
          . $result->{table_mapped}
          . " WHERE "
          . $result->{app_mapped}
          . "= ? AND "
          . $result->{user_mapped} . "= ? ";
        $log->debug($sql);
        return $dbh->do( $sql, undef, $app->{id}, $user );
    }
    elsif ( $result->{type} eq 'ldap' ) {

    }
    else {
        return;
    }
}
1;
