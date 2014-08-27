#file:Auth/Auth_LDAP.pm
#---------------------------------
#!/usr/bin/perl
package Auth::Auth_LDAP;

use strict;
use warnings;

BEGIN {
    use Exporter ();
    our @ISA       = qw(Exporter);
    our @EXPORT_OK = qw(&checkAuth);
}

use Apache2::Reload;
use Apache2::Log;

use DBI;

use Net::LDAP;
use Net::LDAP::Util;

use Apache2::Const -compile => qw(OK FORBIDDEN);

use Core::VultureUtils qw(&get_LDAP_object);

sub checkAuth {
    my ( $package_name, $r, $log, $dbh, $app, $user, $password, $id_method, 
        $session, $class, $csrf_ok ) =
      @_;

    $log->debug("########## Auth_LDAP ##########");
    return Apache2::Const::FORBIDDEN unless $csrf_ok and $user ne '';

    my (
        $ldap,              $ldap_url_attr,
        $ldap_uid_attr,     $ldap_user_ou,
        $ldap_group_ou,     $ldap_user_filter,
        $ldap_group_filter, $ldap_user_scope,
        $ldap_group_scope,  $ldap_base_dn,
        $ldap_group_member, $ldap_group_is_dn,
        $ldap_group_attr,   $ldap_chpass_attr,
        $ldap_account_locked_attr
    ) = Core::VultureUtils::get_LDAP_object( $log, $dbh, $id_method );

    unless ($ldap) {
        $r->pnotes( 'auth_message' => 'AUTH_SERVER_FAILURE' );
        return Apache2::Const::FORBIDDEN;
    }
    $user = Net::LDAP::Util::escape_filter_value($user);

    #Check if user exist in LDAP directory 
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
    my $object = $mesg->entry(0);

    #User not present in LDAP Directory => connexion refused
    if ( $mesg->code or !$object ) {
        $log->error( $user
              . " not found [base=$ldap_base_dn, scope=$ldap_user_scope, filter=(&"
              . $ldap_user_filter . "("
              . $ldap_uid_attr . "="
              . $user
              . "))]" );
        $ldap->unbind;
        return Apache2::Const::FORBIDDEN;
    }
    #Trying to authenticate user
    $mesg = $ldap->bind( $object->dn, password => $password );
    $ldap->unbind();
    #handling LDAP error
    if ( $mesg->code ) {
        $log->error( "LDAP bind failed with " . $object->dn );
        $log->debug( "LDAP error : " . $mesg->code ." : " .$mesg->error);
        handleErrorMessage($r, $log, $dbh, $user, $id_method);
        return Apache2::Const::FORBIDDEN;
    }

    #No error => User is authenticated
    $r->pnotes( 'username' => "$user" );
    return Apache2::Const::OK;
}
sub handleErrorMessage(){
    my ( $r, $log, $dbh, $user, $id_method ) = @_;

    my (
        $ldap,              $ldap_url_attr,
        $ldap_uid_attr,     $ldap_user_ou,
        $ldap_group_ou,     $ldap_user_filter,
        $ldap_group_filter, $ldap_user_scope,
        $ldap_group_scope,  $ldap_base_dn,
        $ldap_group_member, $ldap_group_is_dn,
        $ldap_group_attr,   $ldap_chpass_attr,
        $ldap_account_locked_attr
    ) = Core::VultureUtils::get_LDAP_object( $log, $dbh, $id_method );

    #Check if user account is locked
    $log->debug("Locked account check");
    my $mesg_locked = $ldap->search(
        base => $ldap_user_ou ? $ldap_user_ou : $ldap_base_dn,
        scope  => $ldap_user_scope,
        filter => "(&"
          . $ldap_user_filter . "("
          . $ldap_uid_attr . "="
          . $user . ")("
          . $ldap_account_locked_attr . "))"
    );
    my $object_locked = $mesg_locked->entry(0);

    #Send ACCOUNT_LOCKED message if account locked
    if (defined($ldap_account_locked_attr)
        and $ldap_account_locked_attr
        and defined($object_locked) )
    {
        $r->pnotes( 'auth_message' => 'ACCOUNT_LOCKED' );
        $log->debug($user . " account is locked");
    }

    #Check if user account need to change password
    $log->debug("Need change password check");
    my $mesg_change = $ldap->search(
        base => $ldap_user_ou ? $ldap_user_ou : $ldap_base_dn,
        scope  => $ldap_user_scope,
        filter => "(&"
          . $ldap_user_filter . "("
          . $ldap_uid_attr . "="
          . $user . ")("
          . $ldap_chpass_attr . "))"
    );
    my $object_change = $mesg_change->entry(0);

    #Send NEED_CHANGE_PASS message if user account need to change password
    if ( defined($ldap_chpass_attr) 
         and $ldap_chpass_attr 
         and defined($object_change) ) 
    {
        $r->pnotes( 'auth_message' => 'NEED_CHANGE_PASS' );
        $log->debug("User $user need to change password");
    }
}
1;

