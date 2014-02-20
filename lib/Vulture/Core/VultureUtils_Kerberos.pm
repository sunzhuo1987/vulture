#file:Core/VultureUtils_Kerberos.pm
#---------------------------------
#!/usr/bin/perl
package Core::VultureUtils_Kerberos;

use strict;
use warnings;

BEGIN {
    use Exporter ();
    our @ISA       = qw(Exporter);
    our @EXPORT_OK = qw(&getKerberosTgt &getKerberosServiceToken);
}

use Authen::Krb5;
use GSSAPI;

sub getKerberosTgt {
    my ($log,$r,$user,$password,$realm) = @_; 

    Authen::Krb5::init_context() or die "::getKerberosTgt : no context: $@\n";
    Authen::Krb5::init_ets();

    # setup krb5 credential cache name environnement variable for the GSSAPI infra.
    $ENV{'KRB5CCNAME'}="KEYRING:krb5cc_".$user;

    my $userp=Authen::Krb5::parse_name("$user\@$realm");
    my $servicep = Authen::Krb5::parse_name("krbtgt/$realm\@$realm");
    my $cc = Authen::Krb5::cc_default();
    my $kerr = Authen::Krb5::get_in_tkt_with_password($userp, $servicep, $password, $cc);


    if ( $kerr ) { 
        $log->debug("::getKerberosTgt : request for $user\@$realm success");
        Authen::Krb5::free_context();
        return $kerr;
    } else {
        my $errorcode = Authen::Krb5::error();
        my $reason = Authen::Krb5::error($kerr);
        $log->debug("::getKerberosTgt : request for $user\@$realm failed!!!: errorcode = $errorcode , desc = $reason ");

        # TODO : find a way to compare krb5 errorcode rather than error text.
        # check if password has expired : KRB5KDC_ERR_KEY_EXP = -1765328361
        if ( uc($reason)  eq "PASSWORD HAS EXPIRED" ) { 
            $r->pnotes( 'auth_message' => 'NEED_CHANGE_PASS' );
            $log->debug("::getKerberosTgt failed : Password has expired");
        }   

        # check if account has expired or is disabled : KRB5KDC_ERR_CLIENT_REVOKED = -1765328366
        if ( uc($reason)  eq "CLIENTS CREDENTIALS HAVE BEEN REVOKED" ) {
            $r->pnotes( 'auth_message' => 'NEED_CONTACT_ADMIN' );
            $log->debug("::getKerberosTgt failed : Account is locked");
        }

        Authen::Krb5::free_context();
        return $kerr;
    }
}
# Return a comma separated list of kerberos auth_id children
sub getKerberosAuths {
    my ($log, $dbh, $auth_id) = @_;

    my $krb_auths = '';
    my $sth = $dbh->prepare("SELECT name, auth_type, id_method FROM auth WHERE id=?");
    $sth->execute($auth_id);
    my ($name, $type, $id_m) = $sth->fetchrow_array();
    $log->debug("::getKerberosAuths : check auth name=$name ,type=$type , id=$auth_id");
    $sth->finish();
    if ($type eq 'logic'){
        $sth = $dbh->prepare("SELECT auth_id FROM logic_auths WHERE logic_id=?");
        $sth->execute($id_m);
        my @row = $sth->fetchrow_array;
        while (@row){
            $krb_auths .= getKerberosAuths($log, $dbh, $row[0], $krb_auths) . ",";
            @row = $sth->fetchrow_array;
        }
        $sth->finish();
    }elsif ($type eq 'kerberos'){
        $krb_auths .= $id_m . ",";
        $log->debug("::getKerberosAuths : found kerberos auth, auth_id=$id_m");
    }

    return $krb_auths;
}
# Return default Kerberos Realm of your host
sub getKerberosDefaultRealm {
    Authen::Krb5::init_context() or die "::getKerberosDefaultRealm : no context: $@\n";
    Authen::Krb5::init_ets();
    my $realm=Authen::Krb5::get_default_realm();
    Authen::Krb5::free_context();
    return $realm;
}
# Return Kerberos Realms list for app
sub getKerberosRealms {
    my ($log,$r,$dbh,$app) = @_;

    # Get kerberos realms configuration.
    my $realms = undef;
    $log->debug("::getKerberosRealms : retrieve app kerberos config for app.id=" . $app->{id});

    my ($query,$sth,$ref);
    $query = "SELECT sso_kerberos_default, sso_kerberos_domain from app WHERE app.id = ?";
    $log->debug($query);
    $sth = $dbh->prepare($query);
    $sth->execute($app->{id});
    my ( $sso_kerberos_default, $sso_kerberos_domain ) = $sth->fetchrow_array();
    $sth->finish();
    $log->debug("::getKerberosRealms : app kerberos config: sso_kerberos_default=$sso_kerberos_default, ,sso_kerberos_domain=$sso_kerberos_domain");
    
    #Retrieve Kerberos Domain from App configuration
    if ($sso_kerberos_default == 0 && $sso_kerberos_domain ne '') {
        $realms = $sso_kerberos_domain;
        $log->debug("::getKerberosRealms : Kerberos domain found from App config : $sso_kerberos_domain");
    }
    #Retrieve Kerberos Domain from Auth config
    elsif ($sso_kerberos_default == 1) {
        # Get the app auth_id config.
        my ($query, $sth, $ref);
        $query = "SELECT auth.name,auth.auth_type,auth.id FROM auth JOIN app ON auth.id=app.auth_id WHERE app.id = ?";
        $log->debug($query);
        $sth = $dbh->prepare($query);
        $sth->execute($app->{id});
        my ( $auth_name, $auth_type, $auth_id ) = $sth->fetchrow_array();
        $sth->finish();
        $log->debug("::getKerberosRealms : app auth config: name=$auth_name ,type=$auth_type ,id=$auth_id");

        # Get the app kerberos auth_id list.
        my $krb_auths = getKerberosAuths($log, $dbh, $auth_id);
        $log->debug("::getKerberosRealms : getKerberosAuths=$krb_auths");

        #Get the kerberos realm list
        for my $krb_auth_id ( split( ",", $krb_auths ) ) {
            if ( $krb_auth_id ) {
                $query = "SELECT * FROM kerberos WHERE id= ?";
                $log->debug($query);
                $sth = $dbh->prepare($query);
                $sth->execute($krb_auth_id);
                $ref = $sth->fetchrow_hashref;
                $sth->finish();

                $log->debug("::getKerberosRealms : found app auth config for kerberos realm=" . $ref->{'realm'});
                $realms .= $ref->{'realm'} . ",";
            }
        }
    }
    #If no kerberos auth defined for this app get the default infrastructure kerberos realm
    if (not defined $realms) {
        $log->warn("::getKerberosRealms : no kerberos auth found for this app, use default krb5 realm");
        $realms=getKerberosDefaultRealm();
    }

    $log->debug("::getKerberosRealms=$realms");

    return $realms;
}
sub getKerberosServiceTokenFromCredentialCache {
    my $svc = shift;
    my $host = shift;
    my $log = shift;


    Authen::Krb5::init_context() or die "::getKerberosServiceTokenFromCredentialCache : no context: $@\n";
    Authen::Krb5::init_ets();

    my $targethostname = join( '@', $svc, $host );
    my $status;
    my $otoken;

    TRY: {
        my ($target, $tname, $ttl );
        $status = GSSAPI::Name->import( $target,
                                       $targethostname,
                                       GSSAPI::OID::gss_nt_hostbased_service)
               or last;
        $status = $target->display($tname) or last;
        $log->debug("::getKerberosServiceTokenFromCredentialCache : using Name $tname");

        my $ctx = GSSAPI::Context->new();
        my $imech = GSSAPI::OID::gss_mech_krb5;
        my $iflags = GSS_C_REPLAY_FLAG;
        my $bindings = GSS_C_NO_CHANNEL_BINDINGS;
        my $creds = GSS_C_NO_CREDENTIAL;
        my $itime = 0;
        my $itoken = q{};

        $status = $ctx->init($creds,$target,
                            $imech,$iflags,$itime,$bindings,$itoken,
                            undef, $otoken,undef,undef) or last;
        $status = $ctx->valid_time_left($ttl) or last;
        $log->debug("::getKerberosServiceTokenFromCredentialCache : Security context's time to live $ttl secs");
    }

    Authen::Krb5::free_context();

    unless ($status->major == GSS_S_COMPLETE  ) {
        $log->error("::getKerberosServiceTokenFromCredentialCache failed, ERROR=$status");
        return 0;
    } else {
        $log->debug("::getKerberosServiceTokenFromCredentialCache succeded.");
        return $otoken;
    }
}
sub getKerberosServiceToken {
    my ($log,$r,$dbh,$app,$user,$pwd) = @_;

    #Get kerberos service and host from the app url
    my ($svc, $host );
    if ( $app->{url} =~ /^(.*):\/\/(.*)$/ ) {
        # NB: it seems that the service is always HTTP even for HTTPS app url
        # TODO : confirm with KRB5 RFC, is it a best practice or a standard?
        #$svc = $1;
        $svc = "http";
        $host = $2;
    }
    $log->debug("::getKerberosServiceToken : user=$user , svc=$svc , host=$host");

    # setup krb5 credential cache name environnement variable for the GSSAPI infra.
    $ENV{'KRB5CCNAME'}="KEYRING:krb5cc_".$user;

    # If the application is configured for kerberos auth, the user should have a CC
    # with a TGT and requesting the token from the CC will do the rest.
    my $token = getKerberosServiceTokenFromCredentialCache($svc, $host, $log);
    if (! $token) {
        # But it can fail for the following reasons :
        # - the user has been authenticated by a non kerberos method
        # - the request is balanced on another node where the user credential cache is new/empty (To Be Tested)
        # - the TGT has expired before vulture cookies (To Be Tested)

        $log->warn("::getKerberosServiceToken : request service token from CC failed => request a new TGT");

        # In this case we need to get all the kerberos realms configured for this app auth (ignore OR/AND operators)
        my $realms = getKerberosRealms($log,$r,$dbh,$app);

        # Now try them and return the token on the first success. 
        for my $realm ( split( ",", $realms ) ) {
            if ( $realm ) {
                $log->debug("::getKerberosServiceToken : test new TGT request for realm=$realm");
                # Now request the TGT 
                my $ticket = getKerberosTgt($log,$r,$user,$pwd,$realm);
                if ($ticket) {
                    $log->debug("::getKerberosServiceToken : TGT request success for realm=$realm");
                    if ( $token = getKerberosServiceTokenFromCredentialCache($svc, $host, $log)) {
                        return $token;
                    } else {
                        $log->debug("::getKerberosServiceToken : service token request failed for realm=$realm");
                    }
                } else {
                    $log->debug("::getKerberosServiceToken : TGT request failed for realm=$realm");
                }
            }
        }
    }
    if (! $token) {
        $log->error("::getKerberosServiceToken : service token request failed");
    }

    return $token;
}
1;
