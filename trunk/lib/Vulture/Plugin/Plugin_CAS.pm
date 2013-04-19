#file:Plugin/Plugin_CAS.pm
#-------------------------
#!/usr/bin/perl
package Plugin::Plugin_CAS;

use strict;
use warnings;

BEGIN {
    use Exporter ();
    our @ISA       = qw(Exporter);
    our @EXPORT_OK = qw(&plugin);
}

use Apache2::Log;
use Apache2::Reload;
use Apache2::Request;
use APR::URI;
use XML::LibXML;
use Error qw(:try);
use POSIX;

use Core::VultureUtils
  qw(&session &get_memcached &set_memcached &get_cookie &get_app &get_LDAP_field &get_SQL_field);

use Apache2::Const -compile => qw(OK FORBIDDEN);
use Net::LDAP::Util;
use URI::URL; 

sub trim {
    my $arg = shift;
    $arg =~ s/^\s+//;
    $arg =~ s/\s+$//;
    return $arg;
}

sub getXsDate() {
    return POSIX::strftime( "%Y-%m-%dT%H:%M:%SZ", gmtime );
}

sub genXid() {
    my @cs  = qw(a b c d e f 0 1 2 3 4 5 6 7 8 9);
    my $xid = '_';
    my $c   = 32;
    while ( $c > 0 ) {
        $xid .= $cs[ int( rand(16) ) ];
        $c--;
    }
    return $xid;
}

sub plugin {
    my ( $package_name, $r, $log, $dbh, $intf, $app, $options ) = @_;

    $log->debug("########## Plugin_CAS ##########");
    my ( $action, $service, $ticket );
    my $req     = Apache2::Request->new($r);
    my $mc_conf = $r->pnotes('mc_conf');

    #Get parameters
    $action = @$options[0];
    $log->debug("plugin CAS on action $action");

    my $url = $req->param('url');
    $service =
         $req->param('service')
      || $req->param('serviceValidate')
      || $req->param('TARGET')
      || $req->param('target')
      || $req->param('samlValidate');
    $ticket = $req->param('ticket') || $req->param('TICKET') || '';

    #Get memcached data
    my (%users);
    %users = %{ Core::VultureUtils::get_memcached('vulture_users_in',$mc_conf) || {} };

    #CAS Portal doesn't have auth
    my $auths = $intf->{'auth'};
    if ( not defined @$auths or not @$auths ) {
        $log->debug("Auth in CAS is undefined");
        return Apache2::Const::FORBIDDEN;
    }

    #If user want to login in CAS (redirected by service), set $url_to_redirect
    if ( $action eq 'login' ) {
        $log->debug("Login");

        #User not logged in SSO
        my $parsed_service = APR::URI->parse( $r->pool, $service );
        my $host = $parsed_service->hostname;

        #Get app
        my $app =
          Core::VultureUtils::get_app( $log, $dbh, $mc_conf, $intf->{id},
            $host )
          if defined $host;
        $app->{'auth'} = $auths;

        #Send app if exists.
        $r->pnotes( 'app' => $app );

        #Getting SSO session if exists.
        my $SSO_cookie_name =
          Core::VultureUtils::get_cookie( $r->headers_in->{Cookie},
            $r->dir_config('VultureProxyCookieName') . '=([^;]*)' );
        my (%session_SSO);

        Core::VultureUtils::session( \%session_SSO, $intf->{sso_timeout},
            $SSO_cookie_name, $log, $mc_conf, $intf->{sso_update_access_time} );

        #Get session id if not exists
        if ( $SSO_cookie_name ne $session_SSO{_session_id} ) {
            $log->debug("Replacing SSO id");
            $SSO_cookie_name = $session_SSO{_session_id};
        }

        #Set cookie for SSO portal
        $r->err_headers_out->add(
                'Set-Cookie' => $r->dir_config('VultureProxyCookieName') . "="
              . $session_SSO{_session_id}
              . "; path=/; domain="
              . $r->hostname );

        $r->pnotes( 'id_session_SSO' => $SSO_cookie_name );

        #Destroy useless handlers
        $r->set_handlers( PerlFixupHandler => undef );

        return Apache2::Const::OK;

        #Validate service ticket
    }
    elsif ( $action eq 'validate' ) {
        $log->debug("Validate ticket");
        my $res = "no\n\n";

#Each user has an hash like { ticket => id_ticket, ticket_service => service, ticket_created => timestamp, SSO => id_session_SSO }

        while ( my ( $key, $hashref ) = each %users ) {
            my %user_hash = %$hashref;

            #Delete old ticket if too old
            if (
                $intf->{cas_st_timeout} > 0
                and (
                    time() - $user_hash{ticket_created} >
                    $intf->{cas_st_timeout} )
              )
            {
                delete $hashref->{ticket};
                delete $hashref->{ticket_service};
                delete $hashref->{ticket_created};
                next;
            }

            #Check if parameter matches with stored tickets
            if (    exists $user_hash{ticket}
                and $user_hash{ticket} eq $ticket
                and exists $user_hash{ticket_service}
                and $user_hash{ticket_service} eq $service
                and exists $user_hash{ticket_created} )
            {
                my $login;
                $res = "yes\n$login\n";

                #Unvalidate ticket
                delete $hashref->{ticket};
                delete $hashref->{ticket_service};
                delete $hashref->{ticket_created};

                #Stop loop
                last;
            }
        }

        #Commit changes
        Core::VultureUtils::set_memcached( 'vulture_users_in', \%users );

        #Display result in ResponseHandler
        $r->pnotes( 'response_content'      => $res );
        $r->pnotes( 'response_content_type' => 'text/plain' );

        #Destroy useless handlers
        $r->set_handlers( PerlAuthenHandler => undef );
        $r->set_handlers( PerlAuthzHandler  => undef );
        $r->set_handlers( PerlFixupHandler  => undef );
        return Apache2::Const::OK;

        #Check if user is logged in application
    }
    elsif ( $action eq 'serviceValidate' ) {
        $log->debug("serviceValidate");
        my $xml =
          "<cas:serviceResponse xmlns:cas='http://www.yale.edu/tp/cas'>";
        my $errorCode  = "INVALID_TICKED";
        my $user_found = 0;

        #Check if all parameters are set
        unless ( defined $ticket and defined $service ) {
            $errorCode = "INVALID_REQUEST";
        }
        else {

#Each user has an hash like { ticket => id_ticket, ticket_service => service, ticket_created => timestamp, SSO => id_session_SSO }
            while ( my ( $login, $hashref ) = each %users ) {
                my %user_hash = %$hashref;

                #Delete old ticket if too old
                if (
                    $intf->{cas_st_timeout} > 0
                    and (
                        time() - $hashref->{ticket_created} >
                        $intf->{cas_st_timeout} )
                  )
                {
                    delete $hashref->{ticket};
                    delete $hashref->{ticket_service};
                    delete $hashref->{ticket_created};
                    next;
                }

                #Check if parameter matches with stored tickets
                if ( exists $user_hash{ticket}
                    and $user_hash{ticket} eq $ticket )
                {

                    #Service must match with stored service
                    if ( exists $user_hash{ticket_service}
                        and $user_hash{ticket_service} ne $service )
                    {
                        $errorCode = "INVALID_SERVICE";
                    }
                    else {
                        $xml .=
"<cas:authenticationSuccess><cas:user>$login</cas:user></cas:authenticationSuccess>";
                        $user_found = 1;
                    }

                    #Unvalidate ticket
                    delete $hashref->{ticket};
                    delete $hashref->{ticket_service};
                    delete $hashref->{ticket_created};

                    last;
                }
            }
        }

        #Commit changes
        Core::VultureUtils::set_memcached( 'vulture_users_in', \%users );

        unless ($user_found) {
            $xml .=
"<cas:authenticationFailure code=\"$errorCode\"></cas:authenticationFailure>";
      $log->debug("no user found");
        }
        $xml .= "</cas:serviceResponse>";

        #Display result in ResponseHandler
        $r->pnotes( 'response_content'      => $xml );
        $r->pnotes( 'response_content_type' => 'text/xml' );

        #Destroy useless handlers
        $r->set_handlers( PerlAuthenHandler => undef );
        $r->set_handlers( PerlAuthzHandler  => undef );
        $r->set_handlers( PerlFixupHandler  => undef );
        return Apache2::Const::OK;

        #Nothing
    }
    elsif ( $action eq 'samlValidate' ) {
        $log->debug("CAS:SAML: samlValidate");

        #        my $posted = $req->content;
        my $posted = '';
        while ( $r->read( my $postd, 1024 ) ) { $posted .= $postd; }
        my $parser   = XML::LibXML->new;
        my $badquery = 0;
        my $status   = "Success";
        my $username = '';
        unless ( defined $service ) {
            $log->debug("CAS:SAML:no target ");
            $status   = "Requester";
            $badquery = 1;
        }
        else {
            try {
                my $xmlreq = $parser->load_xml( string => $posted );
                my $xpc = XML::LibXML::XPathContext->new($xmlreq);
                $xpc->registerNs( "samlp",
                    "urn:oasis:names:tc:SAML:1.0:protocol" );
                my $ticket =
                  trim( $xpc->findvalue("//samlp:AssertionArtifact") );
                my $reqnodes = $xpc->findnodes("//samlp:Request");
                if ( @$reqnodes eq 1 ) {
                    $log->debug("CAS:SAML: got token");
                    my $reqnode = @$reqnodes[0];
                    my $major   = $reqnode->getAttribute("MajorVersion");
                    my $minor   = $reqnode->getAttribute("MinorVersion");
                    unless ( $major == 1 and $minor == 1 ) {
                        $status   = "VersionMismatch";
                        $badquery = 1;
                    }
                    my $user_found = 0;
####################################################################
                    while ( my ( $login, $hashref ) = each %users ) {
                        my %user_hash = %$hashref;
          
                        if (
                            $intf->{cas_st_timeout} > 0
                            and (
                                time() - $hashref->{ticket_created} >
                                $intf->{cas_st_timeout} )
                          )
                        {
                            delete $hashref->{ticket};
                            delete $hashref->{ticket_service};
                            delete $hashref->{ticket_created};
                            next;
                        }
                        if ( exists $user_hash{ticket}
                            and $user_hash{ticket} eq $ticket )
                        {
               my $testL1 = new URI::URL $service;
                            $log->debug($testL1->host);
                            if (exists $user_hash{ticket_service}){
                                my $testL2 = new URI::URL $user_hash{ticket_service};
                                if ($testL2->host ne $testL1->host)
                            {
                                $status   = "Requester";
                                $badquery = 1;
                            }
                            else {
                                $user_found = 1;
                                $username   = $login;
                            }
              }
                            #Unvalidate ticket
                            $log->debug("delete ticjets");
                            delete $hashref->{ticket};
                            delete $hashref->{ticket_service};
                            delete $hashref->{ticket_created};
                            last;
                        }
                    }
                    Core::VultureUtils::set_memcached( 'vulture_users_in',
                        \%users );
                    if ( $user_found == 0 ) {
                        $badquery = 1;
                        $status   = 'Requester';
                    }
####################################################################
                }
                else { $badquery = 1; }
            }
            catch Error with {
                $status   = "Requester";
                $badquery = 1;
            };
        }
        my $rid     = genXid();
        my $instant = getXsDate();
        my $xml =
"<SOAP-ENV:Envelope xmlns:SOAP-ENV=\"http://schemas.xmlsoap.org/soap/envelope/\">\n";
        $xml .= "<SOAP-ENV:Header/>\n";
        $xml .= "<SOAP-ENV:Body>\n";
        $xml .=
"<Response xmlns=\"urn:oasis:names:tc:SAML:1.0:protocol\" xmlns:saml=\"urn:oasis:names:tc:SAML:1.0:assertion\" \n";
        $xml .=
"xmlns:samlp=\"urn:oasis:names:tc:SAML:1.0:protocol\" xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\" \n";
        $xml .=
"xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" IssueInstant=\"$instant\" \n";
        $xml .= "MajorVersion=\"1\" MinorVersion=\"1\" ResponseID=\"$rid\">\n";

        if ( $badquery == 1 ) {
            $xml .= "<Status>\n";
            $xml .= "<StatusCode Value=\"samlp:$status\"></StatusCode>\n";
            $xml .= "</Status>\n";
        }
        else {
            my $aid    = genXid();
            my $issuer = "VultureCAS";
            $xml .= "<Status>\n";
            $xml .= "<StatusCode Value=\"samlp:Success\"></StatusCode>\n";
            $xml .= "</Status>\n";
            $xml .= "<Assertion xmlns=\"urn:oasis:names:tc:SAML:1.0:assertion\" AssertionID=\"$aid\" \n";
            $xml .= "IssueInstant=\"$instant\" Issuer=\"$issuer\" \n";
            $xml .= " MajorVersion=\"1\" MinorVersion=\"1\">\n";
            my $before = time() - 15 * 60;
            my $after  = time() + 15 * 60;
            my $bf = POSIX::strftime( "%Y-%m-%dT%H:%M:%SZ", gmtime($before) );
            my $af = POSIX::strftime( "%Y-%m-%dT%H:%M:%SZ", gmtime($after) );
            $xml .= "<Conditions NotBefore=\"$bf\" NotOnOrAfter=\"$af\">\n";
            $xml .= "<AudienceRestrictionCondition><Audience>\n";
            $xml .= "$service\n";
            $xml .= "</Audience></AudienceRestrictionCondition>\n";
            $xml .= "</Conditions>\n";
            $xml .= "<AttributeStatement>\n";
            $xml .= "<Subject>\n";
            $xml .= "<NameIdentifier>$username</NameIdentifier>\n";
            $xml .= "<SubjectConfirmation><ConfirmationMethod>\n";
            $xml .= "urn:oasis:names:tc:SAML:1.0:cm:artifact\n";
            $xml .= "</ConfirmationMethod></SubjectConfirmation>\n";
            $xml .= "</Subject>\n";
            my ( $field, $fieldval ) = get_cas_field( $log, $dbh, $username );

            if ($field) {
                $xml .=
"<Attribute AttributeName=\"$field\" AttributeNamespace=\"http://www.ja-sig.org/products/cas/\">\n";
                $xml .= "<AttributeValue>$fieldval</AttributeValue>\n";
                $xml .= "</Attribute>\n";
            }
            $xml .= "</AttributeStatement>\n";
            $xml .=
"<AuthenticationStatement AuthenticationInstant=\"$instant\" AuthenticationMethod=\"urn:ietf:rfc:1510\">\n";
            $xml .= "<Subject>\n";
            $xml .= "<NameIdentifier>$username</NameIdentifier>\n";
            $xml .= "<SubjectConfirmation><ConfirmationMethod>\n";
            $xml .= "urn:oasis:names:tc:SAML:1.0:cm:artifact\n";
            $xml .= "</ConfirmationMethod></SubjectConfirmation>\n";
            $xml .= "</Subject>\n</AuthenticationStatement>\n";
            $xml .= "</Assertion>\n";
        }
        $xml .= "</Response>\n";
        $xml .= "</SOAP-ENV:Body>\n";
        $xml .= "</SOAP-ENV:Envelope>\n";

        $r->pnotes( 'response_content'      => $xml );
        $r->pnotes( 'response_content_type' => 'text/plain' );
        $r->set_handlers( PerlAuthenHandler => undef );
        $r->set_handlers( PerlAuthzHandler  => undef );
        $r->set_handlers( PerlFixupHandler  => undef );
        return Apache2::Const::OK;
    }
    else {
        return Apache2::Const::FORBIDDEN;
    }
}

sub get_cas_field {
    my ( $log, $dbh, $login ) = @_;
    my $query =
'SELECT field,auth_type,id_method FROM plugin_cas,auth where auth.id = plugin_cas.auth_id ';
    my $sth = $dbh->prepare($query);
    $sth->execute();
    my $cas_auth = $sth->fetchrow_hashref;
    $sth->finish();
    # No additionnal field
    return undef unless $cas_auth->{field};
    my $field  = $cas_auth->{field};
    my $atype  = $cas_auth->{auth_type};
    my $method = $cas_auth->{id_method};
    my $auth_types = {
        sql => \&Core::VultureUtils::get_SQL_field,
        ldap => \&Core::VultureUtils::get_LDAP_field
    };
    unless ($auth_types->{$atype}){
        $log->error("Plugin_CAS : Bad authentification method {$atype}");
        return undef;
    }
    # get field from ldap or sql
    my $ret = &{$auth_types->{$atype}}($log,$dbh,$method,$login,$field);
    # if success return field name and value
    return (defined $ret ? ($field,$ret) : undef); 
}
1;

