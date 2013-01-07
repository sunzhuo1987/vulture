#file:Auth/Auth_OTP.pm
#---------------------------------
#!/usr/bin/perl
package Auth::Auth_OTP;

use strict;
use warnings;

use String::ShellQuote;

BEGIN {
    use Exporter ();
    our @ISA       = qw(Exporter);
    our @EXPORT_OK = qw(&checkAuth);
}

use Apache2::Reload;
use Apache2::Log;
use Digest::SHA1 qw(sha1_hex);

use DBI;
use Apache2::Const -compile => qw(OK FORBIDDEN);
use Core::VultureUtils;
use Auth::Auth_LDAP;
use Auth::Auth_SQL;

sub checkAuth {
    my (
        $package_name, $r,        $log,       $dbh, $app,
        $user,         $password, $id_method, $session
    ) = @_;
    my $query =
      (     'SELECT auth_type, id_method, otp.name, '
          . ' script, template, passlen, timeout, contact_field'
          . ' FROM auth, otp WHERE auth.id = otp.auth_id AND otp.id=?' );
    my $sth = $dbh->prepare($query);
    $sth->execute($id_method);
    my $var = $sth->fetchrow_hashref;
    $sth->finish();

    unless ($var) {

        # broken conf?
        $log->error("unable to get otp method $id_method");
        return Apache2::Const::FORBIDDEN;
    }
    my $auth_id       = $var->{'id_method'};
    my $auth_type     = $var->{'auth_type'};
    my $contact_field = $var->{'contact_field'};
    my $script        = $var->{'script'};
    my $passlen       = $var->{'passlen'};
    my $template      = $var->{'template'};
    my $timeout       = $var->{'timeout'};
    my $ret;
    my ( $auth_func, $field_func );
    $log->debug("########## Auth_OTP ##########");

    if ( !$session->{'otp_step1'} ) {

        # first step: we have to use external auth method
        my $otp_auths = {
            sql => {
                auth_f  => \&Auth::Auth_SQL::checkAuth,
                field_f => \&Core::VultureUtils::get_SQL_field
            },
            ldap => {
                auth_f  => \&Auth::Auth_LDAP::checkAuth,
                field_f => \&Core::VultureUtils::get_LDAP_field
            }
        };

        # wtf : an invalid auth type was associated with this otp
        unless ( $otp_auths->{$auth_type} ) {
            $log->error("bad auth_type '$auth_type' in otp auth");
            return Apache2::Const::FORBIDDEN;
        }
        my $auth = $otp_auths->{$auth_type};
        $log->debug("lets check $auth_type");

        # check auth
        unless (
            &{ $auth->{auth_f} }( $auth_type, $r, $log, $dbh, $app, $user,
                $password, $auth_id ) == Apache2::Const::OK )
        {
            return Apache2::Const::FORBIDDEN;
        }

        # get contact infos
        my $contact =
          &{ $auth->{field_f} }( $log, $dbh, $auth_id, $user, $contact_field );
        unless ($contact) {
            $log->error("OTP: cannot get contact info for user ...");
            return Apache2::Const::FORBIDDEN;
        }
        $log->debug("good auth, lets generate OTP pass..");
        my $otp_pass = Core::VultureUtils::generate_random_string($passlen);

        # quick fix: set a unused auth_message to avoid
        #      'login failed' message in responseHandler
        $r->pnotes( 'auth_message' => "OTP_REQUIRED" );

        # variables validation
        if (   $user =~ /__CONTACT__/g
            or $user =~ /__MESSAGE__/g
            or $contact =~ /__MESSAGE__/g )
        {
            $log->error("cannot otpize user $user with contact $contact");
            return Apache2::Const::FORBIDDEN;
        }

        # generate message
        $template =~ s/__PASS__/$otp_pass/g;
        $template =~ s/__USER__/$user/g;

        # generate script
        $template = shell_quote $template;
        $contact  = shell_quote $contact;
        $script =~ s/__CONTACT__/$contact/g;
        $script =~ s/__MESSAGE__/$template/g;

        # execute user script
        # $log->debug("sending message [$script]");
        `$script`;
        $session->{otp_step1} = time();
        $session->{otp_user}  = $user;
        $session->{otp_pass}  = Digest::SHA1::sha1_hex($otp_pass);

        # this will show only otp name on the auth form
        $r->pnotes( "auth_name" => $var->{'name'} );

        # always return forbidden in step1
        # step2 only can return OK
        return Apache2::Const::FORBIDDEN;
    }
    else {

        # step 2
        if ( $session->{'otp_step1'} + $timeout < time() ) {
            $log->debug("OTP step2: timeout for user $user");
            delete $session->{'otp_pass'};
            delete $session->{'otp_user'};
            delete $session->{'otp_step1'};
            return Apache2::Const::FORBIDDEN;
        }
        $log->debug("check OTP pass now..");

        # Check OTP
        if ( Digest::SHA1::sha1_hex($password) eq $session->{'otp_pass'} ) {
            $log->debug("good OTP pass for $user");

            # delete OTP
            delete $session->{otp_user};
            delete $session->{otp_pass};
            delete $session->{otp_step1};
            return Apache2::Const::OK;
        }
        else {
            $log->debug("BAD OTP pass, user $user can try again");

            # show otp auth name
            $r->pnotes( "auth_name" => $var->{'name'} );
            return Apache2::Const::FORBIDDEN;
        }
    }
}
1;
