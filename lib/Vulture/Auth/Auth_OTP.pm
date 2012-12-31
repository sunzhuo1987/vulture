#file:Auth/Auth_OTP.pm
#---------------------------------
#!/usr/bin/perl
package Auth::Auth_OTP;

use strict;
use warnings;

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
use Core::VultureUtils qw(&get_LDAP_object &generate_random_string &get_LDAP_field &get_LDAP_mobile);
use Auth::Auth_LDAP;

sub checkAuth {
    my ( $package_name, $r, $log, $dbh, $app, 
        $user, $password, $id_method,$session ) = @_;
    my $query = 'SELECT ldap_id,script,passlen,template,timeout from otp where id=?';
    my $sth   = $dbh->prepare($query);
    $sth->execute($id_method);
    my $var = $sth->fetchrow_hashref; 
    $sth->finish();
    return undef unless $var;
    my $ldap_id = $var->{'ldap_id'};
    my $script = $var->{'script'};
    my $passlen = $var->{'passlen'};
    my $template = $var->{'template'};
    my $timeout = $var->{'timeout'};  
    $log->debug("########## Auth_OTP ##########");
    if (!$session->{'otp_ldaped'}){
        # Auth LDAP    
        my $ret=Auth::Auth_LDAP::checkAuth('ldap',$r,$log,$dbh,$app,$user,$password,$ldap_id);
        if ($ret == Apache2::Const::OK){ 
            my $mobile = get_LDAP_mobile($log, $dbh,$ldap_id,$user);
            if (not $mobile){
                $log->error("OTP: cannot get mobile for user ...");
            }
            else{
                $log->debug("good ldap auth, lets generate OTP pass..");
                $r->pnotes('auth_message'=>"OTP_REQUIRED");
                my $otp_pass = Core::VultureUtils::generate_random_string($passlen);
                # generate script
                $template =~ s/\{\{user\}\}/$user/g;
                $template =~ s/\{\{pass\}\}/$otp_pass/g;
                $script =~ s/\{\{number\}\}/$mobile/g;
                $script =~ s/\{\{message\}\}/$template/g;
                # execute user script
                $log->debug("execute script [$script]");
                `$script`;
                $session->{'otp_ldaped'} = 1;
                $session->{'otp_pass'} = Digest::SHA1::sha1_hex($otp_pass);
            }
        }
        return Apache2::Const::FORBIDDEN;
    }
    else{ 
        $log->debug("check OTP pass now..");
        # Check OTP
        if (Digest::SHA1::sha1_hex($password) eq $session->{'otp_pass'}){
            $log->debug("good OTP pass, welcome back sir"); 
            # delete OTP
            $session->{'otp_pass'} = undef;
            $session->{'otp_ldaped'} = undef;
            return Apache2::Const::OK;
        }
        else{
            $log->debug("BAD OTP pass, try again");
            return Apache2::Const::FORBIDDEN;
        }
    }
}
1;
