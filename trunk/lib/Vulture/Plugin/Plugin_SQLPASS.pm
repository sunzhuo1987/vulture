#file:Plugin/Plugin_BLOCK.pm
#-------------------------
#!/usr/bin/perl
package Plugin::Plugin_SQLPASS;

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

use Apache2::Const -compile => qw(FORBIDDEN);
use Core::AuthenHandler qw(&csrf_ok);
use Core::Config qw(&get_key);
use Auth::Auth_SQL qw(&changePassword);

use Email::MIME;
use Email::Sender::Simple qw(sendmail);

sub plugin {
    my ( $package_name, $r, $log, $dbh, $intf, $app, $options ) = @_;

    $log->debug("########## Plugin_SQLPASS ##########");

    #Destroy useless handlers
    $r->set_handlers( PerlAccessHandler => undef );
    $r->set_handlers( PerlAuthenHandler => undef );
    $r->set_handlers( PerlAuthzHandler  => undef );
    $r->set_handlers( PerlFixupHandler  => undef );

    my $mc_conf = $r->pnotes('mc_conf');
    my $req     = Apache2::Request->new($r);

    my $sso_sid = Core::VultureUtils::get_cookie( $r->headers_in->{'Cookie'},
        $r->dir_config('VultureProxyCookieName') . '=([^;]*)' )||'';
    my (%session_SSO);
    Core::VultureUtils::session( \%session_SSO, $intf->{sso_timeout},
        $sso_sid, $log, $mc_conf, $intf->{sso_update_access_time} );

    my $sth = $dbh->prepare("SELECT id FROM sql WHERE name=?");
    $sth->execute($options);
    my ($sql_id) = $sth->fetchrow_array();
    my $user = $req->param('vulture_login');
    my $oldp = $req->param('vulture_password');
    my $newp1 = $req->param('vulture_newpass1');
    my $newp2 = $req->param('vulture_newpass2');

    my $lost 	= $req->param('lost');
    my $appname = $req->param('appname');

    my $success = 0;
    if ($user and $lost and $appname)
    {
	$log->debug("Password lost for user " . $user);
	#Get lostContact from config
	my $config = $r->pnotes('config');
	my $lost_contact = $config->get_key('email_'.$appname)||'';
	unless ($lost_contact) {
		$log->debug("Unable to notify contact: Check Configuration !");
	}
	else {
		$log->debug("Sending an email to " . $lost_contact);

		my $body 	= $config->get_key('passwordlost_email_body_'.$appname) || "User = $user";
		my $subject 	= $config->get_key('passwordlost_email_subject_'.$appname) || "A user needs a new password for $appname";
		my $emailfrom	= $config->get_key('email_from') || 'vulture@no-reply.com';

		my $message = Email::MIME->create(
		  header_str => [
		    From    => $emailfrom,
		    To      => $lost_contact,
		    Subject => $subject,
		  ],
		  attributes => {
		    encoding => 'quoted-printable',
		    charset  => 'ISO-8859-1',
		  },
		  body_str => $body,
		);

		# send the message
		sendmail($message);

		$success=1;
	}

	

    }
    elsif (not ($user and $oldp and $newp1 and ( $newp1 eq $newp2)))
    {
        $log->debug("change pass: wrong arguments");
    }   
    else{
        my $ret = Auth::Auth_SQL::changePassword( 
            $r, $log,$dbh,$sql_id,$user, $oldp , $newp1);
        if ($ret){
            $log->debug("change pass: ok");
            $success = 1;
        }
        else{
            $log->debug("change pass: failure");
        }
    }
    $r->pnotes( 'response_content_type' => 'application/xml' );
    $r->pnotes( 'response_content' => "{\"success\":$success}");
    return Apache2::Const::OK;
}
1;
