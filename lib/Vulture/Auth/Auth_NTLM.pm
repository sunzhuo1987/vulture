#file:Auth/Auth_NTLM.pm
#---------------------------------
#!/usr/bin/perl
package Auth::Auth_NTLM;

use strict;
use warnings;

BEGIN {
    use Exporter ();
    our @ISA = qw(Exporter);
    our @EXPORT_OK = qw(&checkAuth);
}

use Apache2::RequestRec ();
use Apache2::RequestIO ();
use Apache2::Connection ();
use Apache2::Log;
use Apache2::Reload;
use Apache2::Access;
use Authen::Smb;
use Apache2::Access ;
use Apache2::Log ;
use Apache2::RequestUtil ;
use APR::Table ;
use APR::SockAddr ;
use Apache2::Const -compile => qw(HTTP_UNAUTHORIZED HTTP_INTERNAL_SERVER_ERROR DECLINED HTTP_FORBIDDEN OK FORBIDDEN) ;

use strict ;
use vars qw{$cache $VERSION %msgflags1 %msgflags2 %msgflags3 %invflags1 %invflags2 %invflags3 $addr $port $debug} ;
$cache = undef ;
use MIME::Base64 () ;
use Socket ;
use mod_perl2 ;

%msgflags1 = ( 0x01 => "NEGOTIATE_UNICODE",
	       0x02 => "NEGOTIATE_OEM",
	       0x04 => "REQUEST_TARGET",
	       0x10 => "NEGOTIATE_SIGN",
	       0x20 => "NEGOTIATE_SEAL",
	       0x80 => "NEGOTAITE_LM_KEY",
	       );

%msgflags2 = ( 0x02 => "NEGOTIATE_NTLM",
	       0x40 => "NEGOTIATE_LOCAL_CALL",
	       0x80 => "NEGOTIATE_ALWAYS_SIGN",
	       );

%msgflags3 = ( 0x01 => "TARGET_TYPE_DOMAIN",
	       0x02 => "TARGET_TYPE_SERVER",
	       );

%invflags1 = ( "NEGOTIATE_UNICODE" => 0x01,
	       "NEGOTIATE_OEM"     => 0x02,
	       "REQUEST_TARGET"    => 0x04,
	       "NEGOTIATE_SIGN"    => 0x10,
	       "NEGOTIATE_SEAL"    => 0x20,
	       "NEGOTIATE_LM_KEY"  => 0x80,
	       );

%invflags2 = ( "NEGOTIATE_NTLM"        => 0x02,
	       "NEGOTIATE_LOCAL_CALL"  => 0x40,
	       "NEGOTIATE_ALWAYS_SIGN" => 0x80,
	       );

%invflags3 = ( "TARGET_TYPE_DOMAIN" => 0x01,
	       "TARGET_TYPE_SERVER" => 0x02,
	       );

sub substr_unicode 
{
    my ($data, $off,  $len) = @_ ;
    
    my $i = 0 ; 
    my $end = $off + $len ;
    my $result = '' ;
    for ($i = $off ; $i < $end ; $i += 2)
    {# for now we simply ignore high order byte
	    $result .=  substr ($data, $i,  1) ;
    }

    return $result ;
}


sub get_msg1
{
    my ($r, $log, $data, $defaultdomain) = @_ ;
    
    my ($protocol, $type, $zero, $flags1, $flags2, $zero2, $dom_len, $x1, $dom_off, $x2, $host_len, $x3, $host_off, $x4) = unpack ('Z8Ca3CCa2vvvvvvvv', $data) ;
    my $host   = $host_off?substr ($data, $host_off, $host_len):'' ;
    my $domain = $dom_off?substr ($data, $dom_off,  $dom_len):'' ;

    $domain = $dom_len?$domain:$defaultdomain ;
    $host   = $host_len?$host:'' ;
    my $accept_unicode = $flags1 & 0x01;

    $log->debug ("Auth_NTLM: get_msg1: domain == $domain host == $host accept_unicode == $accept_unicode");

    if ($debug)
    {
        my @flag1str;
        foreach my $i ( sort keys %msgflags1 ) 
        {
            push @flag1str, $msgflags1{ $i } if $flags1 & $i;
        }
        my $flag1str = join( ",", @flag1str );

        my @flag2str;
        foreach my $i ( sort keys %msgflags2 ) 
        {
            push @flag2str, $msgflags2{ $i } if $flags2 & $i;
        }
        my $flag2str = join( ",", @flag2str );

        $log->debug( "[$$] AuthenNTLM: protocol=$protocol, type=$type, flags1=$flags1($flag1str), " 
        . "flags2=$flags2($flag2str), domain length=$dom_len, domain offset=$dom_off, "
        . "host length=$host_len, host offset=$host_off, host=$host, domain=$domain\n") ;
    }

    return ($type,$accept_unicode) ;
}


sub set_msg2
{
    my ($r, $log, $nonce, $accept_unicode) = @_ ;

    my $charencoding = $accept_unicode ? $invflags1{ NEGOTIATE_UNICODE } : $invflags1{ NEGOTIATE_OEM };
    my $flags2 = $invflags2{ NEGOTIATE_ALWAYS_SIGN } | $invflags2{ NEGOTIATE_NTLM };
    my $data = pack ('Z8Ca7vvCCa2a8a8', 'NTLMSSP', 2, '', 40, 0, $charencoding,  $flags2, '', $nonce, '') ;
    my $header = 'NTLM '. MIME::Base64::encode($data, '') ;

    $log -> debug ("Auth_NTLM: set_msg2 charencoding = $charencoding flags2 = $flags2 nonce=$nonce Send header: $header:'NTLM' ...");

    return $header;
}


sub get_msg3
{
    my ($r, $log, $data, $defaultdomain) = @_ ;

    my ($protocol, $type, $zero, 
        $lm_len,  $l1, $lm_off,
        $nt_len,   $l3, $nt_off,
        $dom_len, $x1, $dom_off,
        $user_len, $x3, $user_off,
        $host_len, $x5, $host_off,
        $msg_len
        ) = unpack ('Z8Ca3vvVvvVvvVvvVvvVv', $data) ;
    
	my $lm     = $lm_off  ? substr ($data, $lm_off,   $lm_len):'' ;
	my $nt     = $nt_off  ? substr ($data, $nt_off,   $nt_len):'' ;
	my $user   = $user_off ? substr_unicode ($data, $user_off, $user_len) :'' ;
	my $host   = $host_off ? substr_unicode ($data, $host_off, $host_len) :'' ;
	my $domain = $dom_off ? substr_unicode ($data, $dom_off,  $dom_len) :'' ;

	my $userdomain = $dom_len?$domain:$defaultdomain ;
	my $usernthash = $nt_len ? $nt : $lm;

	$log->debug ("Auth_NTLM: get_msg3 protocol=$protocol, type=$type, user=$user, host=$host, domain=$userdomain, msg_len=$msg_len, user_nthash=$usernthash");

	return ($type,$user,$usernthash,$userdomain) ;
}



sub checkAuth{
	my ($package_name, $r, $class, $log, $dbh, $app, $user, $password, $id_method) = @_;	

    $log->debug("########## Auth_NTLM ##########");

    my $table;
    my $self ;
    my $conn = $r -> connection ;
    my $connhdr = $r -> headers_in -> {'Connection'} ;

    $table = $conn->notes();
    if (ref ($cache) ne $class || $$conn != $cache->{connectionid})
    {
        $conn->notes($table);
        $self = {connectionid => $$conn } ;
        bless $self, $class ;
        $cache = $self ;
        $log->debug("Auth_NTLM: New connexion");
    }
    else
    {
        $self = $cache ;
        $log->debug("Auth_NTLM: Reusing connexion");
    }

    my $query = "SELECT * FROM ntlm WHERE id= ?";
    my $sth = $dbh->prepare($query);
    $log->debug($query);
    $sth->execute($id_method);
    my $ref = $sth->fetchrow_hashref;
    $sth->finish();

    my $domain      = $ref->{'domain'};
    my $pdc         = $ref->{'primary_dc'};
    my $bdc         = $ref->{'secondary_dc'};
    my $protocol    = $ref->{'protocol'};
	my $t;

    my $auth_line 	=  $r->headers_in->{'Authorization'} or {} ;
    my $data	= undef;
    if ($auth_line =~ /^NTLM\s+(.*?)$/i) {
        $data 	= MIME::Base64::decode($1) ;
    }

	if (!$data)
	{
        $log->debug('Bad/Missing NTLM Authorization Header for ' . $r->uri);
        my $hdr = $r -> err_headers_out ;
        $hdr -> add ('WWW-Authenticate', 'NTLM') ;
        return Apache2::Const::HTTP_UNAUTHORIZED ;
	}

	($protocol, $t) = unpack ('Z8C', $data) ;
	my ($type, $accept_unicode, $username, $usernthash, $userdomain) = undef;
	if ($t == 1) {
        ($type,$accept_unicode) = get_msg1 ($r, $log, $data, $domain);
	}
	elsif ($t == 3) {
        ($type,$username,$usernthash,$userdomain) = get_msg3 ($r, $log, $data,$domain);
	}

    if ($type == 1)
    {
        $log->debug('Auth_NTLM: handler type == 1');
        my $nonce = $self -> get_nonce ($r,$log,$pdc,$bdc,$domain) ;
        if (!$nonce)
        {
	    $self->{lock} = undef;
            $log->debug('Cannot get nonce');
            return Apache2::Const::FORBIDDEN ;
        }

        $log->debug('Auth_NTLM: verify handle = 1 smbhandle == $self->{smbhandle} nonce == $nonce ');
        $log->debug('Auth_NTLM: Sending type 2 message ');
        my $header1 = set_msg2 ($r, $log, $nonce, $accept_unicode) ;
        my $hdr = $r -> err_headers_out ;
        $hdr -> add ('WWW-Authenticate', $header1);
        return Apache2::Const::HTTP_UNAUTHORIZED ;
    }
    elsif ($type == 3)
    {
        $log->debug('Auth_NTLM: handler type == 3');
        my $nonce = $self -> get_nonce ($r,$log,$pdc,$bdc,$domain) ;

        $log->debug("Auth_NTLM: Authen::Smb::Valid_User_Auth --> Call with smbhandle=$self->{smbhandle}, username=$username, nt_hash=$usernthash, 1, domain=$userdomain");
        my $rc = Authen::Smb::Valid_User_Auth ($self->{smbhandle}, $username, $usernthash, 1, $userdomain) ;
        $log->debug('Auth_NTLM: Authen::Smb::Valid_User_Auth --> Ok !');

        my $errno  = Authen::Smb::SMBlib_errno ;
        my $smberr = Authen::Smb::SMBlib_SMB_Error ;

        $log->debug('Auth_NTLM: Authen::Smb::Valid_User_Disconnect --> Call');
        Authen::Smb::Valid_User_Disconnect ($self->{smbhandle}) if ($self->{smbhandle}) ;
        $log->debug('Auth_NTLM: Authen::Smb::Valid_User_Disconnect --> Ok !');
	$self->{lock} = undef;

        if ($rc == &Authen::Smb::NTV_LOGON_ERROR)
        {
            $log->debug("Auth_NTLM: Wrong password/user (rc=$rc/$errno/$smberr): $userdomain\\$username for " . $r -> uri) ;
            my $hdr = $r -> err_headers_out ;
            $hdr -> add ('WWW-Authenticate', 'NTLM');
            return Apache2::Const::HTTP_UNAUTHORIZED ;
        }
        if ($rc)
        {
            $log->debug("Auth_NTLM: SMB Server error $rc/$errno/$smberr for " . $r -> uri) ;
            my $hdr = $r -> err_headers_out ;
            $hdr -> add ('WWW-Authenticate', 'NTLM');
            return Apache2::Const::HTTP_UNAUTHORIZED ;
        }
    }
    else
    {
	$self->{lock} = undef;
        $log->debug('Auth_NTLM: Bad NTLM Authorization Header type $type for '.$r->uri) ;
        return Apache2::Const::HTTP_UNAUTHORIZED ;
    }

    $self->{lock} = undef;
    $r->user ($username);
    return Apache2::Const::OK ;
}

package Auth::Auth_NTLM::Lock ;

use IPC::SysV qw(IPC_CREAT S_IRWXU SEM_UNDO);
use IPC::Semaphore;


sub lock
   {
   my $class = shift ;
   my $key   = shift ;
   my $debug   = shift ;
   my $log = @_[1];

   my $self = bless {debug => $debug}, $class ;
   $self->{sem} = new IPC::Semaphore($key, 1,
           IPC_CREAT | S_IRWXU) or die "Cannot create semaphore with key $key ($!)" ;

   $self->{sem}->op(0, 0, SEM_UNDO,
                    0, 1, SEM_UNDO);
   $log->debug("[$$] AuthenNTLM: enter lock\n")  ;

   return $self ;
   }

sub DESTROY
    {
    my $self    = shift;
    my $log = @_[1];

    $self->{sem}->op(0, -1, SEM_UNDO);
    $log->debug( "[$$] AuthenNTLM: leave lock\n")  ;
    }



1;

