#file:Auth/Auth_SQL.pm
#---------------------------------
#!/usr/bin/perl
package Auth::Auth_SQL;

use strict;
use warnings;

BEGIN {
    use Exporter ();
    our @ISA       = qw(Exporter);
    our @EXPORT_OK = qw(&checkAuth &changePassword);
}

use Apache2::RequestRec ();
use Apache2::RequestIO  ();
use Apache2::Connection ();
use Apache2::Log;
use Apache2::Reload;

use Digest::MD5 qw(md5_hex md5_base64);
use Digest::SHA1 qw(sha1_hex sha1_base64);
use DBI;

use Apache2::Const -compile => qw(OK FORBIDDEN);
use Core::VultureUtils qw(&get_DB_object);

sub digest_pwd {
    my ($password, $algo) = @_;
    if ( $algo eq "plain" ) {
        return $password;
    }
    elsif ( $algo eq "sha1" ) {
        return Digest::SHA1::sha1_hex($password);
    }
    elsif ($algo eq "md5" ) {
        return Digest::MD5::md5_hex($password);
    }
}
    
sub changePassword { 
    my ($r, $log,$dbh,$id_method,$user, $old_pass, $new_pass) = @_; 
    my ( $new_dbh, $ref ) = get_DB_object( $log, $dbh, $id_method );
    if ( not ($new_dbh and $ref)){
        return 0;
    }
    my $sth = $new_dbh->prepare(
            "UPDATE $ref->{table} SET $ref->{pass_column}=? "
            . "WHERE $ref->{user_column}=? AND $ref->{pass_column}=?");
    return ($sth->execute(
        digest_pwd($new_pass, $ref->{pass_algo}),
        $user,
        digest_pwd($old_pass, $ref->{pass_algo})) ne  "0E0" );
}
    
sub checkAuth {
    my ( $package_name, $r, $log, $dbh, $app, $user, $password, $id_method,
        $session, $class, $csrf_ok ) = @_;

    $log->debug("########## Auth_SQL ##########");
    return Apache2::Const::FORBIDDEN unless $csrf_ok and $user ne '';

    my ( $new_dbh, $ref ) = get_DB_object( $log, $dbh, $id_method );
    if ( not ($new_dbh and $ref)){
        return Apache2::Const::FORBIDDEN;
    }
    if ( not $new_dbh ) {
        my $url = ($app and $app->{'secondary_authentification_failure_options'})||'';
        if ( $url ne '' ) {
            $log->debug("error connecting to DB");
            $r->pnotes( 'response_content' => 'Redirecting you' );

            $r->err_headers_out->set( 'Location' => $url );
            $r->status(Apache2::Const::REDIRECT());
        }
        else {
            return Apache2::Const::FORBIDDEN;
        }
    }
    my $ret = Apache2::Const::FORBIDDEN;
    my $query = "SELECT count(*) FROM $ref->{table} "
        . "WHERE $ref->{user_column}=? AND $ref->{pass_column}=?";
    if ( $new_dbh->selectrow_array( $query, undef, 
            $user, digest_pwd($password,$ref->{pass_algo}))){
        $ret = Apache2::Const::OK;
        $log->debug("User is ok for Auth_SQL");
        $r->pnotes('username'=>"$user");
    }
    else{
        $log->debug("User is bad for Auth_SQL");
    }
    $new_dbh->disconnect();
    return $ret;
}
1;
