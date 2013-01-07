#file:Auth/Auth_SQL.pm
#---------------------------------
#!/usr/bin/perl
package Auth::Auth_SQL;

use strict;
use warnings;

BEGIN {
    use Exporter ();
    our @ISA       = qw(Exporter);
    our @EXPORT_OK = qw(&checkAuth);
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

sub checkAuth {
    my ( $package_name, $r, $log, $dbh, $app, $user, $password, $id_method ) =
      @_;

    $log->debug("########## Auth_SQL ##########");

    my ( $new_dbh, $ref ) = get_DB_object( $log, $dbh, $id_method );
    if ( $new_dbh eq "error" ) {
        my $url = $app->{'secondary_authentification_failure_options'};
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
    elsif ( $new_dbh and $ref ) {

        #Password encryption
        if ( $ref->{'pass_algo'} eq "plain" ) {

            #Nothing to do
        }
        elsif ( $ref->{'pass_algo'} eq "sha1" ) {
            $password = Digest::SHA1::sha1_hex($password);
        }
        elsif ( $ref->{'pass_algo'} eq "md5" ) {
            $password = Digest::MD5::md5_hex($password);
        }

        #Checking credentials
        my $query =
            "SELECT count(*) FROM "
          . $ref->{'table'}
          . " WHERE "
          . $ref->{'user_column'}
          . "=? AND "
          . $ref->{'pass_column'} . "=?";
        $log->debug($query);
        if ( $new_dbh->selectrow_array( $query, undef, $user, $password ) ) {
            $log->debug("User is ok for Auth_SQL;");
            $new_dbh->disconnect();
            return Apache2::Const::OK;
        }
        else {
            $log->debug("User is bad for Auth_SQL;");
            $new_dbh->disconnect();
            return Apache2::Const::FORBIDDEN;
        }
    }
    return Apache2::Const::FORBIDDEN;
}
1;
