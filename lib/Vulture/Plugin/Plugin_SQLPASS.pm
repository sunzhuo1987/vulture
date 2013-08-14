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
use Auth::Auth_SQL qw(&changePassword);

sub plugin {
    my ( $package_name, $r, $log, $dbh, $intf, $app, $options ) = @_;

    $log->debug("########## Plugin_SQLPASS ##########");
    my $mc_conf = $r->pnotes('mc_conf');
    my $req     = Apache2::Request->new($r);

    my $user = $req->param('user');
    my $oldp = $req->param('old_pwd');
    my $newp1 = $req->param('new_pwd1');
    my $newp2 = $req->param('new_pwd2');

    my $sql_id = $options;
    $log->debug("sql id : $sql_id");
    
    if (not ($newp1 and ( $newp1 eq $newp2))){
        $log->debug("bad new pass!");
        return Apache2::Const::OK;
    }
    my $ret = Auth::Auth_SQL::changePassword( 
        $r, $log,$dbh,$sql_id,$user, $oldp , $newp1);
    if (not $ret){
        $log->debug("change pass : no success");
    }
    else{
        $log->debug("change pass : no problemo");
    }

    $log->debug("SQLPASS: im leaving..");
    return Apache2::Const::FORBIDDEN;
}
1;
