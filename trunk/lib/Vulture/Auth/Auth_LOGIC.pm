#file:Auth/Auth_LOGIC.pm
#---------------------------------
#!/usr/bin/perl
package Auth::Auth_LOGIC;

use strict;
use warnings;

BEGIN {
    use Exporter ();
    our @ISA       = qw(Exporter);
    our @EXPORT_OK = qw(&checkAuth);
}

use Apache2::Reload;
use Apache2::Log;

use Apache2::Const -compile => qw(OK FORBIDDEN);

sub checkAuth {
    my ( $package_name, $r, $log, $dbh, $app, $user, 
        $password, $id_method,$session_sso ) = @_;
    if (not defined $session_sso->{auth_methods}){
        $session_sso->{auth_methods} = ();
    }
    # get logical auth type
    my $query = 'SELECT operator FROM logic WHERE id_method=?';
    my $sth = $dbh->prepare($query);
    $sth->execute($id_method);
    my $ref = $sth->fetchrow_hashref;
    $sth->finish();
    my $operator = $ref->{op};
    
    # get child methods
    $query = ("SELECT auth.name, auth.auth_type, auth.id_method"
        ." FROM auth, logic_auths"
        ." WHERE auth.id=logic_auths.auth_id AND logic_auths.logic_id = ? ");
    my @auths=@{$dbh->selectall_arrayref( $query, undef,$id_method)};
    $sth->finish();
    $log->debug("########## Auth_LOGIC ##########");
    foreach my $row (@$auths) {
        my ($name,$type,$meth) = @$row;
        my $module_name = "Auth::Auth_" . uc( $type );
#        $log->debug("Load $module_name");
#        load_module($module_name,'checkAuth');
#        $ret = $module_name->checkAuth( $r, $log, $dbh, $app, 
#            $user, $password, $meth, $session, $class);
#        return $ret if $ret == Apache2::Const::OK;
#        return $ret if $ret == Apache2::Const::HTTP_UNAUTHORIZED;
    }  
}
1;
