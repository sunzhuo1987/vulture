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
use Core::VultureUtils qw(&encrypt &decrypt);

sub checkAuth {
    my ( $package_name, $r, $log, $dbh, $app, $user, 
        $password, $id_method,$session_sso, $class, $csrf_ok ) = @_;

    # get logical auth type
    my $query = 'SELECT name,op,login_auth_id FROM logic WHERE id=?';
    my $sth = $dbh->prepare($query);
    $sth->execute($id_method);
    my $ref = $sth->fetchrow_hashref;
    $sth->finish();
    my $name = $ref->{name};
    my $operator = $ref->{op};
    my $login_id = $ref->{login_auth_id};
    
    # get child methods
    $query = ("SELECT auth.name, auth.auth_type, auth.id_method, auth.id"
        ." FROM auth JOIN logic_auths"
        ." ON auth.id=logic_auths.auth_id"
        ." WHERE logic_auths.logic_id = ? ");
    my @todo_auths=@{$dbh->selectall_arrayref( $query, undef,$id_method)};
    $sth->finish();

    # Auth we are already logged in:
    my $lusr = undef;
    my $lpwd = undef;
    my $fail_login = 0;
    my ($and_login, $and_pwd) = (undef,undef);

    $log->debug("########## Auth_LOGIC ($name, $operator, $login_id) ##########");

    foreach my $todo (@todo_auths) {
        my ($name,$type,$meth, $auth_id) = @$todo;
        $log->debug("LOGIC (auth): $name, $type, $meth");        
        $lusr = $lpwd = undef;

        my $akey = "auth_infos_$auth_id";
        # We are not already logged with this method:
        if (defined $session_sso->{$akey}){
            my $ainfo = $session_sso->{$akey};
            $lusr = $ainfo->{login};
            $lpwd = Core::VultureUtils::decrypt($r,$ainfo->{pwd});
            $log->debug("LOGIC : $user already logged in $name as '$lusr'");
        }
        else{
            # Try to authenticate ...
            $log->debug("LOGIC : try to authenticate '$user' to $name");
            my $module_name = "Auth::Auth_" . uc($type);
            $log->debug("Load $module_name");
            Core::VultureUtils::load_module($module_name,'checkAuth');
            if ( $module_name->checkAuth(
                $r, $log, $dbh, $app, 
                $user, $password, $meth, $session_sso, $class, $csrf_ok
                ) == Apache2::Const::OK
            ){
        
		#Don't do that because it overrides auth_messages like "need change pass..."
	        #$r->pnotes('auth_message' => 'PENDING_LOGIN');
                $user = $r->pnotes('username');
                $log->debug("LOGIC : save '$user' in '$akey'");
                $session_sso->{$akey} = { login => $user, pwd => Core::VultureUtils::encrypt($r,$password)};
                $lusr = $user;
                $lpwd = $password;
            }
        }
        # User is logged in this method:
        if (defined $lusr and $lusr){
            $log->debug("LOGIC : $lusr finally logged in $name");
            # OR 
            if ($operator eq 'OR'){
                # Alright, that's enought for a 'OR' 
                $r->pnotes('username' => "$lusr");
                $r->pnotes('password' => "$lpwd");
                return Apache2::Const::OK;
            }
            # AND
            elsif ($auth_id == $login_id){
                $and_login = $lusr;
                $and_pwd = $lpwd;
            }
        }
        else {
            $log->debug("LOGIC : $user finally failed to authenticate to $name");
            # 'AND' won't be satisfied this time..
            $fail_login = 1;
        }
    }
    if ($fail_login == 1){
        $log->debug("LOGIC : AND wasn't satisfied..");
        $r->pnotes('username' => undef);
        return Apache2::Const::FORBIDDEN;
    }
    # 'AND' auth succeded 
    if (not defined $and_login){
        $log->error("Something went wrong in AND auth, no login found.");
        return Apache2::Const::FORBIDDEN;
    }
    $log->debug("LOGIC : AND succeeded");
    $r->pnotes('username' => "$and_login");
    $r->pnotes('password' => "$and_pwd");
    return Apache2::Const::OK;
}
1;
