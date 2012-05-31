#file:Core/ActionManager.pm
#-------------------------
#!/usr/bin/perl
package Core::ActionManager;

use strict;
use warnings;

use Core::VultureUtils qw(&get_translations &get_style);
use Apache2::Const -compile => qw(OK HTTP_UNAUTHORIZED);

BEGIN {
    use Exporter ();
    our @ISA = qw(Exporter);
    our @EXPORT_OK = qw(&handle_action);
}

sub handle_action {
    my ($r, $log, $dbh, $intf, $app, $type, $title, $fields) = @_;
    my ($package, $filename, $line) = caller;
    my ($query, $sth, $action, $options, $html);
    
    $log->debug($type);
    my @messages = qw/AUTH_SERVER_FAILURE ACCOUNT_LOCKED LOGIN_FAILED NEED_CHANGE_PASS ACL_FAILED/;
    #If type is in messages array

    if(grep $_ eq uc($type), @messages ){
        $action = defined $app->{'actions'} ? $app->{'actions'}->{lc($type).'_action'} : $intf->{'actions'}->{lc($type).'_action'};
        $options = defined $app->{'actions'} ? $app->{'actions'}->{lc($type).'_options'} : $intf->{'actions'}->{lc($type).'_options'};
    }
    
    #Handle action to do
    if($action){
        $log->debug($action.' => '.$options);
        
        if($action eq 'template'){
            #Get translations
            my $translations = Core::VultureUtils::get_translations($r, $log, $dbh, $type);
            $html = Core::VultureUtils::get_style($r, $log, $dbh, $app, $type, $title, {}, $translations);
        } elsif($action eq 'message'){
            $html = '<html><head><meta http-equiv="Content-type" content="text/html; charset=utf-8"/></head><body>'.$options.'</body></html>';
        } elsif($action eq 'log'){
            $log->debug('Message : '.$type);
        } elsif($action eq 'redirect'){
            $html = '<html><head><meta http-equiv="Refresh" content="0; url='.$options.'"/></head></html>';
        } elsif($action eq 'script'){
            #Get evaluation of script
            eval $options;
        } else {
            return Apache2::Const::OK;
        }
        
        #Check if we can write smth to output
        eval {
            $r->print($html);
            $r->content_type('text/html');
        };
        
        #We can't. Delegate display to ResponseHandler       
        if($@){
            $r->set_handlers(PerlAccessHandler => undef);
            $r->set_handlers(PerlAuthenHandler => undef);
            $r->set_handlers(PerlAuthzHandler => undef);
            $r->set_handlers(PerlFixupHandler => undef);
            $log->debug($html);
            $r->pnotes('response_content' => $html);
            $r->pnotes('response_content_type' => 'text/html');
            
            if($type eq "ACL_FAILED"){
                $r->custom_response(Apache2::Const::HTTP_UNAUTHORIZED, $html);
            }
        }
        return Apache2::Const::OK;
    }
}
1;
