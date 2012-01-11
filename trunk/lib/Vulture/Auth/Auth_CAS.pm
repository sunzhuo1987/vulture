#file:Auth/Auth_CAS.pm
#---------------------------------
#!/usr/bin/perl
package Auth::Auth_CAS;

use strict;
use warnings;

use Apache2::RequestRec ();
use Apache2::RequestIO ();
use Apache2::Connection ();
use Apache2::Log;
use Apache2::Reload;
use Apache2::Request;

use Apache2::Const -compile => qw(OK FORBIDDEN REDIRECT);

use LWP::UserAgent;

use URI::Escape;

use Core::VultureUtils qw(&session);

sub checkAuth{
	my ($package_name, $r, $class, $log, $dbh, $app, $user, $password, $id_method) = @_;	

	$log->debug("########## Auth_CAS ##########");

    #Get CAS infos
	my $query = "SELECT * FROM cas WHERE id= ?";
    my $sth = $dbh->prepare($query);
    $log->debug($query);
    $sth->execute($id_method);
    my $ref = $sth->fetchrow_hashref;
    $sth->finish();

    #Ticket is into session $session_app{url_to_redirect}
    my (%session_app);
    my $ticket;
	Core::VultureUtils::session(\%session_app, $app->{timeout}, $r->pnotes('id_session_app'), $log, $app->{update_access_time});
    if($session_app{url_to_redirect} =~ s/[?&]ticket=(\S+)\s*//g){
        $ticket = $1;
    }
    
    #Build service
    $r = Apache::SSLLookup->new($r);
    my $incoming_uri = $app->{name};
    if ($incoming_uri !~ /^(http|https):\/\/(.*)/ ) {
        #Fake scheme for making APR::URI parse
        $incoming_uri = 'http://'.$incoming_uri;
    }
    my $service = APR::URI->parse($r->pool, $incoming_uri);
    $service->scheme('http');
    $service->scheme('https') if $r->is_https;
    $service->port($r->get_server_port());
    
    #Check required params (i.e. host and port)
    if(defined $ref->{url_validate} and defined $ticket){
        
        #Build serviceValidate URL
        my $url = $ref->{url_validate}.'?serviceValidate='.uri_escape($service->unparse).'&ticket='.uri_escape($ticket);
        $log->debug("Querying url".$url);
        
        #Get answer
        my $ua = LWP::UserAgent->new;
        
        #Setting proxy if needed
        if ($app->{remote_proxy} ne ''){
            $ua->proxy(['http', 'https'], $app->{remote_proxy});
        }
        
        my $response = $ua->get($url);
        
        $log->debug($response->decoded_content);
        
        #Check answer
        if($response->decoded_content =~ /<cas:user>(.+)<\/cas:user>/){
            #Get user from CAS
            $r->pnotes('username' => $1);
            $r->user($1);
            return Apache2::Const::OK;
        } 
    }
    
    #Redirect user to CAS server
    $log->debug('User doesn\'t have service ticket / or invalid. Redirect him to CAS Server');
    $r->pnotes('response_content' => 'Redirecting you to CAS Server');
    $r->err_headers_out->set('Location' => $ref->{url_login}.'?service='.uri_escape($service->unparse));
    $r->status(Apache2::Const::REDIRECT);
    return Apache2::Const::FORBIDDEN;
}
1;
