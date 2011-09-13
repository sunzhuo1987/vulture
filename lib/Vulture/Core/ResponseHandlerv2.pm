#file:Core/ResponseHandlerv2.pm
#---------------------------------
package Core::ResponseHandlerv2;

use Apache2::Access ();
use Apache2::Reload;
use Apache2::RequestUtil ();
use Apache2::Log;

use DBI;

use Apache2::Const -compile => qw(OK DECLINED REDIRECT HTTP_UNAUTHORIZED);

use Core::VultureUtils qw(&session);

use Apache::SSLLookup;

use Module::Load;

sub handler {
  	my $r = Apache::SSLLookup->new(shift);

	my $log = $r->pnotes('log');
	
	#Getting data from pnotes
	my $app = $r->pnotes('app');
	
	my $dbh = $r->pnotes('dbh');
	my $user = $r->pnotes('username');

	#$user may not be set if Authentication is done via APache (ex: mod_auth_kerb)
	$user = $r->user unless ($user);
	my $password = $r->pnotes('password');

	my (%session_app);
	session(\%session_app, $app->{timeout}, $r->pnotes('id_session_app'));
	my (%session_SSO);
	session(\%session_SSO, $app->{timeout}, $r->pnotes('id_session_SSO'));

	#Query counter
	#my $query = "UPDATE stats SET value=value+1 WHERE var='responsehandler_counter'";
	#$log->debug($query);
	#$dbh->do($query) or $log->error($dbh->errstr);

	$log->debug("########## ResponseHandlerv2 ##########");
       	    
	#Bypass everything to display custom message (ex : custom auth)
	if($r->pnotes('response_content') or $r->pnotes('response_headers') or $r->pnotes('response_content_type')){
	    $log->debug("Bypass ResponseHandler because we have a response to display");
		if($r->pnotes('response_headers')){
			@headers = split /\n/, $r->pnotes('response_headers');
			foreach my $header (@headers){
				if($header =~ /^([^:]+):\s+?(.*)$/){
					$r->err_headers_out->set($1 => $2);
				}
			}
		}
		$r->print($r->pnotes('response_content')) if defined $r->pnotes('response_content_type');
		$r->content_type($r->pnotes('response_content_type')) if defined $r->pnotes('response_content_type');
		return Apache2::Const::OK;
	}

	#SSO Forwarding
	if(exists $session_app{SSO_Forwarding}){
		if(defined $session_app{SSO_Forwarding}){
			my $module_name = "SSO::SSO_".uc($session_app{SSO_Forwarding});

			load $module_name;
			
			#Get return
			$ret = $module_name->forward($r, $log, $dbh, $app, $user, $password);
		}
		delete $session_app{SSO_Forwarding};
		$session_app{SSO_Forwarding} = $r->pnotes('SSO_Forwarding') if defined $r->pnotes('SSO_Forwarding');

		return Apache2::Const::OK;
	}
	
	#If user is logged, then redirect
	if($user){

		#SSO Forwarding once
		if(not defined $session_app{SSO_Forwarding} and $app->{sso_forward}){
			#If results are the same, it means user has already complete the SSO Learning phase
			my $query = "SELECT count(*) FROM post, sso, app WHERE post.sso_id = sso.id AND sso.id = app.sso_forward_id AND app.id=? AND field_type != 'autologon_password' AND field_type != 'autologon_user' AND field_type != 'hidden'";
			my $query2 = "SELECT count(*) FROM profile WHERE app_id = ? AND user = ?";
			my $result1 = $dbh->selectrow_array($query, undef, $app->{id});
			my $result2 = $dbh->selectrow_array($query2, undef, $app->{id}, $user);

            my $query_type = "SELECT sso.type FROM sso, app WHERE app.id = ? AND sso.id = app.sso_forward_id";
			my $type = $dbh->selectrow_array($query_type, undef, $app->{id});

		#Learning ok or no need of learning
            if ($result1 == 0 or $type eq 'sso_forward_htaccess' or $result2 == 1){
                $log->debug("Getting pass for SSO Forward Forward");
                $session_app{SSO_Forwarding} = 'FORWARD';

            #Learning was not done yet
            } elsif ($result2 == 0) {
                $log->debug("Getting pass for SSO Learning");
                $session_app{SSO_Forwarding} = 'LEARNING';
            } else {
                $log->debug("Getting pass for SSO : nothing to forward or to learn");
            }
		}
        #Display portal instead of redirect user
	    if($app->{display_portal}){
            $log->debug("Display portal with all applications");
		    #Getting all app info
            my $portal = display_portal($r,$log, $dbh);
            $log->debug($portal);
		    $r->content_type('text/html');
		    $r->print($portal);
		    return Apache2::Const::OK;
		    
        } else {
		#Redirect user
		    $r->status(200);

		    my $url = $r->is_https ? 'https://' : 'http://';
		    $url .= $app->{name}.':'.$app->{port}.$session_app{url_to_redirect};
		    $r->err_headers_out->set('Location' => $url);
		    $log->debug('Redirecting to '.$url);

		    return Apache2::Const::REDIRECT;
        }
    
    #No user set before. Need to display Vulture auth
	} else {
        #Display Vulture auth
        if($app and !$app->{'auth_basic'} and not $r->pnotes('static')) {
	        $log->debug("Display auth form");
	        $r->content_type('text/html');
	        $r->print(display_auth_form($r, $log, $dbh, $app));
	        return Apache2::Const::OK;
        }
	    $log->debug("Serving static file");
    }
	return Apache2::Const::DECLINED;
}

sub display_auth_form {
	my ($r, $log, $dbh, $app) = @_;
	my $raw = $r->unparsed_uri;
	my $uri = $r->unparsed_uri;
	my $message = $r->pnotes("auth_message");    
    my $translated_message;
	if($r->unparsed_uri =~ /vulture_app=([^;]*)/){
		$uri = $1;
	}

    #Error message to translate / Form
    if($r->headers_in->{'Accept-Language'}){
        #Splitting Accept-Language headers
        # Prepare the list of client-acceptable languages
        my @languages = ();
        foreach my $tag (split(/,/, $r->headers_in->{'Accept-Language'})) {
            my ($language, $quality) = split(/\;/, $tag);
            $quality =~ s/^q=//i if $quality;
            $quality = 1 unless $quality;
            next if $quality <= 0;
            # We want to force the wildcard to be last
            $quality = 0 if ($language eq '*');
            # Pushing lowercase language here saves processing later
            push(@languages, { quality => $quality,
            language => $language,
            lclanguage => lc($language) });
        }
        @languages = sort { $b->{quality} <=> $a->{quality} } @languages;

        my $currentLanguage;

        foreach my $tag (@languages){
        
            #Querying data for language accepted by the server
            my $query = "SELECT count(*) FROM style_translation WHERE country = '".$tag->{lclanguage}."'";
            if ($tag->{lclanguage} =~ /^([^-]+)-([^-]+)$/){
                $query .= " OR country = '".$1."' OR country = '".$2."'";
            }
            $log->debug($query);
            if ($dbh->selectrow_array($query)){
                $currentLanguage = $tag->{lclanguage};
                last;
            }
        }
        my $language_query = "country = '".$currentLanguage."'";
        if ($currentLanguage =~ /^([^-]+)-([^-]+)$/){
            $language_query .= " OR country = '".$1."' OR country = '".$2."'";
        }
        
        #Message translation
        my $message_query = "message = 'USER' OR message = 'PASSWORD'";
        $message_query .= " OR message = '".$message."'" if defined $message;

        my $query = "SELECT message, translation FROM style_translation WHERE (".$message_query.") AND (".$language_query.")";        
        $log->debug($query);

        $translated_messages = $dbh->selectall_hashref($query,'message');
    }

    my %translations = %$translated_messages;
    my $html = '<html><head><meta http-equiv="Content-Type" content="text/html; charset=utf-8"><title>Vulture auth</title></head><body>';
    
    #
    # ONLY FOR SQLITE3
    #

    #Querying database for style
    my $intf_id = $r->dir_config('VultureID');
	my $query = "SELECT CASE WHEN app.style_id NOT NULL THEN app.style_id WHEN intf.style_id NOT NULL THEN intf.style_id ELSE '' END AS 'id_style', style_style.name, style_css.value AS css, style_image.image AS image, style_tpl.value AS tpl FROM app,intf, style_tpl_mapping, style_tpl LEFT JOIN style_style ON style_style.id = id_style LEFT JOIN style_css ON style_css.id = style_style.css_id LEFT JOIN style_image ON style_image.id = style_style.image_id WHERE app.id= ".$app->{id}." AND intf.id = ".$intf_id." AND style_tpl_mapping.style_id = id_style AND style_tpl.id = style_tpl_mapping.tpl_id AND style_tpl.type = 'LOGIN'";
    $log->debug($query);
    $sth = $dbh->prepare($query);
	$sth->execute;
	my $ref = $sth->fetchrow_hashref;
	$sth->finish();
	
    #Including css
    if (defined $ref->{css}){
        $html .= "<style type=\"text/css\">".$ref->{css}."</style>";
    } else {
        $html .= <<BAR
    <STYLE type="text/css">

body,th,td,p,div,span,a,ul,ol,dl,li,select,input,textarea,blockquote{text-align: center;font-size:11px;}
table { margin : 10px auto auto auto; }

input {
         border-bottom: solid 1px #cccccc;
         border-right: solid 1px #cccccc;
         margin: 5px;
         padding: 2px;
}

#custom {
          width: 502px;
          height: 217px;
          background-repeat: no-repeat;
          background-image: url('/static/img/logo.jpg');
}

</STYLE>
BAR
;
    }
    
    $form = <<FOO
<div id="form_vulture">
<form method="POST" name="auth_form" action="$raw">
<input type=hidden name=vulture_app value="$uri">
<table>
<tr class="row"><td class="input">$translations{'USER'}{'translation'}</td><td><input type="text" name="vulture_login"></td></tr>
<tr class="row"><td class="input">$translations{'PASSWORD'}{'translation'}</td><td><input type="password" autocomplete="off" name="vulture_password"></td></tr>
<tr class="row"><td></td><td align="right"><input type="submit"></td></tr>
</table>
</form>
</div>
FOO
;

    #Parsing template if exists
    if(defined $ref->{tpl}){
        $html .= join "",map {
            my ($directive) = $_ =~ /__(.+)__/s;
            if ($directive){
                if ($directive eq "IMAGE"){
                    $_ = "<img id=\"logo\" src=\"/static/".$ref->{image}."\" />";
                } elsif ($directive eq "ERRORS"){
                    if ($message and defined $translations{$message} and defined $translations{$message}{'translation'}){
                        $_ = $translations{$message}{'translation'};
                    }
                } elsif ($directive eq "FORM"){
                    $_ = $form
                } else {
                }
            } else {
                $_ = $_;        
            }
        } split (/(__.*?__)/s, $ref->{tpl});
    
    #Template was undefined
    } else {
        $html .= "<img id=\"logo\" src=\"/static/img/vulture.png\"";
        $html .= "<h2><font color=\"red\">$translations{$message}{'translation'}</font></h2>" if defined $translations{$message}{'translation'};
        $html .= $form ;
    }
    $html .= '</body></html>';
	return $html;
}

sub display_portal {
	my ($r,$log,$dbh) = @_;

    my $intf_id = $r->dir_config('VultureID');
	my $query = "SELECT app.name FROM app WHERE app.intf_id='".$intf_id."'";
    $log->debug($query);

    my $all_apps = $dbh->selectall_arrayref($query);
	my $html;
	foreach my $app (@$all_apps) {
        $html .= "<a href='http://".@$app[0]."'><h3>Application ".@$app[0]."</h3></a>";
	}
	return $html;
}

1;
