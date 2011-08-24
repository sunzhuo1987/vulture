#------------------------------------------------------------------------------
# Project  : Reverse Proxy HTML link rewriter
# Name     : ModProxyPerlHtml.pm
# Language : perl 5.8 built for i686-linux
# OS       : linux Slackware 10 kernel 2.4.26
# Authors  : Gilles Darold, gilles@darold.net
# Copyright: Copyright (c) 2005 : Gilles Darold - All rights reserved -
# Description : This mod_perl2 module is a replacement for mod_proxy_html.c
#		with much better URL HTML rewriting.
# Usage    : See documentation in this file with perldoc.
#------------------------------------------------------------------------------
# This program is free software; you can redistribute it and/or modify it under
# the same terms as Perl itself.
#------------------------------------------------------------------------------
package Apache2::ModProxyPerlHtml;
use strict qw(vars);
use warnings;

require mod_perl2;

use Apache2::Connection ();
use Apache2::RequestRec;
use Apache2::RequestUtil;
use APR::Table;
use base qw(Apache2::Filter);
use Apache2::Const -compile => qw(OK DECLINED :conn_keepalive);
use constant BUFF_LEN => 8000;

$Apache2::ModProxyPerlHtml::VERSION = '2.0';

%Apache2::ModProxyPerlHtml::linkElements = (
	'a'       => ['href'],
	'applet'  => ['archive', 'codebase', 'code'],
	'area'    => ['href'],
	'base'    => ['href'],
	'bgsound' => ['src'],
	'blockquote' => ['cite'],
	'body'    => ['background'],
	'del'     => ['cite'],
	'embed'   => ['pluginspage', 'src'],
	'form'    => ['action'],
	'frame'   => ['src', 'longdesc'],
	'iframe'  => ['src', 'longdesc'],
	'ilayer'  => ['background'],
	'img'     => ['src', 'lowsrc', 'longdesc', 'usemap'],
	'input'   => ['src', 'usemap'],
	'ins'     => ['cite'],
	'isindex' => ['action'],
	'head'    => ['profile'],
	'layer'   => ['background', 'src'],
	'link'    => ['href'],
	'object'  => ['classid', 'codebase', 'data', 'archive', 'usemap'],
	'q'       => ['cite'],
	'script'  => ['src', 'for'],
	'table'   => ['background'],
	'td'      => ['background'],
	'th'      => ['background'],
	'tr'      => ['background'],
	'xmp'     => ['href'],
);

sub handler
{
	my $f = shift;

	my $debug = $f->r->dir_config->get('ProxyHTMLVerbose');
	if ($debug =~ /(on|1)/i) {
		$debug = 1;
	} else {
		$debug = 0;
	}

	# Thing we do at the first chunk
	my $content_type = $f->r->content_type() || '';
	unless ($f->ctx) {
		$f->r->headers_out->unset('Content-Length');
		my @pattern = $f->r->dir_config->get('ProxyHTMLURLMap');
		my $ct = $f->ctx;
		$ct->{data} = '';
		foreach my $p (@pattern) {
			push(@{$ct->{pattern}}, $p);
		}
		$f->ctx($ct);
	}
	# Thing we do on all invocations
	my $ctx = $f->ctx;
	while ($f->read(my $buffer, BUFF_LEN)) {
		$ctx->{data} .= $buffer;
		$ctx->{keepalives} = $f->c->keepalives;
		$f->ctx($ctx);
	}
	# Thing we do at end
	if ($f->seen_eos) { 
		# Skip content that should not have links
		if ($content_type =~ /(text\/html|text\/css|application\/x-javascript)/) {
			# Replace links if pattern match
			foreach my $p (@{$ctx->{pattern}}) {
				my ($match, $substitute) = split(/[\s\t]+/, $p);
				&complex_link_replacement(\$ctx->{data}, $match, $substitute);

			}
		}
		$f->ctx($ctx);
		#$f->r->headers_out->set('Content-Length', length($f->ctx->{data}));
		$f->print($f->ctx->{data});
		my $c = $f->c;
		if ($c->keepalive == Apache2::Const::CONN_KEEPALIVE && $ctx->{data} && $c->keepalives > $ctx->{keepalives}) {
			if ($debug) {
				warn "[ModProxyPerlHtml] cleaning context for keep alive request\n";
			}
			$ctx->{data} = '';
			$ctx->{pattern} = ();
			$ctx->{keepalives} = $c->keepalives;
		}
			
	}

	return Apache2::Const::OK;
}

sub complex_link_replacement
{
	my ($data, $pattern, $replacement) = @_;

	my $old_terminator = $/;
	$/ = '';
	my @TODOS = ();
	my $i = 0;
	# Replace standard link into attributes of any element
	foreach my $tag (keys %Apache2::ModProxyPerlHtml::linkElements) {
		next if ($$data !~ /<$tag/i);
		foreach my $attr (@{$Apache2::ModProxyPerlHtml::linkElements{$tag}}) {
			while ($$data =~ s/(<$tag[\t\s]+[^>]*\b$attr=['"]*)$pattern([^'"\s>]+)/NEEDREPLACE_$i$$/i) {
				push(@TODOS, "$1$replacement$2");
				$i++;
			}
		
		}
	}
	# Replace all links in javascript code
	$$data =~ s/([^\\]['"])$pattern([^'"]*['"])/$1$replacement$2/ig;

	# Replace meta refresh URLs
	$$data =~ s/(<meta[\t\s]+[^>]*\bcontent=['"]*.*)URL=$pattern([^'"\s]+)/$1$replacement$2/ig;

	# Replace todos now
	for ($i = 0; $i <= $#TODOS; $i++) {

		$$data =~ s/NEEDREPLACE_$i$$/$TODOS[$i]/i;
	}

	$/ = $old_terminator;

}

1;

__END__

=head1 DESCRIPTION

Apache2::ModProxyPerlHtml is a mod_perl2 replacement of the Apache2
module mod_proxy_html.c use to rewrite HTML links for a reverse proxy.

Apache2::ModProxyPerlHtml is very simple and has better parsing/replacement
of URL than the C code. It also support meta refresh tag rewriting.
 

=head1 AVAIBILITY

You can get the latest version of Apache2::ModProxyPerlHtml from:

	http://www.samse.fr/GPL/ModProxyPerlHtml/

=head1 PREREQUISITES

You must have Apache2 and mod_perl2 installed. No other perl
module are used.

You also need to install the mod_proxy Apache module. See
documentation at http://httpd.apache.org/docs/2.0/mod/mod_proxy.html

=head1 INSTALLATION

	% perl Makefile.PL
	% make && make install

=head1 APACHE CONFIGURATION

Here is the DSO module loading I use:

    LoadModule deflate_module modules/mod_deflate.so
    LoadModule headers_module modules/mod_headers.so
    LoadModule proxy_module modules/mod_proxy.so
    LoadModule proxy_connect_module modules/mod_proxy_connect.so
    LoadModule proxy_ftp_module modules/mod_proxy_ftp.so
    LoadModule proxy_http_module modules/mod_proxy_http.so
    LoadModule ssl_module modules/mod_ssl.so
    LoadModule perl_module  modules/mod_perl.so


Here is the reverse proxy configuration I use :

    ProxyRequests Off
    SSLProxyEngine  On
    ProxyPreserveHost On
    ProxyPass       /webmail/  http://webmail.domain.com/
    ProxyPassReverse /webmail/ http://webmail.domain.com/
    ProxyPass       /webcal/  http://webcal.domain.com/
    ProxyPassReverse /webcal/ http://webcal.domain.com/
    ProxyPass       /intranet/  http://intranet.domain.com/
    ProxyPassReverse /intranet/ http://intranet.domain.com/
    PerlInputFilterHandler Apache2::ModProxyPerlHtml
    PerlOutputFilterHandler Apache2::ModProxyPerlHtml
    SetHandler perl-script
    PerlAddVar ProxyHTMLURLMap "http://webmail.domain.com /webmail"
    PerlAddVar ProxyHTMLURLMap "http://webcal.domain.com /webcal"
    PerlAddVar ProxyHTMLURLMap "http://intranet.samse.fr /intranet"
    PerlSetVar ProxyHTMLVerbose "On"
    LogLevel Info

    # URL rewriting
    RewriteEngine   On
    RewriteLog      "/var/log/apache/rewrite.log"
    RewriteLogLevel 9
    # Add ending '/' if not provided
    RewriteCond     %{REQUEST_URI}  ^/mail$
    RewriteRule     ^/(.*)$ /$1/    [R]
    RewriteCond     %{REQUEST_URI}  ^/planet$
    RewriteRule     ^/(.*)$ /$1/    [R]
    # Add full path to the CGI to bypass the index.html redirect that may fail
    RewriteCond     %{REQUEST_URI}  ^/calendar/$
    RewriteRule     ^/(.*)/$ /$1/cgi-bin/wcal.pl    [R]
    RewriteCond     %{REQUEST_URI}  ^/calendar$
    RewriteRule     ^/(.*)$ /$1/cgi-bin/wcal.pl     [R]

    <Location /webmail/>
    	ProxyPassReverse /
    	PerlAddVar ProxyHTMLURLMap "/ /webmail/"
    	RequestHeader   unset   Accept-Encoding
    	SSLRequireSSL
    </Location>

    <Location /webcal/>
    	ProxyPassReverse /
    	PerlAddVar ProxyHTMLURLMap "/ /webcal/"
    	RequestHeader   unset   Accept-Encoding
    	SSLRequireSSL
    </Location>

    <Location /intranet/>
    	ProxyPassReverse /
    	PerlAddVar ProxyHTMLURLMap "/ /intranet/"
	# Use to avoid duplicate rewriting in some case
    	PerlAddVar ProxyHTMLURLMap "/intranet/intranet /intranet"
    	PerlAddVar ProxyHTMLURLMap "/intranet/webmail /webmail"
    	PerlAddVar ProxyHTMLURLMap "/intranet/webcal /webcal"
    	RequestHeader   unset   Accept-Encoding
    	SSLRequireSSL
    </Location>

=head1 BUGS

Apache2::ModProxyPerlHtml is still under development and is sure
to contain a few bugs. Please send me email to submit bug reports.

=head1 COPYRIGHT

Copyright (c) 2005 - Gilles Darold

All rights reserved.  This program is free software; you may redistribute
it and/or modify it under the same terms as Perl itself.

=head1 AUTHOR

Apache2::ModProxyPerlHtml was created by :

	Gilles Darold
	<gilles at darold dot net>

and is currently maintain by me.


