#!/usr/bin/perl

package Plugin::Plugin_OutputFilterHandler;

use strict;
use warnings;

BEGIN {
    use Exporter ();
    our @ISA       = qw(Exporter);
    our @EXPORT_OK = qw(&plugin);
}

use base qw(Apache2::Filter);
use Apache2::Const qw(OK DECLINED FORBIDDEN :conn_keepalive);
use Apache2::Connection ();
use Apache2::RequestRec;
use Apache2::RequestUtil;
use APR::Table;
use APR::URI;
use constant BUFF_LEN => 8000;
use Apache2::ServerRec;
use Apache2::URI;
use Data::Dumper;
use Encode;

%Plugin::Plugin_OutputFilterHandler::linkElements = (
    'a'      => [ 'href',    'id' ],
    'applet' => [ 'archive', 'codebase', 'code' ],
    'area'       => ['href'],
    'bgsound'    => ['src'],
    'blockquote' => ['cite'],
    'body'       => ['background'],
    'del'        => ['cite'],
    'embed'      => [ 'pluginspage', 'src' ],
    'form'       => ['action'],
    'frame'      => [ 'src', 'longdesc' ],
    'iframe'     => [ 'src', 'longdesc' ],
    'ilayer'     => ['background'],
    'img'        => [ 'src', 'lowsrc', 'longdesc', 'usemap' ],
    'input'   => [ 'src',        'usemap' ],
    'ins'     => ['cite'],
    'isindex' => ['action'],
    'head'    => ['profile'],
    'layer'   => [ 'background', 'src' ],
    'link'    => ['href'],
    'object' => [ 'classid', 'codebase', 'data', 'archive', 'usemap' ],
    'q'      => ['cite'],
    'script' => [ 'src',        'for' ],
    'table'  => ['background'],
    'td'     => [ 'background', 'src' ],
    'th'     => ['background'],
    'tr'     => ['background'],
    'xmp'    => ['href'],
);

sub handler {
    my $f    = shift;
    my $r    = $f->r;
    my $log  = $r->server->log;
    my $user = $r->user;
    my $i    = 0;
    if ( $r->content_type ne "image/svg+xml" ) {
        unless ( $f->ctx ) {
            while ( $r->pnotes( 'type' . $i ) ) {
                my $type = $r->pnotes( 'type' . $i );
                my $exp  = $r->pnotes( 'exp' . $i );
                if ( $type eq "Header Add" ) {
                    $r->headers_out->unset($exp);
                    $r->headers_out->set(
                        $exp => $r->pnotes( 'options_' . $i ) );
                }
                if ( $type eq "Header Modify" ) {

                    if ( $r->content_type =~ m/$exp/i ) {
                        $r->headers_out->unset( $r->pnotes( 'options_' . $i ) );
                        $r->headers_out->set( $r->pnotes( 'options_' . $i ) =>
                              $r->pnotes( 'options1_' . $i ) );
                    }
                }
                if ( $type eq "Header Replacement" ) {
                    $log->debug("Header Replacement");
                    my @valhead           = $r->headers_out->get($exp);
                    my $value             = $r->pnotes( 'options_' . $i );
                    my $replacementheader = $r->pnotes( 'options1_' . $i );
                    my $headval;
                    foreach $headval (@valhead) {
                        if ( $headval && $headval =~ /$value/x ) {
                            $log->debug(
"Plugin_OutputFilterHandler RH Rule substitution OLDVAL=",
                                $headval
                            );
                            $headval =~ s/$value/$replacementheader/ig;
                            $log->debug(
"Plugin_OutputFilterHandler RH Rule substitution NEWVAL=",
                                $headval
                            );
                            $r->headers_out->unset($exp);
                            $r->headers_out->set( $exp => $headval );
                        }
                    }
                }
                if ( $type eq "Mime Forbiden" ) {
                    if ( $r->content_type =~ m/$exp/i ) {
                        return Apache2::Const::FORBIDDEN;
                    }
                }
                if ( $type eq "Header Unset" ) {
                    $r->headers_out->unset($exp);
                }
                if ( $type eq "Header to Link" ) {
                    my $linkval = $r->headers_out->get($exp);
                    $linkval =
                      $linkval . " => " . $r->pnotes( 'options_' . $i );
                    $log->debug($linkval);
                }
                if ( $type eq "Header to Proxy" ) {
                    $log->debug($exp);
                    my $linkval = $r->headers_out->get($exp);

                    #$session{url} = $linkval;
                    $log->debug( "we follow the link", $linkval );
                }
                if ( $type eq "Rewrite Content" ) {
                    $log->debug("Rewrite Content");
                    my $options = $r->pnotes( 'options_' . $i );
                    my $content_type = $f->r->content_type() || '';
                    if ( $content_type =~ /charset=(.*)/ ) {
                        Encode::from_to( $exp,     "utf8", $1 );
                        Encode::from_to( $options, "utf8", $1 );
                    }
                    $f->r->headers_out->unset('Content-Length');
                    my @rewrite = $exp . " => " . $options;
                    $log->debug($exp);
                    my $ct = $f->ctx;
                    $ct->{data} = '';
                    foreach my $p (@rewrite) {
                        push( @{ $ct->{rewrite} }, $p );
                    }
                    $f->ctx($ct);
                }
                my $linkval;
                if ( ( $type eq "Rewrite Link" ) or ( defined($linkval) ) ) {
                    $log->debug("Rewrite Link");
                    my $options = $r->pnotes( 'options_' . $i );
                    my $content_type = $f->r->content_type() || '';
                    if ( $content_type =~ /charset=(.*)/ ) {
                        Encode::from_to( $exp,     "utf8", $1 );
                        Encode::from_to( $options, "utf8", $1 );
                    }
                    $f->r->headers_out->unset('Content-Length');
                    my @pattern = $exp . " => " . $options;
                    if ( defined($linkval) ) {
                        @pattern = $linkval;
                    }
                    my $ct = $f->ctx;
                    $ct->{data} = '';
                    foreach my $p (@pattern) {
                        push( @{ $ct->{pattern} }, $p );
                    }
                    $f->ctx($ct);
                }
                $i++;
            }
            $i = 0;
        }
        my $ctx = $f->ctx;
        while ( $f->read( my $buffer, BUFF_LEN ) ) {
            $ctx->{data} .= $buffer;
            $ctx->{keepalives} = $f->c->keepalives;
            $f->ctx($ctx);
        }

        # Thing we do at end
        if ( $f->seen_eos ) {
            if ( ( $ctx->{pattern} ) || ( $ctx->{rewrite} ) ) {

                # Skip content that should not have links
                my $parsed_uri = $f->r->construct_url();
                my $encoding = $f->r->headers_out->{'Content-Encoding'} || '';

                # if Accept-Encoding: gzip,deflate try to uncompress
                if ( $encoding =~ /gzip|deflate|x-compress|x-gzip/ ) {
                    use IO::Uncompress::AnyInflate
                      qw(anyinflate $AnyInflateError);
                    my $output = '';
                    anyinflate \$ctx->{data} => \$output
                      or print STDERR "anyinflate failed: $AnyInflateError\n";
                    if ( $ctx->{data} ne $output ) {
                        $ctx->{data} = $output;
                    }
                    else {
                        $encoding = '';
                    }
                }
                if ( $r->content_type =~
/(text\/xml|text\/html|application\/vnd.ogc.wms_xml|text\/css|application\/x-javascript)/
                  )
                {

                    # Replace links if pattern match
                    my $parsed_2 = APR::URI->parse( $f->r->pool, $parsed_uri );
                    &link_replacement( \$ctx->{data}, '//',
                        $parsed_2->scheme . '://', $parsed_uri );
                    foreach my $p ( @{ $ctx->{pattern} } ) {
                        my ( $match, $substitute ) = split( / => /, $p );
                        $log->debug($match);
                        $log->debug($substitute);
                        &link_replacement( \$ctx->{data}, $match, $substitute,
                            $parsed_uri );
                    }

                    # Rewrite content if pattern match
                    foreach my $p ( @{ $ctx->{rewrite} } ) {
                        my ( $match, $substitute ) = split( / => /, $p );
                        $log->debug($match);
                        $log->debug($substitute);
                        &rewrite_content( \$ctx->{data}, $match, $substitute,
                            $parsed_uri );
                    }
                }

                if ( $encoding =~ /gzip|x-gzip/ ) {
                    use IO::Compress::Gzip qw(gzip $GzipError);
                    my $output = '';
                    my $status = gzip \$ctx->{data} => \$output
                      or die "gzip failed: $GzipError\n";
                    $ctx->{data} = $output;
                }
                elsif ( $encoding =~ /deflate|x-compress/ ) {
                    use IO::Compress::Deflate qw(deflate $DeflateError);
                    my $output = '';
                    my $status = deflate \$ctx->{data} => \$output
                      or die "deflate failed: $DeflateError\n";
                    $ctx->{data} = $output;
                }
                unless ( defined $ctx->{data} ) {
                    $ctx->{data} = '';
                }
            }
            $f->ctx($ctx);

            # Dump datas out
            $f->print( $f->ctx->{data} );
            my $c = $f->c or return Apache2::Const::DECLINED;
            if (   $c->keepalive == Apache2::Const::CONN_KEEPALIVE
                && $ctx->{data}
                && $c->keepalives > $ctx->{keepalives} )
            {

          #unused variable debug
          #if ($debug) {
          #	warn "[ModProxyPerlHtml] cleaning context for keep alive request\n";
          #}
                $ctx->{data}       = '';
                $ctx->{pattern}    = ();
                $ctx->{keepalives} = $c->keepalives;
            }
        }
        return Apache2::Const::OK;
    }
    else {
        return Apache2::Const::DECLINED;
    }
}

sub link_replacement {
    my ( $data, $pattern, $replacement, $uri ) = @_;

    return if ( !$$data );

    my $old_terminator = $/;
    $/ = '';
    my @TODOS = ();
    my $i     = 0;

    # Replace standard link into attributes of any element
    foreach my $tag ( keys %Plugin::Plugin_OutputFilterHandler::linkElements ) {
        next if ( $$data !~ /<$tag/i );
        foreach my $attr (
            @{ $Plugin::Plugin_OutputFilterHandler::linkElements{$tag} } )
        {
            while ( $$data =~
s/(<$tag[\t\s]+[^>]*\b$attr=['"]*)($replacement|$pattern)([^'"\s>]+)/NEEDREPLACE_$i$$/i
              )
            {
                push( @TODOS, "$1$replacement$3" );
                $i++;
            }

        }
    }

# Replace all links in javascript code
#	$$data =~ s/([^\\]['"])($replacement|$pattern)([^'"]*['"])/$1$replacement$3/ig;
    $$data =~
      s/([\\]['])($replacement|$pattern)([^'"]*[\\]['])/$1$replacement$3/ig;

    # Try to set a fully qualified URI
    $uri =~ s/$replacement.*//;

    # Replace meta refresh URLs
    $$data =~
s/(<meta\b[^>]+content=['"]*.*url=)($replacement|$pattern)([^>]+)/$1$uri$replacement$3/i;

    # Replace base URI
    $$data =~
s/(<base\b[^>]+href=['"]*)($replacement|$pattern)([^>]+)/$1$uri$replacement$3/i;

    # CSS have url import call, most of the time not quoted
    $$data =~
      s/(url\(['"]*)($replacement|$pattern)(.*['"]*\))/$1$replacement$3/ig;

    # Javascript have image object or other with a src method.
    $$data =~
s/(\.src[\s\t]*=[\s\t]*['"]*)($replacement|$pattern)(.*['"]*)/$1$replacement$3/ig;

    # The single ended tag broke mod_proxy parsing
    $$data =~ s/($replacement|$pattern)>/\/>/ig;

    # Replace todos now
    for ( $i = 0 ; $i <= $#TODOS ; $i++ ) {

        $$data =~ s/NEEDREPLACE_$i$$/$TODOS[$i]/i;
    }

    $/ = $old_terminator;

}

sub rewrite_content {
    my ( $data, $pattern, $replacement, $uri ) = @_;

    return if ( !$$data );

    my $old_terminator = $/;
    $/ = '';

    # Rewrite things in code (case sensitive)
    $$data =~ s/$pattern/$replacement/g;

    $/ = $old_terminator;

}
1;

