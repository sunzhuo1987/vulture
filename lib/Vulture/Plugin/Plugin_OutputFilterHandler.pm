#!/usr/bin/perl

package Plugin::Plugin_OutputFilterHandler;

use strict;
use warnings;

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
%Plugin::Plugin_OutputFilterHandler::functions = (
    'Header Add' => \&Plugin::Plugin_OutputFilterHandler::header_add,
    'Header Modify' => \&Plugin::Plugin_OutputFilterHandler::header_modify,
    'Header Replacement' => \&Plugin::Plugin_OutputFilterHandler::header_replace,
    'Header Unset' => \&Plugin::Plugin_OutputFilterHandler::header_unset,
    'Mime Forbiden' => \&Plugin::Plugin_OutputFilterHandler::mime_forbid,
    'Rewrite Content' => \&Plugin::Plugin_OutputFilterHandler::rewrite_content,
    'Rewrite Link' => \&Plugin::Plugin_OutputFilterHandler::rewrite_link,
);
sub header_add{
    my ($f, $exp, $opt, $opt1) = @_;
    $f->r->headers_out->unset($exp);
    $f->r->headers_out->set($exp=>$opt);
}
sub header_modify{
    my ($f, $exp, $opt, $opt1) = @_;
    if ( $f->r->content_type =~ m/$exp/i ) {
        $f->r->headers_out->unset( $opt);
        $f->r->headers_out->set( $opt => $opt1);
    }
}
sub header_replace{
    my ($f, $exp, $opt, $opt1) = @_;
    foreach my $headval ($f->r->headers_out->get($exp)) {
        if ( $headval and ($headval =~ /$opt/x) ) {
            $headval =~ s/$opt/$opt1/ig;
            $f->r->headers_out->unset($exp);
            $f->r->headers_out->set( $exp => $headval );
        }
    }
}
sub header_unset{
    my ($f, $exp, $opt, $opt1) = @_;
    $f->r->headers_out->unset($exp);
}
sub mime_forbid{
    my ($f, $exp, $opt, $opt1) = @_;
    if ( $f->r->content_type =~ m/$exp/i ) {
        return Apache2::Const::FORBIDDEN;
    }
}
sub rewrite_content{
    my ($f,  $exp, $opt, $opt1) = @_;
    if ( $f->r->content_type =~ /charset=(.*)/ ) {
        Encode::from_to( $exp, "utf8", $1 );
        Encode::from_to( $opt, "utf8", $1 );
    }
    $f->r->headers_out->unset('Content-Length');
    my $ctx = $f->ctx;
    $ctx->{do_rewrite} = 1;
    push(@{$ctx->{rewrite_content}}, [$exp, $opt]);
    $f->ctx($ctx);
}
sub rewrite_link{
    my ($f,  $exp, $opt, $opt1) = @_;
    my $content_type = $f->r->content_type() || '';
    if ( $content_type =~ /charset=(.*)/ ) {
        Encode::from_to( $exp,     "utf8", $1 );
        Encode::from_to( $opt, "utf8", $1 );
    }
    $f->r->headers_out->unset('Content-Length');
    my $ctx = $f->ctx;
    $ctx->{do_rewrite} = 1;
    push( @{ $ctx->{rewrite_link} }, [$exp , $opt] );
    $f->ctx($ctx);
}
sub handler {
    my $f    = shift;
    my $r    = $f->r;
    my $log  = $r->server->log;
    my $user = $r->user;
    my $ctx = $f->ctx;

    if ( $r->content_type eq "image/svg+xml" ){
        return Apache2::Const::DECLINED;
    }
    unless ( $ctx->{once} ){
        $ctx->{once} = 1;
        $f->ctx($ctx);
        my $rewrites = $r->pnotes("content_rewrites");
        foreach my $conf_row (@$rewrites){
            my ($type, $exp, $opt, $opt1) = @$conf_row;
            if (not exists $Plugin::Plugin_OutputFilterHandler::functions{$type}){
                $log->error("Unknown rewrite function in outputfilter!");
                next;
            }
            my $ret = &{$Plugin::Plugin_OutputFilterHandler::functions{$type}}(
                $f, $exp, $opt, $opt1 );
            return $ret if defined $ret and $ret == Apache2::Const::FORBIDDEN;
        }
    }
    $ctx = $f->ctx;
    my $content = '';
    while ( $f->read( my $buffer, BUFF_LEN ) ) {
        $content .= $buffer;
        $ctx->{keepalives} = $f->c->keepalives;
    }
    $ctx->{data} .= $content;
    $f->ctx($ctx);
    return Apache2::Const::OK unless ($f->seen_eos);
    # Thing we do at end
    if ( $ctx->{do_rewrite} ) {
        # Skip content that should not have links
        my $parsed_uri = $f->r->construct_url();
        my $encoding = $f->r->headers_out->{'Content-Encoding'} || '';

        # if Accept-Encoding: gzip,deflate try to uncompress
        if ( $encoding =~ /gzip|deflate|x-compress|x-gzip/ ) {
            $log->debug("decompressing $encoding");
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
          ){
            # Replace links if pattern match
            my $parsed_2 = APR::URI->parse( $f->r->pool, $parsed_uri );
            &do_rewrite_link( \$ctx->{data}, '//',
                $parsed_2->scheme . '://', $parsed_uri );
            foreach my $p ( @{$ctx->{rewrite_link}} ) {
                my ( $match, $substitute ) = @$p;#split( / => /, $p );
                $log->debug("LINK : MATCH : $match, SUB : $substitute");
                &do_rewrite_link( \$ctx->{data}, $match, $substitute,
                    $parsed_uri );
            }

            # Rewrite content if pattern match
            foreach my $p ( @{$ctx->{rewrite_content}} ) {
                my ( $match, $substitute ) = @$p;#split( / => /, $p );
                $log->debug("CONTENT : MATCH : $match, SUB : $substitute");
                &do_rewrite_content( \$ctx->{data}, $match, $substitute,
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
        $f->ctx($ctx);
    }

    # Dump datas out
    $f->print( $f->ctx->{data});

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
    return Apache2::Const::OK;
}

sub do_rewrite_link {
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

sub do_rewrite_content {
    my ( $data, $pattern, $replacement, $uri ) = @_;
    return if ( !$$data );

    my $old_terminator = $/;
    $/ = '';

    # Rewrite things in code (case sensitive)
    $$data =~ s/$pattern/$replacement/g;

    $/ = $old_terminator;

}
1;
