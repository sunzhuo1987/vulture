#file:Plugin/Plugin_STATIC.pm
#-------------------------
#!/usr/bin/perl
package Plugin::Plugin_STATIC;

use strict;
use warnings;
use Cwd;

BEGIN {
    use Exporter ();
    our @ISA       = qw(Exporter);
    our @EXPORT_OK = qw(&plugin);
}

use Apache2::Log;
use Apache2::Reload;

use Core::VultureUtils qw(&session &get_cookie);
use Apache2::Const -compile => qw(OK FORBIDDEN);
use MIME::Types;

sub plugin {
    my ( $package_name, $r, $log, $dbh, $intf, $app, $options ) = @_;
    my @captured = @{$options};
    my $mc_conf  = $r->pnotes('mc_conf');
    $log->debug("########## Plugin_STATIC ##########");

    #Destroy useless handlers
    $r->set_handlers( PerlAccessHandler => undef );
    $r->set_handlers( PerlAuthenHandler => undef );
    $r->set_handlers( PerlAuthzHandler  => undef );
    $r->set_handlers( PerlFixupHandler  => undef );

    my $fpath = Cwd::abs_path( $r->dir_config('VultureStaticPath') . $captured[0] );
    return Apache2::Const::FORBIDDEN if not $fpath;

    $log->debug("Serving $fpath");
    my $regexp = $r->dir_config('VultureStaticPath');
    if ( $fpath !~ /^$regexp/ ) {
        return Apache2::Const::FORBIDDEN;
    }
    $r->filename($fpath);
    my $mimetypes = MIME::Types->new;
    my MIME::Type $mime = $mimetypes->mimeTypeOf($fpath);
    if (defined $mime){
        $r->content_type($mime->type());
    }
    $r->pnotes( 'static' => 1 );
    return Apache2::Const::OK;
}
1;
