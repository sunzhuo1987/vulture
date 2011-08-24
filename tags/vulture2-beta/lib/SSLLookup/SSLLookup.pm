package Apache::SSLLookup;

use 5.008001;

use strict;

use DynaLoader ();

our @ISA = qw(DynaLoader);
our $VERSION = '2.00_04';

__PACKAGE__->bootstrap($VERSION);

1;

__END__

=head1 NAME

Apache::SSLLookup - hooks for various mod_ssl functions

=head1 SYNOPSIS

in httpd.conf:

  # pre-loading via PerlModule or startup.pl is REQUIRED!!!
  PerlModule Apache::SSLLookup

in any handler:

  sub handler {
    my $r = Apache::SSLLookup->new(shift);

    my $request_is_over_ssl = $r->is_https;

    my $value = $r->lookup_var('SSL_CLIENT_VERIFY');

    ...
  }

=head1 DESCRIPTION

Apache::SSLLookup is a glue layer between Perl handlers
and the mod_ssl public API.  under normal circumstances, you would
use C<$rE<gt>subprocess_env()> to glean information about mod_ssl.
for example,

  my $request_is_over_ssl = $r->subprocess_env('HTTPS');

however, this is only possible after mod_ssl runs its fixups -
that is, Perl handlers can only accurately check the
C<subprocess_env> table for mod_ssl information in the
PerlResponsePhase or later.

this module allows you to query mod_ssl directly via its public
C API at any point in the request cycle.  but without using C,
of course.

=head1 METHODS

there are only three methods you need to be concerned with.

=over 4

=item new()

to use this class you create an C<Apache::SSLLookup> object.
C<Apache::SSLLookup> is a subclass of C<Apache::RequestRec>
so you can simply call C<new()> and get on with your business.

  my $r = Apache::SSLLookup->new($r);

=item is_https()

returns true if mod_ssl considers the request to be under SSL.

  my $request_is_over_ssl = $r->is_https;

you can call this function any time during the request, specifically
before mod_ssl populates C<subprocess_env('HTTPS')> in the fixup
phase.

you must be using Apache 2.0.51 or greater for this method to
accurately reflect the SSL status of the request.

=item lookup_var()

returns the value of various mod_ssl environment variables.

  my $value = $r->lookup_var('SSL_CLIENT_VERIFY');

you can call this function any time during the request, specifically
before mod_ssl populates C<subprocess_env()> in the fixup phase.

=back

=head1 NOTES

this module is for Apache 2.0 exclusively.  it will not work with
Apache 1.3.

you MUST MUST MUST preload this module with PerlModule or from
a startup.pl.  what if you don't?  the short answer is that this
module will do nothing for you.  the long answer is that unless
you preload the module it will not be able to glean the optional
function definitions from mod_ssl.  I'm still trying to figure
out why not...

=head1 AUTHOR

Geoffrey Young E<lt>geoff@modperlcookbook.orgE<gt>

=head1 COPYRIGHT

Copyright (c) 2004, Geoffrey Young

All rights reserved.

This module is free software.  It may be used, redistributed
and/or modified under the same terms as Perl itself.

=cut
