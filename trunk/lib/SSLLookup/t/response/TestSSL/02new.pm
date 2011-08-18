package TestSSL::02new;

use strict;
use warnings FATAL => qw(all);

use Apache::Test qw(-withtestmore);

use Apache2::Const -compile => qw(OK);

sub handler {

  my $r = shift;

  plan $r, tests => 7;

  { 
    use_ok('Apache::SSLLookup');
  }

  { 
    can_ok('Apache::SSLLookup', 'new');
  }

  {
    eval { $r = Apache::SSLLookup->new() };

    like ($@,
          qr/Usage:/,
          'new() requires arguments');
  }

  {
    eval { $r = Apache::SSLLookup->new({}) };

    like ($@,
          qr/method `new' invoked by a `unknown' object with no `r' key/,
          'new() requires an object');
  }

  {
    eval { $r = Apache::SSLLookup->new(bless {}, 'foo') };

    like ($@,
          qr/method `new' invoked by a `foo' object with no `r' key/,
          'new() requires an Apache2::RequestRec object');
  }

  {
    $r = Apache::SSLLookup->new($r);

    isa_ok($r, 'Apache::SSLLookup');

    isa_ok($r, 'Apache2::RequestRec');
  }

  return Apache2::Const::OK;
}

1;
