# this is equivalent to your startup.pl.
# it does not need to contain anything unless
# startup.pl behavior is a required part of your module

if ($ENV{HARNESS_PERL_SWITCHES}) {

  eval {
    # 0.48 is the first version of Devel::Cover that can
    # really generate mod_perl coverage statistics
    require Devel::Cover;
    Devel::Cover->VERSION(0.48);

    # this ignores coverage data for some generated files
    # you may need to adjust this slightly for your config
    Devel::Cover->import('+inc' => 't/response/',);

    1;
  } or die "Devel::Cover error: $@";
}

1;
