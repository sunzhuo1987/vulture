#file:Core/Config.pm
#-------------------------
#!/usr/bin/perl
package Core::Config;

use strict;
use warnings;

BEGIN {
    use Exporter ();
    our @ISA = qw(Exporter);
    our @EXPORT_OK = qw(&new &get_key);
}

use DBI;

sub new {
	my $class = $_[0];
	my($self) = {};
	$self->{'dbh'} = $_[1];
	bless ($self, $class);
    
    my $sth = $self->{'dbh'}->prepare("SELECT var, value FROM conf");
    $sth->execute;
    $self->{'config'} = $sth->fetchall_hashref('var');
    $sth->finish();
	return ($self);
}

sub get_key {
	my ($self, $key) = @_;
	
	return $self->{'config'}->{$key}->{'value'} ? $self->{'config'}->{$key}->{'value'} : undef;
}
1;
