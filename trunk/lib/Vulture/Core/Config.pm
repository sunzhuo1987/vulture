#file:Core/Config.pm
#-------------------------
package Core::Config;

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

sub getKey {
	my ($self, $key) = @_;
	
	return $self->{'config'}->{$key}->{'value'} ? $self->{'config'}->{$key}->{'value'} : '';
}
1;
