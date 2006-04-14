package Snort::Rule;

use 5.008006;
use strict;
use warnings;

our $VERSION = '1.00';

# Put any options in here that require quotes around them
my @QUOTED_OPTIONS = ('MSG','URICONTENT','CONTENT','PCRE');

# CONSTRUCTOR

sub new {
	my ($class, %param) = @_;
	my $self = {};
	bless($self,$class);
	$self->init(%param);
	$self->parseRule($param{parse}) if($param{parse});
	return ($self);
}

# INIT

sub init {
	my ($self,%param) = @_;
	$self->action(	$param{action});
	$self->proto(	$param{proto});
	$self->src(	$param{src});
	$self->sport(	$param{sport});
	$self->dir(	$param{dir});
	$self->dst(	$param{dst});
	$self->dport(	$param{dport});
}

# METHODS

sub string {
	my $self = shift;
	my $rule = $self->action().' '.$self->proto().' '.$self->src().' '.$self->sport().' '.$self->dir().' '.$self->dst().' '.$self->dport().' (';
	my @sort = sort { $a <=> $b } keys %{$self->opts};
	foreach my $opt (@sort) {
		$rule .= ' '.$self->opts->{$opt}->{opt}.': '.$self->opts->{$opt}->{val}.';';
	}
	$rule .= ' )';
	return $rule;
}

# ACCESSORS/MODIFIERS

sub action {
	my ($self,$v) = @_;
	$self->{_action} = $v if(defined($v));
	return $self->{_action};
}

sub proto {
	my ($self,$v) = @_;
	$self->{_proto} = $v if(defined($v));
	return $self->{_proto};
}

sub src {
	my ($self,$v) = @_;
	$self->{_src} = $v if(defined($v));
	return $self->{_src};
}

sub sport {
	my ($self,$v) = @_;
	$self->{_sport} = $v if(defined($v));
	return $self->{_sport};
}

sub dir {
	my ($self,$v) = @_;
	$self->{_dir} = $v if(defined($v));
	return $self->{_dir};
}

sub dst {
	my ($self,$v) = @_;
	$self->{_dst} = $v if(defined($v));
	return $self->{_dst};
}

sub dport {
	my ($self,$v) = @_;
	$self->{_dport} = $v if(defined($v));
	return $self->{_dport};
}

sub opts {
	my ($self,$opt,$v) = @_;
	if (defined($opt) && defined($v)) {
		$v = fixQuotes($opt,$v);
		my $pri = (keys %{$self->{_opts}}) + 1;
		$self->{_opts}->{$pri}->{opt} = $opt;
		$self->{_opts}->{$pri}->{val} = $v;
	}
	return $self->{_opts};
}

# FUNCTIONS

sub fixQuotes {
	my ($opt, $v) = @_;
	foreach my $option (@QUOTED_OPTIONS) {
		if (uc($opt) eq $option) {
			if (!($v =~ /^\"\S+|\s+\"$/)) {		# do we have the appropriate quotes? (anchored for pcre)
				$v =~ s/^\"|\"$//g;		# strip the quotes
				$v = "\"$v\"";			# fix em
			}
			last;
		}
	}
	return $v;
}

sub parseRule {
	my ($self, $rule) = @_;
	my @r = split(/\(/,$rule,2);
	$r[1] =~ s/\)$//;

	my @meta = split(/\s+/,$r[0]);
	my @opts = split(/\;/,$r[1]);

	$self->action(	$meta[0]);
	$self->proto(	$meta[1]);
	$self->src(	$meta[2]);
	$self->sport(	$meta[3]);
	$self->dir(	$meta[4]);
	$self->dst(	$meta[5]);
	$self->dport(	$meta[6]);

	foreach my $x (@opts) {
		my ($opt, $v) = split(/\:/, $x);
		$opt =~ s/\s+//;			# clean up the spaces
		$v =~ s/\s+// if($v);
		$self->opts($opt, $v);
	}
}

1;
__END__
=head1 NAME

Snort::Rule - Perl extension for dynamically building snort rules

=head1 SYNOPSIS

  use Snort::Rule;
  $rule = Snort::Rule->new(
				action	=> 'alert',
				proto	=> 'tcp',
				src	=> 'any',
				sport	=> 'any',
				dir	=> '->',
				dst	=> '192.188.1.1',
				dport	=> '44444',
			);
  $rule->opts('msg','Test Rule"');
  $rule->opts('threshold','type limit,track by_src,count 1,seconds 3600');
  $rule->opts('sid','500000');

  print $rule->string()."\n";

  OR

  $rule = 'alert tcp $SMTP_SERVERS any -> $EXTERNAL_NET 25 (msg:"BLEEDING-EDGE POLICY SMTP US Top Secret PROPIN"; flow:to_server,established; content:"Subject|3A|"; pcre:"/(TOP\sSECRET|TS)//[\s\w,/-]*PROPIN[\s\w,/-]*(?=//(25)?X[1-9])/ism"; classtype:policy-violation; sid:2002448; rev:1;)';

  $rule = Snort::Rule->new(parse => $rule);
  print $rule->string()."\n";

=head1 DESCRIPTION

  This is a very simple snort rule object. It was developed to allow for scripted dynamic rule creation. Ideally you could dynamically take a list of bad hosts and build an array of snort rule objects from that list. Then write that list using the string() method to a snort rules file.

=head1 OBJECT METHODS

=head2 new

  Reads in the initial headers to generate a rule and constructs the snort::rule object around it

=head2 action

  Sets and returns the rule action [alert,log,pass,...]
  $rule->action('alert');

=head2 proto

  Sets and returns the protocol used in the rule [tcp,icmp,udp]
  $rule->proto('tcp');

=head2 src

  Sets and returns the source used in the rule
  $rule->proto('$EXTERNAL_NET');

=head2 sport

  Sets and returns the source port used in the rule
  $rule->sport(80);

=head2 dir

  Sets and returns the direction operator used in the rule, -> <- or <>
  $rule->dir('->');

=head2 dst

  Sets and returns the destination used in the rule
  $rule->dst('$HOME_NET');
  $rule->dst('192.168.1.1');

=head2 dport

  Sets and returns the destination port used in the rule
  $rule->dport(6667);

=head2 opts

  Sets an option and a value used in the rule.
  This currently can only be done one set at a time, and is printed in the order it was set.

  $rule->opts(option,value);
  $rule->opts('msg','this is a test rule');

  my $hashref = $rule->opts();
  This will return a hashref: $hashref->{$keyOrderValue}->{option} and $hashref->{$keyOrderValue}->{value}

  There is a fixQuotes() function that reads through this information before setting it, just to ensure the right options are sane. It's a very very basic function, but it seems to get the job done.

=head2 string

  Outputs the rule in string form.
  
=head1 AUTHOR

Wes Young, E<lt>saxguard9-cpan@yahoo.comE<gt>

=head1 COPYRIGHT AND LICENSE

Copyright (C) 2006 by Wes Young

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself, either Perl version 5.8.6 or,
at your option, any later version of Perl 5 you may have available.


=cut
