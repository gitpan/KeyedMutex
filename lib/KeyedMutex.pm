package KeyedMutex;

use strict;
use warnings;

use Digest::MD5 qw/md5/;
use IO::Socket::INET;
use IO::Socket::UNIX;
use POSIX qw/:errno_h/;
use Regexp::Common qw/net/;

package KeyedMutex;

our $VERSION = '0.01';

use constant DEFAULT_SOCKPATH => '/tmp/keyedmutexd.sock';
use constant KEY_SIZE         => 16;

sub new {
    my ($klass, $opts) = @_;
    $klass = ref($klass) || $klass;
    $opts ||= {};
    my $sock;
    my $peer = $opts->{sock} || DEFAULT_SOCKPATH;
    if ($peer =~ /^(?:|($RE{net}{IPv4}):)(\d+)$/) {
        my ($host, $port) = ($1 || '127.0.0.1', $2);
        $sock = IO::Socket::INET->new(
            PeerHost => $host,
            PeerPort => $port,
            Proto    => 'tcp',
        );
    } else {
        $sock = IO::Socket::UNIX->new(
            Type => SOCK_STREAM,
            Peer => $peer,
        );
    }
    die 'failed to connect to keyedmutexd' unless $sock;
    bless {
        sock => $sock,
        locked => undef,
    }, $klass;
}

sub DESTROY {
    my $self = shift;
    $self->{sock}->close;
}

sub locked {
    my $self = shift;
    $self->{locked};
}

sub lock {
    my ($self, $key) = @_;
    
    # check state
    die "already holding a lock\n" if $self->{locked};
    
    # send key
    my $hashed_key = md5($key);
    $self->{sock}->syswrite($hashed_key, KEY_SIZE) == KEY_SIZE
        or die 'connection error';
    # wait for response
    my $res;
    while ($self->{sock}->sysread($res, 1) != 1) {
        die 'connection error' unless $! == EINTR;
    }
    $self->{locked} = $res eq 'O';
    return $self->{locked};
}

sub release {
    my ($self) = @_;
    
    # check state
    die "not holding a lock\n" unless $self->{locked};
    
    $self->{sock}->syswrite('R', 1) == 1
        or die 'connection error';
    $self->{locked} = undef;
    1;
}

1;

__END__

=head1 NAME

KeyedMutex - An interprocess keyed mutex

=head1 SYNOPSIS

  % keyedmutexd >/dev/null &
  
  use KeyedMutex;
  
  my $km = KeyedMutex->new;
  
  until ($value = $cache->get($key)) {
    if ($km->lock($key)) {
      # locked, read from DB
      $value = get_from_db($key);
      $cache->set($key, $value);
      $km->release;
      last;
    }
  }

=head1 DESCRIPTION

C<KeyedMutex> is an interprocess keyed mutex.  Its intended use is to prevent sending identical requests to database servers at the same time.  By using C<KeyedMutex>, only a single client would send a request to the database, and others can retrieve the result from a shared cache (namely memcached or Cache::Swifty) instead.

=head1 THE CONSTRUCTOR

Following parameters are recognized.

=head2 sock

Optional.  Path to a unix domain socket or a tcp port on which C<keyedmutexd> is running.  Defaults to /tmp/keyedmutexd.sock.

=head1 METHODS

=head2 lock($key)

Tries to obtain a mutex lock for given key.  If successful, the client should later on release the lock by calling C<release>.  A return value undef means some other client that held the lock has released it.

=head2 release

Releases the lock.

=head2 locked

Returns if the object is currently holding a lock.

=head1 SEE ALSO

http://labs.cybozu.co.jp/blog/kazuhoatwork/

=head1 AUTHOR

Copyright (c) 2007 Cybozu Labs, Inc.  All rights reserved.

written by Kazuho Oku E<lt>kazuhooku@gmail.comE<gt>

=head1 LICENSE

This program is free software; you can redistribute it and/or modify it under th
e same terms as Perl itself.

See http://www.perl.com/perl/misc/Artistic.html

=cut
