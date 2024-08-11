package NftablesBlocker::Flocker;

# I am so sick and tired of flocks that do not work.  I am going to write my own flocker.

use strict;
use warnings;
use Carp qw(carp croak);
use Fcntl qw(:flock);

# Constructor
sub new {
    my ($class, %args) = @_;
    my $self = {
        lock_file => $args{lock_file} || croak "lock_file parameter is required",
        lock      => 0,
    };
    bless $self, $class;

    $self->_initialize_lock();
    return $self;
}

# Initialize the lock file
sub _initialize_lock {
    my $self = shift;

    if (-e $self->{lock_file}) {
        if ($self->_is_any_pid_running()) {
            $self->{lock} = 0;
        } else {
            $self->_create_lock_file();
            $self->{lock} = 1;
        }
    } else {
        $self->_create_lock_file();
        $self->{lock} = 1;
    }
}

# Check if any PID from the lock file is still running
sub _is_any_pid_running {
    my $self = shift;
    my $pids = $self->_read_lock_file();

    if (!@$pids) {
        carp "No PIDs in file or file is not readable.  Check: $self->{lock_file}";
        return 1;
    }

    foreach my $pid (@$pids) {
        chomp $pid;
        return 1 if kill 0, $pid;
    }

    return 0;
}

# Read the lock file and return an array reference of PIDs
sub _read_lock_file {
    my $self = shift;
    open my $fh, '<', $self->{lock_file} or carp "Cannot open lock file: $!" and return ();
    my @pids = <$fh>;
    close $fh;
    return \@pids;
}

# Create a new lock file with the current PID
sub _create_lock_file {
    my $self = shift;
    open my $fh, '>', $self->{lock_file} or croak "Cannot create lock file: $!";
    print $fh $$;
    close $fh;
}

# Get the current lock status
sub lock {
    my $self = shift;
    return $self->{lock};
}

# Destructor to clean up the lock file
#  This is automagically called when the object goes out of scope
sub DESTROY {
    my $self = shift;
    unlink $self->{lock_file} or carp "Cannot delete lock file: $!";
}

1;
