use ExtUtils::MakeMaker;

WriteMakefile(
    NAME          => 'KeyedMutex',
    VERSION_FROM  => 'lib/KeyedMutex.pm',
    EXE_FILES     => [
        'keyedmutexd/keyedmutexd',
    ],
    PREREQ_PM     => {
        'Digest::MD5'         => 0,
        'File::Remove'        => 0,
        'Regexp::Common'      => 0,
        'Test::Pod::Coverage' => 1.04,
    },
    ABSTRACT_FROM => 'lib/KeyedMutex.pm',
    AUTHOR        => 'Kazuho Oku',
);

package MY;

sub top_targets {
    my $self = shift;
    my $o = $self->SUPER::top_targets();
    $o =~ s/^pure_all\s*:+.*/$& keyedmutexd/m;
    $o;
}

sub clean {
    my $self = shift;
    my $o = $self->SUPER::clean();
    $o =~ s/^clean\s*:+.*/$& clean_keyedmutexd/m;
    $o;
}

sub postamble {
    my $make  =<< 'EOT';
keyedmutexd:
    cd keyedmutexd && $(MAKE) all

clean_keyedmutexd:
    cd keyedmutexd && $(MAKE) clean

EOT
    ;
    $make =~ s/^    /\t/mg;
    $make;
}
