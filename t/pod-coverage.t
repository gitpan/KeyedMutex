use Test::Pod::Coverage tests => 1;

pod_coverage_ok('KeyedMutex', { also_private => [ qw/new/ ] });
