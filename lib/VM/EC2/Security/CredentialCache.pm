package VM::EC2::Security::CredentialCache;

use strict;
use warnings;
use DateTime::Format::ISO8601;
use VM::EC2::Instance::Metadata;

=head1 NAME

VM::EC2::Security::CredentialCache -- Cache credentials respecting expriation time for IAM roles.

=head1 SYNOPSIS

Retrieves the current EC2 instance's IAM credentials and caches them until they expire.

  use VM::EC2::Security::CredentialCache;

  # return a VM::EC2::Security::Credentials if avaiable undef otherwise.
  my $credentials = VM::EC2::Security::CredentialCache->get();

=head1 DESCRIPTION

This module provides a cache for an EC2's IAM credentials represented by L<VM::EC2::Security::Credentials>. 
Rather than retriving the credentials for every possible call that uses them, cache them until they
expire and retreive them again if they have expired.

=cut

my $credentials;
my $credential_expiration_dt;

sub get {
    if (!defined($credentials)) {
        my $meta = VM::EC2::Instance::Metadata->new;
        defined($meta) || die("Unable to retrieve instance metadata");
        $credentials= $meta->iam_credentials;
        defined($credentials) || die("No IAM credentials retrieved from instance metadata");
        $credential_expiration_dt = DateTime::Format::ISO8601->parse_datetime($credentials->expiration());
    }

    if ($credential_expiration_dt->subtract_datetime_absolute(DateTime->now())->is_positive()) {
        return $credentials;
    } 
    
    $credentials = undef;
    $credential_expiration_dt = undef;
    return get_credentials();
}

1;
