package VM::EC2::Security::CredentialCache;
$VM::EC2::Security::CredentialCache::VERSION = '0.18';
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

        return $credentials;
    }

    # AWS provides new credentials atleast 5 minutes before the expiration of the old 
    # credentials, but we'll only start looking at 4 minutes
    if ($credential_expiration_dt->subtract_datetime_absolute(DateTime->now())->in_units('minutes') > 4) {
        return $credentials;
    } 
        
    # These credentials are good for only 4 minutes or less, so clear them and attempt to 
    # retrieve new credentials.
    $credentials = undef;
    $credential_expiration_dt = undef;
    return get();
}

1;
