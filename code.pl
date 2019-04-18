#!/usr/bin/env perl
use utf8;
binmode(STDOUT, ":utf8");
use Modern::Perl '2015';
use autodie;

use Fcntl; # O_RDONLY

use Cwd;

#use Redis;

use Email::MIME;

use Mail::DKIM::Verifier;

use JSON;

my $dkim = Mail::DKIM::Verifier->new();
my $message;

{
    no warnings 'once';
    open(HANDLE, "data/facebook.eml");

    #while (<STDIN>)
    while (<HANDLE>) {
        $message .= $_;
        # remove local line terminators
        chomp;
        s/\015$//;

        # use SMTP line terminators
        $dkim->PRINT("$_\015\012");
    }
    close(HANDLE) or die("Failed to close?");
}
$dkim->CLOSE;

my $result = $dkim->result;

print("DKMIM:");
print("\ttesult: " . $result . "\n");

if ($result ne "pass") {
    my $detail = $dkim->result_detail;
    print("\t\tresult details: " . $detail . "\n");
}
# there might be multiple signatures, what is the result per signature?
foreach my $signature ($dkim->signatures)
{
    print "\t\tsignature identity: " . $signature->identity . ', verify result: ' . $signature->result_detail . "\n";
}

# the alleged author of the email may specify how to handle email
foreach my $policy ($dkim->policies)
{
    #print ("Policy: " . $policy);
    print "\t\tWARNING: fraudulent message" if ($policy->apply($dkim) eq 'reject');
}
print("Email headers:\n");
my $email = Email::MIME->new($message);

my @parts = $email->parts; # These will be Email::MIME objects, too.
my $decoded = $email->body;
my $non_decoded = $email->body_raw;

my $content_type = $email->content_type;
my $description = $email->debug_structure;

#$description =~  s/^/\t\t/g;
#$description =~  s/\n/\n\t\t/g;
$description =~  s/^ *\+/\t\t/g;
$description =~  s/^ ? *\+/\t\t\t/gm;
chomp $description;

print "\tcontent_type: " . $content_type . "\n";
print "\temail structure:\n" . $description . "\n";

sub get_dkim_signed_headers {
    my ($header_obj) = @_;
    my $dkim_sig = $header_obj->header_raw("DKIM-Signature");
    return 0 if (not $dkim_sig);
    my @parts = split /; /, $dkim_sig;
    foreach my $part (@parts) {
        chomp $part;
        my @tag = split /=/, $part;
        if ($tag[0] eq "h") {
            my $tagdata = $tag[1];
            return split /:/, $tagdata;
        }
    }
}

#my @pairs = $parsed->header_str_pairs;
my $header = $email->header_obj;
use Data::Dumper;

# DKIM-Signature h=Date:To:Subject:From:MIME-Version:Content-Type;

#print $header->as_string;
my @vhead = get_dkim_signed_headers($header);

foreach my $hname (@vhead) {
    my $hdata = $header->header_str($hname);
    print "VALIDATED: " . $hname . ": " . $hdata . "\n" if $hdata;
}


print("\n\n-----------------------------------------------------------------------\n");
