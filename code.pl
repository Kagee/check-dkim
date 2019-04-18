#!/usr/bin/env perl

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

open(HANDLE, "data/facebook.eml");

#while (<STDIN>)
while (<HANDLE>)
{
    $message .= $_;
    # remove local line terminators
    chomp;
    s/\015$//;

    # use SMTP line terminators
    $dkim->PRINT("$_\015\012");
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

#my @pairs = $parsed->header_str_pairs;
my $header = $email->header_obj;
use Data::Dumper;

# DKIM-Signature h=Date:To:Subject:From:MIME-Version:Content-Type;

#print $header->as_string;
print $header->header_raw("mIme-vErSiOn");
#print Dumper(@header);
#print Dumper($header);
#print Dumper(%header3);
print("\n\n-----------------------------------------------------------------------\n");
