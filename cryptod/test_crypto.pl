#!/bin/env perl

# vim:tabstop=3

use strict;
use warnings;
use IO::Socket;

$| = 1;
my $port = 9997;

sub send_data {
   my ($host, $port, $timeout, $data) = @_;
   my $return_data = "";
   my $past_header = "";

   # Nested evals to guard against race conditions.
   eval {
      local $SIG{ALRM} = sub { die "bad error occurred" };
      alarm $timeout;
      eval {
         my $socket = IO::Socket::INET->new( PeerAddr => $host,
                     PeerPort => $port,
                     Proto    => "tcp",
                     Type     => SOCK_STREAM) or die "bad error occurred";

         print $socket "$data" or die "bad error occurred";

         # This while loop gets past the header from the webserver,
         # and removes all whitespace.

         while (my $line = <$socket>) {
            $return_data .= $line;
         }
         close($socket);
      };
      alarm 0;
   };
   alarm 0;
   return $return_data;
}

sub crypto {
   my $plaintext = shift;
   return send_data("127.0.0.1", $port, 999, "[ENCRYPT]\r\n$plaintext\r\n.\r\n");
}

sub decrypto {
   my $crypttext = shift;
   return send_data("127.0.0.1", $port, 999, "[DECRYPT]\r\n$crypttext\r\n.\r\n");
}

sub hash {
   my $plaintext = shift;
   return send_data("127.0.0.1", $port, 999, "[RMD160_HASH]\r\n$plaintext\r\n.\r\n");
}

sub status {
   my $plaintext = shift;
   return send_data("127.0.0.1", $port, 999, "[STATUS]\r\n.\r\n");
}

sub b64_decode {
   my $crypttext = shift;
   return send_data("127.0.0.1", $port, 999, "[B64_DECODE]\r\n$crypttext\r\n.\r\n");
}

sub b64_encode {
   my $plaintext = shift;
   return send_data("127.0.0.1", $port, 999, "[B64_ENCODE]\r\n$plaintext\r\n.\r\n");
}

my $trip_counter = 0;
my $iterations = 100000;
my $words = "words";
my @words_array = ();
my $lower_limit = 2;
#my $upper_limit = 200;
my $upper_limit = 500;
my $counter = 0;
my $regen_sentence = 0;

open(RH, "<$words");
while(<RH>) {
   chomp;
   push(@words_array, $_);
}
close(RH);

srand(time());
my $sentence = "";
my $dict_count = scalar(@words_array);

while(1) {
   my $encrypted = "";
   my $decrypted = "";

   if (!$sentence || $regen_sentence) {
      my $counter = 0;
      my $word_count = int(rand($upper_limit - $lower_limit) + $lower_limit);

      for ($counter = 0; $counter < $word_count; $counter++) {
         $sentence .= $words_array[int(rand($dict_count))] . " ";
      }
   }

   my $rand_num = int(rand(100));

   if ($rand_num < 25) {
      $encrypted = crypto($sentence);
      $decrypted = decrypto($encrypted);

      if ($decrypted ne $sentence) {
         print "FAIL ($trip_counter done): >$sentence< (got: >$decrypted<)\n";
         die;
      }

   } elsif ($rand_num < 50) {
      hash($sentence);

   } elsif ($rand_num < 75) {
      $encrypted = b64_encode($sentence);
      $decrypted = b64_decode($encrypted);

      if ($decrypted ne $sentence) {
         print "FAIL ($trip_counter done): >$sentence< (got: >$decrypted<)\n";
         die;
      }

   } elsif ($rand_num < 75) {
      status();
   } 

   $trip_counter++;
   print "." if ($trip_counter % 1000 == 0);
   last if ($trip_counter > $iterations);
}

print "> Done with $iterations iterations.\n";
