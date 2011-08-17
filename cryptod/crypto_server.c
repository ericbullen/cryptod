/*
 *
 * CryptoServer- Written by Eric Bullen (Feb 12, 2008)
 * Licensed under the GNU GPL Licence version 2
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * This program listens on a TCP port or unix socket, and receives information
 * on that port, and performs the requested action. Common actions
 * are aes256 encrypting/decrypting, base64 encoding/decoding, and
 * RMD160 hashing. It uses pthreads to handle multiple simultaneous
 * requests, uses very little ram (about 900k), and is extremely fast.
 *
 * Doing a sustained test of 218 million transactions, and processing
 * over 128GB of data (could have been more if I didn't use Perl to test),
 * there were no memory leaks (valgrind memory checking showed NO errors),
 * or incorrect encryption/decryption.
 *
 * Questions (preferably not coding ones), or contributions, please 
 * contact me at: eric.bullen@gmail.com
 *
 */

///////////// SYSTEM INCLUDES /////////////
#include <arpa/inet.h>
#include <ctype.h>
#include <math.h>
#include <openssl/evp.h>
#include <pthread.h>
#include <pwd.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

////////////// KEY VARIABLES //////////////

#define VERSION "1.0"
#define BUFFER_SIZE 4096
#define KEY_LENGTH 1024

struct key_struct {
   unsigned char strong_key[EVP_MAX_KEY_LENGTH];
   unsigned char strong_iv[EVP_MAX_IV_LENGTH];
};

struct threadarg {
   int client;
   char buffer[BUFFER_SIZE];
   struct key_struct *key;
};

struct option_list {
   int debug;
   int daemonize;
   int listen_port;
   int time_to_exit;
   int url_safe_b64;
   char *user;
   char *key_file;
   char *listen_socket;
};

int debug = 0;
int max_threads = 0;
int running_threads = 0;
unsigned int hash_count = 0;
unsigned int service_count = 0;
unsigned long long int bytes_decrypted = 0;
unsigned long long int bytes_encrypted = 0;
struct option_list options;

// Lock for global counters, etc.
static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;

///////////// LOCAL INCLUDES /////////////
#include "crypto_server.h"

///////////////////////////////////////////////////////////////////////
// Main thread- receives connections, and passes them off to threads //
///////////////////////////////////////////////////////////////////////

int main(int argc, char **argv) {
   int c;
   unsigned char *user_key;

   // Signal handling - respecting the possibility that a signal was
   // previously ignored (done by non-job-control shells).

   // No core dumping!
   if (signal (SIGQUIT, termination_handler) == SIG_IGN)
      signal (SIGQUIT, SIG_IGN);
   if (signal (SIGINT, termination_handler) == SIG_IGN)
      signal (SIGINT, SIG_IGN);
   if (signal (SIGHUP, termination_handler) == SIG_IGN)
      signal (SIGHUP, SIG_IGN);
   if (signal (SIGTERM, termination_handler) == SIG_IGN)
      signal (SIGTERM, SIG_IGN);

   // Set default values for the options struct
   options.debug = 0;
   options.daemonize = 0;
   options.url_safe_b64 = 0;
   options.listen_port = 9997;
   options.time_to_exit = 0;
   options.key_file = NULL;
   options.listen_socket = NULL;

   // Turn off error reporting for getopt.
   opterr=0;

   while ((c = getopt (argc, argv, "wvk:u:p:s:xdh")) != -1) {
      switch (c) {
         case 'w':
            options.url_safe_b64 = 1;
            break;
         case 'x':
            options.debug = 1;
            break;
         case 'v':
            printf("cryptod version %s\n", VERSION);
            return 1;
         case 'p':
            options.listen_port = strtod(optarg, NULL);
            break;
         case 's':
            options.listen_socket = optarg;
            break;
         case 'u':
            options.user = optarg;
            break;
         case 'k':
            options.key_file = optarg;
            break;
         case 'd':
            options.daemonize = 1;
            break;
         case 'h':
            printf("Arguments: -p <tcp_listen_port> -s <listen_socket_path> -u <switch_user> -k <key_file> -v (version) -w (url safe encoding) -d (daemonize) -x (debug)\n");
            return 1;
         case '?':
            if (optopt == 'p')
               fprintf (stderr, "Option -%c requires an argument (the port number).\n", optopt);
            else if (isprint (optopt))
               fprintf (stderr, "Unknown option `-%c'.\n", optopt);
            else
               fprintf (stderr, "Unknown option character `\\x%x'.\n", optopt);
            return 1;
         default:
            abort();
      }
   }

   if (!options.listen_socket && (options.listen_port < 1 || options.listen_port > 65535))
      DOH("You must specify a tcp port (-p <port>) between 1 and 65535, or a socket (-s <path>).\n");

   //------------ KEY SETUP -------------------------------------
   // Get the key that the daemon will be using.
   user_key = get_key();

   struct key_struct key;

   memset(key.strong_key, 0, EVP_MAX_KEY_LENGTH);
   memset(key.strong_iv, 0, EVP_MAX_IV_LENGTH);

   digest(key.strong_key, user_key, strlen((char *)user_key));
   digest(key.strong_iv, key.strong_key, sizeof(key.strong_key));

   free(user_key);

   //-------------------------------------------------------------

   if (options.user)
      switch_user(options.user);

   // Daemonize now
   if (options.daemonize) {
      if (daemonizer() == -1)
         DOH("ERROR: Could not daemonize.\n");
   }

   pthread_t unix_child;
   pthread_t tcp_child;

   // bind_socket
   if (options.listen_socket) {
      if (pthread_create(&unix_child, NULL, handle_unix_socket, &key) != 0)
         DOH("Thread creation.\n");
   }

   // bind_tcp
   if (options.listen_port > 0) {
      if (pthread_create(&tcp_child, NULL, handle_tcp_socket, &key) != 0)
         DOH("Thread creation.\n");
   }

   if (options.listen_socket)
      pthread_join(unix_child, NULL);

   if (options.listen_port > 0)
      pthread_join(tcp_child, NULL);

   return 0;
}
