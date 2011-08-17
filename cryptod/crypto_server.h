void DOH(char *msg) {
   fprintf(stderr, msg);
   options.time_to_exit = 1;

   if (options.listen_socket)
      unlink(options.listen_socket);

   exit(-1);
}

void *xmalloc (size_t size) {
   register void *value = malloc(size);

   if (value == NULL) {
      free(value);
      DOH("Virtual memory exhausted.\n");
   }

   return value;
}

unsigned char *bin2hex(unsigned char *input) {
   unsigned char *output;
   int length = sizeof(input);
   int i = 0;

   output = xmalloc((length * 2) + 1); // 1 for Null
   memset(output, 0, (length * 2) + 1);

   for(i = 0; i < length; i++)
      sprintf((char *)output + (i * 2), "%02x", input[i]);

   return output;
}

int daemonizer (void) {
   int i;
   pid_t pid;

   chdir("/");
   umask(0);

   if ((pid = fork()) != 0)
      exit(0);

   setsid();
   signal(SIGHUP, SIG_IGN);

   if ((pid = fork()) != 0)
      exit(0);
   
   // STDIN -> STDERR 
   for(i=0; i < 3; i++)
      close(i);

   return 0;
}

int digest(unsigned char *md_value, unsigned char *message, int message_len) {
   EVP_MD_CTX mdctx;
   unsigned int md_len;

   EVP_MD_CTX_init(&mdctx);
   EVP_DigestInit_ex(&mdctx, EVP_ripemd160(), NULL);
   EVP_DigestUpdate(&mdctx, message, message_len);
   EVP_DigestFinal_ex(&mdctx, md_value, &md_len);
   EVP_MD_CTX_cleanup(&mdctx);

   return 0;
}

unsigned char *base64_encode(unsigned char *buf, unsigned int len) {
   register unsigned char *ret = NULL;
   unsigned int  b64_len;
   unsigned int i = 0;

   /* the b64data to data ratio is 3 to 4.
    * integer divide by 3 then multiply by 4, add one for NULL terminator.
    */
   b64_len = (((len + 2) / 3) * 4) + 1;

   ret = (unsigned char *)xmalloc(b64_len);
   memset(ret, 0, b64_len);

   EVP_EncodeBlock(ret, buf, len);
   ret[b64_len - 1] = 0;

   if (options.url_safe_b64) {
      // Make it URL/web safe
      for(i=0; i < b64_len; i++) {
         if (ret[i] == '+')
            ret[i] = '-';  
         else if (ret[i] == '/')
            ret[i] = '_';  
         else if (ret[i] == '=')
            ret[i] = 0;
      }
   }

   return ret;
}

unsigned char *base64_decode(unsigned char *bbuf, unsigned int len, unsigned int *bin_len) {
   register unsigned char *ret = NULL;
   register unsigned char *tmp_buf = NULL;
   unsigned int i = 0;
   unsigned int output_bin_len = 0;
   int padding_size = 0;
   
   if (options.url_safe_b64)
      padding_size = 4 - (len % 4);

   /* integer divide by 4 then multiply by 3, its binary so no NULL */
   *bin_len = (((len + padding_size + 3) / 4) * 3);

   ret = (unsigned char *)xmalloc(*bin_len + 1);
   memset(ret, 0, *bin_len + 1);

   if (options.url_safe_b64) {
      tmp_buf = (unsigned char *)xmalloc(len + padding_size + 1);
      memset(tmp_buf, 0, len + padding_size + 1);

      memcpy(tmp_buf, bbuf, len);

      // Make it URL/web safe
      for(i=0; i < len; i++) {
         if (tmp_buf[i] == '-')
            tmp_buf[i] = '+';
         else if (tmp_buf[i] == '_')
            tmp_buf[i] = '/';
      }

      if (padding_size > 0)
         strncat((char *)tmp_buf, "====", padding_size);
   } else {
      tmp_buf = bbuf;
   }

   len = len + padding_size;
   output_bin_len = EVP_DecodeBlock(ret, tmp_buf, len);
   
   if (output_bin_len > *bin_len) {
      // We have an error
      *ret = (unsigned char)"";
      *bin_len = 0;
   } 

   if (options.url_safe_b64)
      free(tmp_buf);

   return ret;
} 

int aes256_encrypt(unsigned char *strong_key, unsigned char *strong_iv, unsigned char *plaintext, int in_len, int *out_len, unsigned char *ciphertext) {
   int total_len = 0;

   EVP_CIPHER_CTX ctx;

   EVP_EncryptInit(&ctx, EVP_aes_256_cbc(), strong_key, strong_iv);
   EVP_EncryptUpdate(&ctx, ciphertext, out_len, plaintext, in_len);

   total_len = *out_len;

   EVP_EncryptFinal(&ctx, ciphertext + *out_len, out_len);
   EVP_CIPHER_CTX_cleanup(&ctx);

   *out_len += total_len;

   return 0;
}

int aes256_decrypt(unsigned char *strong_key, unsigned char *strong_iv, unsigned char *ciphertext, int in_len, unsigned char *plaintext) {
   int out_len = 0;
   int total_len = 0;

   EVP_CIPHER_CTX ctx;

   EVP_DecryptInit(&ctx, EVP_aes_256_cbc(), strong_key, strong_iv);
   EVP_DecryptUpdate(&ctx, plaintext, &out_len, ciphertext, in_len);

   total_len = out_len;

   EVP_DecryptFinal(&ctx, plaintext + out_len, &out_len);
   EVP_CIPHER_CTX_cleanup(&ctx);

   out_len += total_len;

   plaintext[out_len] = 0;

   return 0;
}

unsigned char *decrypt(unsigned char *strong_key, unsigned char *strong_iv, unsigned char *b64_text, int payload_len) {
   register unsigned char *plaintext = NULL;
   register unsigned char *crypttext = NULL;
   unsigned int bin_len = 0;

   crypttext = base64_decode(b64_text, payload_len, &bin_len);
   plaintext = (unsigned char *)xmalloc(bin_len);
   memset(plaintext, 0, bin_len);

   bin_len = (bin_len - ( bin_len % 16));
   aes256_decrypt(strong_key, strong_iv, crypttext, bin_len, plaintext);

   free(crypttext);

   return plaintext;
}

unsigned char *encrypt(unsigned char *strong_key, unsigned char *strong_iv, unsigned char *plaintext, int plaintext_len) {
   register unsigned char *ciphertext = NULL;
   register unsigned char *b64_text = NULL;
   int out_len;

   int cipher_length = (unsigned int)(16*ceil((1+plaintext_len)/16.0)); // 16 = AES block size
   ciphertext = (unsigned char *)xmalloc(cipher_length);
   memset(ciphertext, 0, cipher_length);

   aes256_encrypt(strong_key, strong_iv, plaintext, plaintext_len, &out_len, ciphertext);

   b64_text = base64_encode(ciphertext, out_len);

   free(ciphertext);

   return b64_text;
}

void termination_handler (int signum) {
   fprintf(stderr, "Exiting on signal %d.\n", signum);
   options.time_to_exit = 1;

   if (options.listen_socket)
      unlink(options.listen_socket);

   exit(1);
}

unsigned char *get_key(void) {
   unsigned char *local_key;

   local_key = xmalloc(KEY_LENGTH);
   memset(local_key, 0, sizeof(local_key));

   FILE *fp = NULL;

   if (options.key_file)
      fp = fopen(options.key_file, "r");

   if (fp != NULL) {
      fgets((char *)local_key, sizeof(local_key) - 1, fp);
      fclose(fp);
   } else {
      printf("Please enter the encrypt/decrypt key: ");
      scanf("%s", local_key);
   }

   return local_key;
}

int is_superuser(void) { 
   /* quickie to see if we're the superuser or not */
   return ( (getuid() == 0 && getgid() == 0) ); 
}

static int get_id(char *username, uid_t *uid, gid_t *gid) {
   /* 
    * Set uid and gid to the preferred user (found in setuid.h). Can either be
    * numeric or a string, found in /etc/passwd.
   */
   struct passwd *pw;

   if ((pw = getpwnam(username))) {
      // Name exists
      *uid = pw->pw_uid;
      *gid = pw->pw_gid;
      return 0;
   }

   /* something Bad happened, so send back an error */
   return -1;
}

int switch_user(char *username) {
   /* 
    * Set uid and gid to the username specified in the function parameters.
    *
    * If the root user starts memcached and specifies `-u root' we will let
    * them run as root.
   */

   uid_t uid; gid_t gid;

   if (is_superuser()) {
      // we are root
      if (strcmp(username,"") == 0) {
         // username isnt set and we're running as root. let's get outta here
         fprintf(stderr,"No username specified with -u option!\n");
         exit(-1);

      } else {
         // We're root, but the user gave us a username to switch too.
         int retval;
         retval = get_id(username,&uid,&gid);
         if (retval) {
            //fprintf(stderr,"An error occurred while trying to setuid\nExiting...\n");
            return retval;
         } // Error in getting uid/gid.
      } // we're okay for the setuid/setgid command Down Below

   } else {
      //we are not root
      if (strcmp(username,"") == 0) {
         //no username, so we'll just run as $USER
         return 0;

      } else {
         /* Here we really have an option to let the user continue running as
          * themselves, or to quit outright.  I've decided to exit.
         */
         int retval;
         retval = get_id(username,&uid,&gid);
         if (retval) {
            //fprintf(stderr,"An error occurred while trying to setuid\nExiting...\n");
            return retval;
         } // Error in getting uid/gid.
      }
   }

   if (setgid(gid)) 
      return -1;
   if (setuid(uid))
      return -1;

   if ((getuid() == 0 || getgid() == 0) && strcmp(username,"root") != 0) {
      /* We're still root, and we shouldn't be! */
      return -1;
   }

   return 0;
}

void *Child(void *threadarg) {
   if ((pthread_detach(pthread_self())) != 0) {
      printf("Socket detach error!\n");
      pthread_exit(NULL);
   }

   pthread_mutex_lock(&lock);

   running_threads++;
   if (running_threads > max_threads)
      max_threads = running_threads;

   pthread_mutex_unlock(&lock);

   struct threadarg *parameters = NULL;
   parameters = (struct threadarg *)threadarg;

   if (options.debug) 
      printf("Begin Thread: %d (socket: %d)\n", (int)pthread_self(), parameters->client);

   char *socket_data = NULL;
   char *tmp_pointer = NULL;
   int bytes_read = 0;
   int read_count = 0;
   int found_endmark = 0;
   int endmark_length = 5; // 5 = "\r\n.\r\n"

   while(1) {
      memset(parameters->buffer, 0, BUFFER_SIZE);
      bytes_read = read(parameters->client, parameters->buffer, BUFFER_SIZE);

      // Triggered when a socket is closed, but no data arrives.
      if (bytes_read <= 0)
            break;

      // Have to do this because I kept on getting problems with realloc
      tmp_pointer = (char *)xmalloc(read_count + bytes_read + 1);              

      memcpy(tmp_pointer, socket_data, read_count);
      free(socket_data);

      socket_data = tmp_pointer;

      memcpy(socket_data + read_count, parameters->buffer, bytes_read);
      read_count += bytes_read;

      // Use the '.' as how SMTP does it - just compare the last 5 bytes.
      if (!strncmp(parameters->buffer + (bytes_read - endmark_length), "\r\n.\r\n", endmark_length)) {
            socket_data[read_count] = 0;
            found_endmark = 1;
            break;
      }
   }

   if (found_endmark && read_count > 0) {
      int header_len = strcspn(socket_data, "\n") - 1;
      int payload_start = header_len + 2;
      int payload_len = read_count - (header_len + 2) - endmark_length;
      unsigned char *output = NULL;
      int got_output = 0;

      if (payload_len > 0) {
         // Is there anything after the header?
         if (header_len > 0) {
            if (options.debug)
               printf("Payload Length: %u\n", payload_len);

            if (!strncmp(socket_data, "[ENCRYPT]", header_len)) {
               output = encrypt(parameters->key->strong_key, parameters->key->strong_iv, (unsigned char *)socket_data + payload_start, payload_len);
               got_output = 1;

               pthread_mutex_lock(&lock);
               bytes_encrypted += read_count;
               pthread_mutex_unlock(&lock);

            } else if (!strncmp(socket_data, "[DECRYPT]", header_len)) {
               output = decrypt(parameters->key->strong_key, parameters->key->strong_iv, (unsigned char *)socket_data + payload_start, payload_len);
               got_output = 1;

               pthread_mutex_lock(&lock);
               bytes_decrypted += read_count;
               pthread_mutex_unlock(&lock);

            } else if (!strncmp(socket_data, "[B64_ENCODE]", header_len)) {
               output = base64_encode((unsigned char *)socket_data + payload_start, payload_len);
               got_output = 1;

               pthread_mutex_lock(&lock);
               bytes_encrypted += read_count;
               pthread_mutex_unlock(&lock);

            } else if (!strncmp(socket_data, "[B64_DECODE]", header_len)) {
               unsigned int binlen = 0;

               output = base64_decode((unsigned char *)socket_data + payload_start, payload_len, &binlen);
               got_output = 1;

               pthread_mutex_lock(&lock);
               bytes_decrypted += read_count;
               pthread_mutex_unlock(&lock);

            } else if (!strncmp(socket_data, "[RMD160_HASH]", header_len)) {
               unsigned char new_output[20];

               memset(new_output, 0, sizeof(new_output));

               digest(new_output, (unsigned char *)socket_data + payload_start, payload_len);

               output = bin2hex(new_output);

               got_output = 1;

               pthread_mutex_lock(&lock);
               hash_count += 1;
               pthread_mutex_unlock(&lock);
            } else {
               printf("ERROR: Header unknown.\n");
            }
         }
      } else {
         if (header_len > 0) {
            if (!strncmp(socket_data, "[STATUS]", header_len)) {
               int rc = 0;
               struct rusage resource;

               if((rc = getrusage(RUSAGE_SELF, &resource)) != 0)
                  DOH("getrusage failed.\n");

               int max_len = BUFFER_SIZE;
               output = xmalloc(max_len);
               memset(output, 0, sizeof(output));

               snprintf((char *)output, max_len,
                        "running_threads: %d\n"     // Arg 3 
                        "bytes_decrypted: %lld\n"
                        "bytes_encrypted: %lld\n"
                        "hash_count: %u\n"
                        "max_threads: %d\n"
                        "user_time: %ld.%06ld sec\n"
                        "system_time: %ld.%06ld sec\n"
                        "page_reclaims: %lu\n"
                        "page_faults: %ld\n"
                        "messages_sent: %ld\n"
                        "messages_received: %ld\n"
                        "max_rss: %ld\n"
                        "integral_shared_memory_size: %ld\n"
                        "integral_unshared_data_size: %ld\n"
                        "integral_unshared_stack_size: %ld\n"
                        "service_count: %u\n",
                        running_threads,
                        bytes_decrypted,
                        bytes_encrypted,
                        hash_count,
                        max_threads,
                        resource.ru_utime.tv_sec, resource.ru_utime.tv_usec,
                        resource.ru_stime.tv_sec, resource.ru_stime.tv_usec,
                        resource.ru_minflt,
                        resource.ru_majflt,
                        resource.ru_msgsnd,
                        resource.ru_msgrcv,
                        resource.ru_maxrss,
                        resource.ru_ixrss,
                        resource.ru_idrss,
                        resource.ru_isrss,
                        service_count);
               got_output = 1;
            }
         }
      }

      if (got_output) {
         send(parameters->client, output, strlen((char *)output), 0);
         free(output);
      }
   }

   if (options.debug) 
      printf("Closing Socket: %d (socket: %d)\n", (int)pthread_self(), parameters->client);

   if (close(parameters->client) != 0)
      DOH("Error closing socket.\n");

   free(socket_data);

   pthread_mutex_lock(&lock);
   running_threads--;
   service_count++;
   pthread_mutex_unlock(&lock);

   if (options.debug) 
      printf("End Thread: %d (socket: %d)\n\n\n", (int)pthread_self(), parameters->client);

   free(parameters);
   return threadarg;
}

void *handle_unix_socket(void *key_struct) {
   int sd;
   struct sockaddr_un source_data, from_data;
   int addr_size = sizeof(from_data);
   int socket_fd = 0;
   int len = 0;

   struct key_struct *key = NULL;
   key = (struct key_struct *)key_struct;

   if ( (sd = socket(AF_UNIX, SOCK_STREAM, 0)) < 0 )
      DOH("Socket.\n");
   
   (void)fcntl(sd, F_SETFD, 1);
   memset(&source_data, 0, sizeof(struct sockaddr_un));
   memset(&from_data, 0, sizeof(struct sockaddr_un));

   source_data.sun_family = AF_UNIX;
   strcpy(source_data.sun_path, options.listen_socket);
   unlink(options.listen_socket);

   len = sizeof(source_data.sun_family) + strlen(source_data.sun_path);

   // BIND TO THE UNIX SOCKET
   umask(0);
   if ( bind(sd, (struct sockaddr *)&source_data, len) != 0 )
      DOH("Can't bind to socket.\n");
   umask(022);

   if ( listen(sd, 10) < 0 )
      DOH("Can't listen to port.\n");

   while (1) {
      pthread_t child;

      if ((socket_fd = accept(sd, (struct sockaddr*)&from_data, (socklen_t *)&addr_size)) != -1 ) {
         struct threadarg *parameters = NULL;

         parameters = (struct threadarg *)xmalloc(sizeof(struct threadarg));
         memset(parameters, 0, sizeof(struct threadarg));
   
         parameters->client = socket_fd;
         parameters->key = key;

         if ( pthread_create(&child, NULL, Child, (void *)parameters) != 0 )
            DOH("Thread creation.\n");

         if (options.time_to_exit) {
            unlink(options.listen_socket);

            free(parameters);
            break;
         }

      } else {
         DOH("Accept error.\n");
      }
   }

   return 0;
}

void *handle_tcp_socket(void *key_struct) {
   int sd;
   struct sockaddr_in addr;
   int addr_size = sizeof(addr);
   int socket_fd = 0;

   struct key_struct *key = NULL;
   key = (struct key_struct *)key_struct;

   if ( (sd = socket(PF_INET, SOCK_STREAM, 0)) < 0 )
      DOH("Socket.\n");

   addr.sin_family = AF_INET;
   addr.sin_port = htons(options.listen_port);
   addr.sin_addr.s_addr = INADDR_ANY;

   int opt = 1;

   if (setsockopt(sd, SOL_SOCKET, SO_REUSEADDR, (char *)&opt, sizeof(opt)) < 0)
      exit(1);

   // BIND TO THE NETWORK
   if ( bind(sd, (struct sockaddr*)&addr, sizeof(addr)) != 0 )
      DOH("Can't bind to port.\n");

   if ( listen(sd, 10) < 0 )
      DOH("Can't listen to port.\n");

   while (1) {
      pthread_t child;

      if ((socket_fd = accept(sd, (struct sockaddr*)&addr, (socklen_t *)&addr_size)) != -1 ) {
         struct threadarg *parameters = NULL;
      
         parameters = (struct threadarg *)xmalloc(sizeof(struct threadarg));
         memset(parameters, 0, sizeof(struct threadarg));
      
         parameters->client = socket_fd;
         parameters->key = key;
      
         if ( pthread_create(&child, NULL, Child, (void *)parameters) != 0 )
            DOH("Thread creation.\n");

         if (options.time_to_exit) {
            free(parameters);
            break;
         }

      } else {
         DOH("Accept error.\n");
      }
   }

   return 0;
}
