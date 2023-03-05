#include <stdlib.h>
#include <stdio.h>
#include <syslog.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/queue.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <signal.h>
#include <strings.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdbool.h>
#include <libgen.h>
#include <sys/time.h>
#include <pthread.h>
#include <assert.h>


#define NSTRS                   4
#define MAX_IT                  1
#define LOCAL_PORT              54321
#define DEFAULT_PORT            9000
#define SIZE_OF_LOCAL_BUFFER 256
//#define SYSTEM_TCP_IP_ADDRESS   "10.0.10.30"
//#define SYSTEM_TCP_IP_ADDRESS   "localhost"
#define SYSTEM_TCP_IP_ADDRESS   "127.0.0.1"  //<<<< USE THIS ON LINUX LAPTOP
//#define SYSTEM_TCP_IP_ADDRESS   "10.0.2.15" <-- was originally for embedded hosts used on class
#define SYSTEM_SOCK_OPTION_VAL  "localhost" //<<<< USE THIS ON LINUX LAPTOP
//#define SYSTEM_SOCK_OPTION_VAL  "eth0";
#define FILE_WRITE_TIMEOUT      10000000
#define FILE_TO_WRITE_TO        "/var/tmp/aesdsocketdata"
#define FILE_TO_READ_TO        "/var/tmp/.tmp_aesdsocketdata"
//#define FILE_TO_WRITE_TO        "tmp/tmp/aesdsocketdata"
//#define LOCAL_PORT 3
#define ADD_BUSYBOX_IP "ip address add 10.0.10.90/24 brd 10.0.10.255 dev eth0"

#define PROGRAM_BUFFER_MAX 256

char *test_strs[NSTRS] = {
    "This is the first server string.\n",
    "This is the second server string.\n",
    "This is the third server string.\n",
    "Server sends: \"This has been the an assignment of ECEA 5305 Coursera "
        "edition.\"\n"
};

#define __LOCAL_SUCCESS__ 0
#define __LOCAL_FAIL__ 1

extern int errno;
extern void broken_pipe_handler();
extern void terminate_program_handler();
//extern void alarm_program_handler();
extern void external_interrupt_handler();
extern void *serve_clients_FGREEN(void* threadp);
void *timer_thread();

static int server_sock, client_sock;
static struct sockaddr_in server_sockaddr; //, client_sockaddr;
bool alarm_timer = false;

// Client THREADS
struct thread_data
{
    pthread_t* thread_id;
    struct sockaddr_in client_sockaddr;
    int client_data;
    int finished;
    int socketfd;
    bool connection_complete;
};


typedef struct thread_data thread_info_t;

struct slist_data_s 
{
    thread_info_t* thread;
    int count;
    SLIST_ENTRY(slist_data_s) entries;
};

typedef struct slist_data_s slist_data_t;

slist_data_t *datap = NULL;
SLIST_HEAD(slisthead, slist_data_s) head;

pthread_mutex_t sharedMemMutexSemaphore;

// The function is to turn the process of calling the function into a daemon.
void create_daemon(void)
{
    pid_t pid = 0;

    pid = fork();

    if (pid < 0)
    {
        perror("Program 'aesdsocket' FAILED to fork.");
        syslog(LOG_USER | LOG_ERR, "DEBUG CODE - FGREEN: Program 'aesdsocket'"
            " FAILED to fork.");

        exit(-1);
    }

    if (pid > 0)
    {
        syslog(LOG_USER | LOG_INFO, "DEBUG CODE - FGREEN: Program 'aesdsocket'"
            " SUCCESSFULLY forked.  The parent program exited. The dameon"
            " PID is %d", pid);

        exit(0);
    }

}
        

void external_process_daemon_kill_function(void)
{
    // Always assume everything fails and check for success.
    FILE *file_descriptor = NULL;

    int read_file_position_is = 0;

    system("touch /tmp/aesdsocketKillMe.txt");

    // Pointer to the working file, open it, create if necessary, and append.
    file_descriptor = fopen ("/tmp/aesdsocketKillMe.txt", "a+");

    if(file_descriptor == NULL)
    {
        syslog(LOG_USER | LOG_ERR, "DEBUG CODE - FGREEN: Student's error "
                "message: ERROR: Opening file failed to open or create file.");
    }
    else
    {
        //fseek(file_descriptor, 0L, SEEK_SET);
        fseek(file_descriptor, 0L, SEEK_END);

        read_file_position_is = ftell(file_descriptor);

        fseek(file_descriptor, 0L, SEEK_SET);

        char *what_to_read;

        what_to_read = (char*)malloc(read_file_position_is + 1);

        if (what_to_read == NULL)
        {
            printf("Error reallocating space for 'what_to_read'");
        }

        memset(what_to_read, 0, sizeof(read_file_position_is + 1));


        fread(what_to_read, read_file_position_is, 1, file_descriptor);

        if(strcmp(what_to_read, "true") == 0)
        {
            fflush(file_descriptor);
            fclose(file_descriptor);

            terminate_program_handler();

        }

        free(what_to_read);

        if(file_descriptor != NULL)
        {
            fflush(file_descriptor);
            fclose(file_descriptor);
        }
    }
}

//linked list
void init_linked_lists(void)
{
    SLIST_INIT(&head);
    assert(SLIST_EMPTY(&head) && "SList init");
}


// DEBUG CODE BELOW - FGREEN WAS NOT HERE
/* Required timer tracking */
int write_timer(FILE *file_descriptor)
{
   syslog(LOG_USER | LOG_ERR, "DEBUG CODE - FGREEN: Entering write_timer()");
   char buffer [256];
   char local_string [256] = {};
   int num_bytes_written = 0;
   const char* time_format = "%a, %d %b %Y %T %z";
   time_t local_time;
   struct tm *timestamp;
   
   local_time =  time(NULL);
   
   timestamp = localtime(&local_time); 
   
   if (timestamp == NULL)
   {
       perror("DEBUG CODE - FGREEN: localtime() failed");
       syslog(LOG_USER | LOG_ERR, "DEBUG CODE - FGREEN: write_timer() FAIL ");

       return (-1);
   }  

   if(strftime(local_string, sizeof(local_string), time_format, timestamp) == 0)
   { 
       return (-1);
   }

   strcpy(buffer, "timestamp:");
   strcat(buffer, local_string);
   strcat(buffer, "\n");

   num_bytes_written = fwrite (buffer, 1, strlen(buffer), file_descriptor);
   
   if (num_bytes_written != 0)
   {
       syslog(LOG_USER | LOG_INFO, "DEBUG CODE - FGREEN: write_timer() - "
              "fwrite() SUCCESS.  num_bytes_written = {%d}, buffer: {%s}"
              , num_bytes_written , buffer);
   }
   else
   {
       syslog(LOG_USER | LOG_ERR, "DEBUG CODE - FGREEN: write_timer() - "
              "fwrite() FAILED.  num_bytes_written = {%d}, buffer: {%s}"
              , num_bytes_written, buffer);
   }

   syslog(LOG_USER | LOG_INFO, "DEBUG CODE - FGREEN: Exiting write_timer()");
   return (0); 
}

void* timer_thread()
{
  int function_return_status = 0;
  time_t t;
  struct tm *tmp;

  for(;;) {
    sleep(10);
    t = time(NULL);
    tmp = localtime(&t);
    if (tmp == NULL) {
      perror("localtime");
      exit(EXIT_FAILURE);
    }

    syslog(LOG_USER | LOG_INFO, "DEBUG CODE - FGREEN: 3 of 3 alarm_timer truue or: {%d}", alarm_timer);
    //printf("DEBUG CODE - FGREEN: 3 of 3 alarm_timer true or: {%d}\n", alarm_timer);
    // Always assume everything fails and check for success.
    FILE *file_descriptor = NULL;
    // Pointer to the working file, open it, create if necessary, and append.
    //file_descriptor = fopen (FILE_TO_READ_TO, "w");
    function_return_status = pthread_mutex_lock(&sharedMemMutexSemaphore);
    if(function_return_status != 0)
    {
        syslog(LOG_USER | LOG_ERR, "DEBUG CODE - FGREEN: pthread_mutex_lock() FAILED ");
        
    }

    file_descriptor = fopen (FILE_TO_WRITE_TO, "a+");
    
    write_timer(file_descriptor);
    

    fflush(file_descriptor);
    fclose(file_descriptor);

    function_return_status = pthread_mutex_unlock(&sharedMemMutexSemaphore);
    if(function_return_status != 0)
    {
        syslog(LOG_USER | LOG_ERR, "DEBUG CODE - FGREEN: pthread_mutex_lock() FAILED ");
        
    }
  }
}


void remove_temporary_file()
{
    int check = 0;

    size_t message_alloc = 256;
    char system_message [message_alloc];

    memset(system_message, 0, sizeof(system_message));

    sprintf(system_message, "rm -fr %s", FILE_TO_WRITE_TO);
    printf("system_message = %s\n", system_message);
    syslog(LOG_USER | LOG_INFO, "DEBUG CODE - FGREEN: removing temporary "
            "file with command '$ %s'", system_message);
    check = system(system_message);

    // check if directory is created or not
    if (!check)
    {
        printf("Directory deleted\n");
    }
    else
    {
        printf("Unable to delete directory\n");
    }
}


int create_temporary_file(char * where)
{
    int status = __LOCAL_FAIL__;

    char *where_to_write = where;

    int check = 0;

    size_t message_alloc = 256;
    char system_message [message_alloc];
    char where_to_write_was[message_alloc];


    memset(system_message, 0, sizeof(system_message));
    sprintf(where_to_write_was, "%s", where_to_write);

    //char *path = "./tmp/tmp/asdf";

    //char *path = reallocarray(where, sizeof(char),

    char *parent_directory = dirname(where_to_write);
    //char *parent_directory = dirname(path);
    printf("parent_directory = %s\n", parent_directory);

    sprintf(system_message, "mkdir -vp %s", parent_directory);
    printf("system_message = %s\n", system_message);

    check = system(system_message);

    // check if directory is created or not
    if (!check)
    {
        printf("Directory created\n");
        status = __LOCAL_SUCCESS__;
    }
    else
    {
        printf("Unable to create directory\n");
        status = __LOCAL_FAIL__;
    }

    struct stat st = {0};

    if (stat(parent_directory, &st) == 0)
    {
        printf ("Parent directory exists: %s\n", parent_directory);
        status = __LOCAL_SUCCESS__;
    }
    else
    {
        printf ("SYSTEM FAIL: Parent directory does NOT exist: %s\n", parent_directory);
        status = __LOCAL_FAIL__;
    }



    return status;
}



/* Read File */
void read_aesd_file(int num_bytes_written)
{
    syslog(LOG_USER | LOG_INFO, "DEBUG CODE - FGREEN: setting up threaded timer ");
    syslog(LOG_USER | LOG_INFO, "DEBUG CODE - FGREEN: setting up local "
            "socket");


    char myIpv4[INET_ADDRSTRLEN]; // space to hold IPV4 Address.
    char myIpv6[INET6_ADDRSTRLEN]; // space to hold IPv6  Address.
    struct sockaddr_in experiment;
    char hostname[64];

    int function_return_status = 0;

    char path_to_write [sizeof(FILE_TO_WRITE_TO)];
    unsigned long num_bytes_read = 0;

    // Always assume everything fails and check for success.
    FILE *file_descriptor = NULL;


    char debug_array[2048];
    memset(debug_array, 0, sizeof(debug_array));

    int read_file_position_is = 0;

    memset(path_to_write, 0, sizeof(path_to_write));
    memset(hostname, 0, sizeof(hostname));
    memset(myIpv4, 0, sizeof(myIpv4));
    memset(myIpv6, 0, sizeof(myIpv6));


    gethostname(hostname, sizeof(hostname));
    inet_pton(AF_INET, SYSTEM_TCP_IP_ADDRESS, &(experiment.sin_addr));
    inet_ntop(AF_INET, &(experiment.sin_addr), myIpv4, INET_ADDRSTRLEN);
    syslog(LOG_USER | LOG_INFO, "DEBUG CODE - FGREEN - myIpv4 %s\n", myIpv4);

    sprintf(path_to_write, "%s", FILE_TO_WRITE_TO);
    create_temporary_file(path_to_write);

    /////////////////////////////////////////////////////
    //         Read file
    ////////////////////////////////////////////////////

    // Pointer to the working file, open it, create if necessary, and append.
    file_descriptor = fopen (FILE_TO_WRITE_TO, "a+");

    if(file_descriptor == NULL)
    {
        printf("DEBUG CODE - FGREEN: Student's error message: Failed to open "
                "file.\n");
        syslog(LOG_USER | LOG_ERR, "DEBUG CODE - FGREEN: Student's error "
                "message: ERROR: Failed to open or create file.");
    }
    else
    {
        // READ BUFFER OVER FLOW TEST
        fseek(file_descriptor, 0L, SEEK_END);
        read_file_position_is = ftell(file_descriptor);
        fseek(file_descriptor, 0L, SEEK_SET);
        // Total file size minus the number just written
        // will be the section needed to pass the test.

        char *what_to_read;

        what_to_read = (char*)malloc(read_file_position_is + 1);
        if (what_to_read == NULL)
        {
            printf("Error reallocating space for 'what_to_read'");
        }

        memset(what_to_read, 0, sizeof(num_bytes_written + 1));

        fread(what_to_read, read_file_position_is, 1, file_descriptor);

        send(client_sock, what_to_read, read_file_position_is, 0);


        printf("DEBUG CODE - FGREEN: reading file: %s\n",
                what_to_read);

        printf("DEBUG CODE - FGREEN: reading file: %s\n",
                what_to_read);
        printf("DEUBG CODE - FGREEN: debug_array: %s\n",
                        debug_array);


        syslog(LOG_USER | LOG_DEBUG, "DEBUG CODE - FGREEN: Reading (%s) to (%s): returned %lu "
                "num_bytes_read", what_to_read, FILE_TO_WRITE_TO, num_bytes_read);

        // Free pointer
        free(what_to_read);

        external_process_daemon_kill_function();
    }

    if(file_descriptor != NULL)
    {
        fflush(file_descriptor);
        fclose(file_descriptor);
    }

    if(function_return_status != 0)
    {
        syslog(LOG_USER | LOG_ERR, "DEBUG CODE - FGREEN: pthread_mutex_unlock() FAILED ");
        
    }
}



/* Listen and accept loop function */
void *serve_clients_FGREEN(void* threadp)
{
    syslog(LOG_USER | LOG_INFO, "DEBUG CODE - FGREEN: setting up threaded timer ");
    printf("DEBUG CODE - FGREEN: setting up threaded timer \n");
    syslog(LOG_USER | LOG_INFO, "DEBUG CODE - FGREEN: setting up local socket");
    printf("DEBUG CODE - FGREEN: setting up local socket\n");


    char myIpv4[INET_ADDRSTRLEN]; // space to hold IPV4 Address.
    char myIpv6[INET6_ADDRSTRLEN]; // space to hold IPv6  Address.
    struct sockaddr_in experiment;
    struct sockaddr_storage client_address_storage;
    socklen_t client_address_length;
    client_address_length = sizeof(client_address_storage);
    int port = 0;
    char hostname[64];

    int function_return_status = 0;

    char path_to_write [sizeof(FILE_TO_WRITE_TO)];
    unsigned long num_bytes_written = 0;

    // Always assume everything fails and check for success.
    FILE *file_descriptor = NULL;

    static socklen_t fromlen;

    char debug_array[2048];
    memset(debug_array, 0, sizeof(debug_array));

    unsigned long write_count_counter = 0;

    memset(path_to_write, 0, sizeof(path_to_write));
    memset(hostname, 0, sizeof(hostname));
    memset(myIpv4, 0, sizeof(myIpv4));
    memset(myIpv6, 0, sizeof(myIpv6));


    gethostname(hostname, sizeof(hostname));
    inet_pton(AF_INET, SYSTEM_TCP_IP_ADDRESS, &(experiment.sin_addr));
    inet_ntop(AF_INET, &(experiment.sin_addr), myIpv4, INET_ADDRSTRLEN);
    syslog(LOG_USER | LOG_INFO, "DEBUG CODE - FGREEN - myIpv4 %s", myIpv4);

    sprintf(path_to_write, "%s", FILE_TO_WRITE_TO);
    create_temporary_file(path_to_write);

    for(;;)
    {
        /* Listen on the socket */
        if(listen(server_sock, 5) < 0)
        {
            perror("Server: listen");
            syslog(LOG_INFO | LOG_ERR, "DEBUG CODE - FGREEN: Server Socket "
                    "'listen()' failed.");
            printf("DEBUG CODE - FGREEN: Server Socket "
                    "'listen()' failed.");
            exit(-1);
        }
        else
        {
            syslog(LOG_INFO | LOG_INFO, "DEBUG CODE - FGREEN: Server Socket "
                    "'listen()' SUCCESS.");
            printf("DEBUG CODE - FGREEN: Server Socket "
                    "'listen()' SUCCESS.");
        }

        /* Accept connections */
        if((client_sock=accept(server_sock,
                        (struct sockaddr *)&datap->thread->client_sockaddr,
                        &fromlen)) < 0)
        {
            perror("Server: accept");
            syslog(LOG_INFO | LOG_ERR, "DEBUG CODE - FGREEN: Server Socket "
                    "'accept()' failed.");
            printf("DEBUG CODE - FGREEN: Server Socket "
                    "'accept()' failed.");
            exit(-1);
        }
        else
        { 
            syslog(LOG_INFO | LOG_INFO, "DEBUG CODE - FGREEN: Server Socket "
                    "'accept()' SUCCESS.");
            printf("DEBUG CODE - FGREEN: Server Socket "
                    "'accept()' SUCCESS.");

            // HYBRID store client_sock into a better data structure until refactoring.
            datap->thread->client_data = client_sock;

            getpeername(server_sock,
                    (struct sockaddr *)&client_address_storage,
                    &client_address_length);

            // Convert system IP address to a string
            // Deal with both IPv4 and IPv6
            if (client_address_storage.ss_family == AF_INET)
            {
                struct sockaddr_in *s = (struct sockaddr_in *)
                    &client_address_storage;

                port = ntohs(s->sin_port);

                inet_ntop(AF_INET, &(s->sin_addr), myIpv4,
                        INET_ADDRSTRLEN);

                syslog(LOG_INFO | LOG_INFO, "DEBUG CODE - FGREEN: Server "
                        "Socket 'accept()' accepted from IPv4 address: %s, "
                        "port: %d", myIpv4, port);
                printf("DEBUG CODE - FGREEN: Server "
                        "Socket 'accept()' accepted from IPv4 address: %s, "
                        "port: %d\n", myIpv4, port);
            }
            else
            {
                struct sockaddr_in6 *s = (struct sockaddr_in6 *)&client_address_storage;
                port = ntohs(s->sin6_port);

                inet_ntop(AF_INET6, &(s->sin6_addr), myIpv6,
                        INET6_ADDRSTRLEN);

                syslog(LOG_INFO | LOG_INFO, "DEBUG CODE - FGREEN: Server "
                        "Socket 'accept()' accepted from IPv6 address: %s, "
                        "port: %d", myIpv6, port);
                printf("DEBUG CODE - FGREEN: Server "
                        "Socket 'accept()' accepted from IPv6 address: %s, "
                        "port: %d\n", myIpv6, port);
            }
        }


        /////////////////////////////////////////////////////
        //         Write file
        ////////////////////////////////////////////////////

        char* socket_input_char = malloc(PROGRAM_BUFFER_MAX*sizeof(char*));
        bool buffer_empty = false;
        int total_received_size = 0;
        int received_size = 0;
        int current_size = 0;

        while(!buffer_empty)
        {
            socket_input_char = (char*) (realloc(socket_input_char, 
                                write_count_counter+PROGRAM_BUFFER_MAX));

            received_size = recv(datap->thread->client_data, (socket_input_char+received_size), 
                                      PROGRAM_BUFFER_MAX, 0);
            printf ("received_size {%d}\n", received_size);
              

            if(received_size == -1)
            {
                printf("DEBUG CODE - FGREEN: Student's error message: "
                       "client_sock received_size error.\n");
                printf("DEBUG CODE - FGREEN: Student's error message: "
                       "socket_input_char {%s}\n", socket_input_char);
                syslog(LOG_USER | LOG_ERR, "DEBUG CODE - FGREEN: "
                       "Student's error message: ERROR: client_sock "
                       "received_size error.");
                exit(-1);
            } 
            
            total_received_size = write_count_counter + received_size;

            if((total_received_size > 0) 
                && (socket_input_char[total_received_size - 1] == '\n'))
            {
                buffer_empty = true;
                socket_input_char[total_received_size - 1] = '\n';
            } 
 
            current_size += PROGRAM_BUFFER_MAX;
        }
  
        if(buffer_empty)
        {
            function_return_status = pthread_mutex_lock(&sharedMemMutexSemaphore);
            if(function_return_status != 0)
            {
                syslog(LOG_USER | LOG_ERR, "DEBUG CODE - FGREEN: pthread_mutex_lock() FAILED ");
                
            }

            
            file_descriptor = fopen (FILE_TO_WRITE_TO, "a+");
            if(file_descriptor == NULL)
            {
                printf("DEBUG CODE - FGREEN: Student's error message: "
                       "Failed to open file.\n");
                syslog(LOG_USER | LOG_ERR, "DEBUG CODE - FGREEN: "
                       "Student's error message: ERROR: Write failed to "
                       "open or create file.");
            }

            if(alarm_timer)
            {
                write_timer(file_descriptor);
                alarm_timer = false;
            }


          
            printf ("DEBUG CODE - FGREEN: BEFORE \n");
            printf ("DEBUG CODE - FGREEN: num_bytes_written {%lu}\n", num_bytes_written);
            printf ("DEBUG CODE - FGREEN: socket_input_char{%s}\n", socket_input_char);
            printf ("DEBUG CODE - FGREEN: total_received_size {%d}\n", total_received_size);

            
            num_bytes_written = (unsigned long) fwrite (socket_input_char, 
                                  1, total_received_size, 
                                  file_descriptor);
            
            printf ("DEBUG CODE - FGREEN: AFTER \n");
            printf ("DEBUG CODE - FGREEN: num_bytes_written {%lu}\n", num_bytes_written);
            printf ("DEBUG CODE - FGREEN: socket_input_char{%s}\n", socket_input_char);
            printf ("DEBUG CODE - FGREEN: total_received_size {%d}\n", total_received_size);
            if (num_bytes_written == total_received_size)
            {
                printf("DEBUG CODE - FGREEN: Student's message: SUCCESS "
                       "num_bytes_written {%lu} == total_received_size {%d}."
                       "\n", num_bytes_written, total_received_size);
                syslog(LOG_USER | LOG_ERR, "DEBUG CODE - FGREEN: SUCCESS "
                       "num_bytes_written {%lu} == total_received_size {%d}."
                       , num_bytes_written, total_received_size);
            }
            else
            {
                printf("DEBUG CODE - FGREEN: Student's ERROR message: ERROR "
                       "num_bytes_written {%lu} != total_received_size {%d}."
                       "\n", num_bytes_written, total_received_size);
                syslog(LOG_USER | LOG_ERR, "DEBUG CODE - FGREEN: ERROR "
                       "num_bytes_written {%lu} != total_received_size {%d}."
                       , num_bytes_written, total_received_size);
 
                exit (-1);
            }
         
        }

        if(file_descriptor != NULL)
        {
            fflush(file_descriptor);
            fclose(file_descriptor);
        }

        function_return_status = pthread_mutex_unlock(&sharedMemMutexSemaphore);
        if(function_return_status != 0)
        {
            syslog(LOG_USER | LOG_ERR, "DEBUG CODE - FGREEN: pthread_mutex_lock() FAILED ");
            
        }


        /////////////////////////////////////////////////////
        //         Read file
        ////////////////////////////////////////////////////


        read_aesd_file(num_bytes_written);

        if(function_return_status != 0)
        {
            syslog(LOG_USER | LOG_ERR, "DEBUG CODE - FGREEN: pthread_mutex_unlock() FAILED ");
            
        }

        /////////////////////////////////////////////////////
        //         Clean Up Socket
        ////////////////////////////////////////////////////


        close(datap->thread->client_data);

        // Convert system IP address to a string
        // Deal with both IPv4 and IPv6
        if (client_address_storage.ss_family == AF_INET)
        {
            struct sockaddr_in *s = (struct sockaddr_in *)
                &client_address_storage;

            port = ntohs(s->sin_port);

            inet_ntop(AF_INET, &(s->sin_addr), myIpv4,
                    INET_ADDRSTRLEN);

            syslog(LOG_INFO | LOG_INFO, "DEBUG CODE - FGREEN: Server "
                    "Socket 'close()' closed connection from IPv4 address: %s, "
                    "port: %d", myIpv4, port);
            syslog(LOG_INFO | LOG_INFO, "Closed connection from %s"
                    , myIpv4);

        }
        else
        {
            struct sockaddr_in6 *s = (struct sockaddr_in6 *)&client_address_storage;
            port = ntohs(s->sin6_port);

            inet_ntop(AF_INET6, &(s->sin6_addr), myIpv6,
                    INET6_ADDRSTRLEN);

            syslog(LOG_INFO | LOG_INFO, "DEBUG CODE - FGREEN: Server "
                    "Socket 'close()' closed connection from IPv6 address: %s, "
                    "port: %d", myIpv6, port);
            syslog(LOG_INFO | LOG_INFO, "Closed connection from %s",
                    myIpv6);

        }

        datap->thread->finished = 1;

    } /* end for ever */

}

/* Close sockets after a Ctrl-C interrupt */

void external_interrupt_handler()
{
        syslog(LOG_USER | LOG_INFO, "DEBUG CODE - FGREEN, Server: sockets "
                "are being closed.");
        printf("DEBUG CODE - FGREEN, Server: sockets "
                "are being closed.\n");
        close(datap->thread->client_data);
        close(server_sock);

        remove_temporary_file();

    exit(-1);

}


void broken_pipe_handler()
{
    syslog(LOG_USER | LOG_INFO, "DEBUG CODE - FGREEN: "
            "broken_pipe_handler(): terminating program");
    printf("DEBUG CODE - FGREEN: "
            "broken_pipe_handler(): terminating program\n");
        close(datap->thread->client_data);
        close(server_sock);
        remove_temporary_file();

        exit(-1);
}

void terminate_program_handler()
{
    syslog(LOG_USER | LOG_INFO, "DEBUG CODE - FGREEN: "
            "terminate_program_handler(): terminating program");
    printf("DEBUG CODE - FGREEN: "
            "terminate_program_handler(): terminating program\n");

    remove_temporary_file();
    close(datap->thread->client_data);
    close(server_sock);

    exit(0);
}


int main(int argc, char ** argv)
{
    int function_status = __LOCAL_FAIL__;

    if (argc >= 2 && strcmp(argv[1], "-delete_working_file") == 0)
    {
        remove_temporary_file();
    }
//    //thread_info_t* thread_information;
//    pthread_t timer;
// 
//    init_linked_lists();
//
//    // start timer thread
//    pthread_create(&timer, (void *)0, timer_thread, (void *)0);

    char hostname[64];
    struct hostent *hp;
    struct linger opt;
    int sockarg;
    unsigned int sock_option = 1;
    unsigned int sock_length = 0;
    char *sock_option_val;


    // DEBUG CODE BELOW - FGREEN
    char myIpv4[INET_ADDRSTRLEN]; // space to hold my designated IP Address.
    char myIpv6[INET6_ADDRSTRLEN]; // space to hold IPv6  Address.
    struct sockaddr_in experiment;

    int port = 0;

    memset(hostname, 0, sizeof(hostname));
    memset(myIpv4, 0, sizeof(myIpv4));
    memset(myIpv6, 0, sizeof(myIpv6));


    inet_pton(AF_INET, SYSTEM_TCP_IP_ADDRESS, &(experiment.sin_addr));
    inet_ntop(AF_INET, &(experiment.sin_addr), myIpv4, INET_ADDRSTRLEN);

    syslog(LOG_USER | LOG_INFO, "DEBUG CODE - FGREEN: myIpv4 %s", myIpv4);
    printf("DEBUG CODE - FGREEN: myIpv4 %s", myIpv4);

    gethostname(hostname, sizeof(hostname));

    if((hp = (struct hostent*) gethostbyname(hostname)) == NULL)
    {
        size_t message_alloc = 256;
        char system_message [message_alloc];

        memset(system_message, 0, sizeof(system_message));

        sprintf(system_message, "%s", ADD_BUSYBOX_IP );
        printf("system_message = %s\n", system_message);
        syslog(LOG_USER | LOG_INFO, "DEBUG CODE - FGREEN: BusyBox does not have an"
                "IP address. Adding: '$ %s'", system_message);


        if((hp = (struct hostent*) gethostbyname("localhost")) == NULL)
        {
            syslog(LOG_INFO | LOG_ERR, "DEBUG CODE - FGREEN Error: %s host unknown.", hp->h_name);
            printf("DEBUG CODE - FGREEN Error: %s host unknown.\n", hp->h_name);

            exit(-1);
        }
        {
            syslog(LOG_USER | LOG_INFO, "DEBUG CODE - FGREEN: successfully retrieved host name: "
                    "%s", hp->h_name);
            printf("DEBUG CODE - FGREEN: successfully retrieved host name: "
                    "%s\n", hp->h_name);
        }
    }
    else
    {
        syslog(LOG_USER | LOG_INFO, "DEBUG CODE - FGREEN: successfully retrieved host name: "
               "%s", hp->h_name);
        printf("DEBUG CODE - FGREEN: successfully retrieved host name: "
               "%s\n", hp->h_name);
    }

    if((server_sock=socket(AF_INET, SOCK_STREAM, 0)) < 0)
    {
        perror("Server: socket");
        exit(-1);
    }

    bzero((char*) &server_sockaddr, sizeof(server_sockaddr));
    server_sockaddr.sin_family = AF_INET;
    server_sockaddr.sin_port = htons(DEFAULT_PORT);
    bcopy (hp->h_addr, &server_sockaddr.sin_addr, hp->h_length);

    //inet_pton(AF_INET, "10.0.10.10", &(server_sockaddr.sin_addr));
    inet_pton(AF_INET, SYSTEM_TCP_IP_ADDRESS, &(server_sockaddr.sin_addr));

    if(getsockopt(server_sock, SOL_SOCKET, SO_REUSEADDR, &sock_option, &sock_length) < 0)
    {
        syslog(LOG_USER | LOG_ERR, "DEBUG CODE - FGREEN: getsockopt() failed."
                " sock_option = %d, sock_length = %d", sock_option, sock_length);
        printf("DEBUG CODE - FGREEN: getsockopt() failed."
                " sock_option = %d, sock_length = %d\n", sock_option, sock_length);
    }
    else
    {
        syslog(LOG_USER | LOG_INFO, "DEBUG CODE - FGREEN: getsockopt() success"
                ".  sock_option = %d, sock_length = %d", sock_option, sock_length);
        printf("DEBUG CODE - FGREEN: getsockopt() success"
                ".  sock_option = %d, sock_length = %d\n", sock_option, sock_length);
    }


    sock_option_val = SYSTEM_SOCK_OPTION_VAL;
    if(setsockopt(server_sock, SOL_SOCKET, SO_REUSEADDR, sock_option_val, 4) < 0)
    {
        syslog(LOG_USER | LOG_ERR, "DEBUG CODE - FGREEN: setsockopt() failed."
                " sock_option = %d, sock_option_val = %c", sock_option,
                *sock_option_val);
        printf("DEBUG CODE - FGREEN: setsockopt() failed."
                " sock_option = %d, sock_option_val = %c\n", sock_option,
                *sock_option_val);
        exit(-1);
    }
    else
    {
        syslog(LOG_USER | LOG_INFO, "DEBUG CODE - FGREEN: setsockopt() succes"
                " sock_option = %d, sock_option_val = %s", sock_option,
                sock_option_val);
        printf("DEBUG CODE - FGREEN: setsockopt() succes"
                " sock_option = %d, sock_option_val = %s\n", sock_option,
                sock_option_val);
    }


    /* Bind address to the socket */
    if(bind(server_sock, (struct sockaddr *) &server_sockaddr,
                sizeof(server_sockaddr)) < 0)
    {
        perror("Server: bind");
        syslog(LOG_USER | LOG_ERR, "DEBUG CODE - FGREEN: bind() failed.");
        printf("DEBUG CODE - FGREEN: bind() failed.\n");
        exit(-1);
    }
    else
    {
        if (argc >= 2 && strcmp(argv[1], "-d") == 0)
        {
            syslog(LOG_USER | LOG_INFO, "DEBUG CODE - FGREEN: User passed in "
                    " the create dameon argurment '-d'.  "
                    "Entering 'create_daemon ()");
            printf("DEBUG CODE - FGREEN: User passed in "
                    " the create dameon argurment '-d'.  "
                    "Entering 'create_daemon ()\n");

            create_daemon();
        }
    }

    /* turn on zero linger time so that undelivered data is discarded when
       socket is closed
       */
    opt.l_onoff = 1;
    opt.l_linger = 0;

    sockarg = 1;

    setsockopt(server_sock, SOL_SOCKET, SO_LINGER, (char*) &opt, sizeof(opt));
    setsockopt(client_sock, SOL_SOCKET, SO_REUSEADDR, (char *)&sockarg,
            sizeof(int));
    signal(SIGINT, external_interrupt_handler);
    signal(SIGPIPE, broken_pipe_handler);
    signal(SIGTERM, terminate_program_handler);

    port = ntohs(server_sockaddr.sin_port);

    inet_ntop(AF_INET, &(server_sockaddr.sin_addr), myIpv4,
            INET_ADDRSTRLEN);

    syslog(LOG_INFO | LOG_INFO, "DEBUG CODE - FGREEN: Server Socket IPv4 is "
            "to address: %s, port: %d", myIpv4, port);
    printf("DEBUG CODE - FGREEN: Server Socket IPv4 is "
            "to address: %s, port: %d\n", myIpv4, port);


    // Create client thread
    //thread_info_t* thread_information;
    pthread_t timer;
    
    init_linked_lists();
    
    // start timer thread
    pthread_create(&timer, (void *)0, timer_thread, (void *)0);
    datap = malloc(sizeof(slist_data_t));
    datap->thread = malloc(sizeof(thread_info_t));
    datap->thread->thread_id = malloc(sizeof(pthread_t));
    
    datap->thread->finished = 0;

    SLIST_INSERT_HEAD(&head, datap, entries);
    
    pthread_create(datap->thread->thread_id, (void *)0, serve_clients_FGREEN,
                           datap->thread);

    SLIST_FOREACH(datap, &head, entries)
    {
        if(datap->thread->finished != 0) 
        {
          //free(datap);
          pthread_join(*datap->thread->thread_id, NULL);
          free(datap->thread->thread_id);
          free(datap->thread);
          SLIST_REMOVE(&head, datap, slist_data_s, entries);
        }
    }


    while (!SLIST_EMPTY(&head)) 
    {
        datap = SLIST_FIRST(&head);
        shutdown(datap->thread->client_data, SHUT_RDWR);
        close(datap->thread->client_data);
        pthread_join(*datap->thread->thread_id, NULL);
        free(datap->thread->thread_id);
        free(datap->thread);
        SLIST_REMOVE_HEAD(&head, entries);
        free(datap);
    }

    return function_status;
}
