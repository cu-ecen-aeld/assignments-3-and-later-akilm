#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>
#include <syslog.h>

#define FUN_FAILURE (-1)

/* file_create: create a file descriptor associates with the specific file name. */
int file_create(const char *file_name);

/* file_write: write a string to a file through fd. */
void file_write(int fd, const char *str);

/* file_close: free the resource */
void file_close(int fd);


int file_create(const char *file_name) {

    // file descriptor number
    int fd;

    // Mode permission bits
    mode_t mode = S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH;

    fd = open(file_name, O_CREAT | O_WRONLY, mode);
    if (fd == FUN_FAILURE) {
        printf("func %s fail, errno: %d\n", __func__, errno);
        printf("error: %s\n", strerror(errno));
        syslog(LOG_USER | LOG_ERR, "%s", strerror(errno));
        closelog();
        exit(EXIT_FAILURE);
    }

    return fd;
}


void file_write(int fd, const char *str) {

    int retval;

    retval = write(fd, (const void *) str, strlen(str));

    if (retval == FUN_FAILURE) {
        printf("func %s fail, errno: %d\n", __func__, errno);
        printf("error: %s\n", strerror(errno));
        syslog(LOG_USER | LOG_ERR, "%s", strerror(errno));
        file_close(fd);
        closelog();
        exit(EXIT_FAILURE);
    }

    return;	
}

void file_close(int fd) {

    if (close(fd) == FUN_FAILURE) {
        printf("func %s fail, errno: %d\n", __func__, errno);
        printf("error: %s\n", strerror(errno));
        syslog(LOG_USER | LOG_ERR, "%s", strerror(errno));
        closelog();
        exit(EXIT_FAILURE);
    }
    
    return;
}

int main(int argc, char *argv[]) {

    // The two arguments
    const char *file_name = NULL;
    const char *str = NULL;

    /* fd: File descriptor number */
    int fd;
    /* connect to the system logger. Setup syslog logging for this utility */
    openlog(NULL, LOG_PID, LOG_USER);

    /* The default argc value is 1, but we will pass in two arguments so the argc will equal 3. */	
    if (argc < 3) {
        printf("Please pass in the correct arguments.\n");
        syslog(LOG_USER | LOG_ERR, "Please pass in the correct arguments.");
        closelog();
        exit(EXIT_FAILURE);
    } else {
       file_name = argv[1];
       str = argv[2];
    }

    fd = file_create(file_name);
    file_write(fd, str);
    /* Use the syslog capability to write a message. */
    syslog(LOG_USER | LOG_DEBUG, "Writing %s to %s", str, file_name);

    file_close(fd);
    closelog();

    return 0;
}
