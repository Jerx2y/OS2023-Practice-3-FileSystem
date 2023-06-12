#include <fcntl.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
int main(){
    
    pid_t pid;
    // OPEN FILES
    int fd;
    fd = open("test.txt" , O_RDWR | O_CREAT | O_TRUNC);
    if (fd == -1)
    {
        /* code */
		fprintf(stderr, "fail on open test.txt\n");
		return -1;
    }
    //write 'hello fcntl!' to file

    /* code */

    if (write(fd, "hello fcntl!", 12) != 12) {
        fprintf(stderr, "fail on write to test.txt\n");
        return -1;
    }

    // DUPLICATE FD

    /* code */
    
    int dfd = fcntl(fd, F_DUPFD);

    pid = fork();

    if(pid < 0){
        // FAILS
        printf("error in fork");
        return 1;
    }
    
    struct flock fl;

    if(pid > 0){
        // PARENT PROCESS
        //set the lock

        fcntl(fd, F_SETLKW, &fl);

        //append 'b'
        lseek(fd, 0, SEEK_END);
        if (write(fd, "b", 1) != 1) {
            fprintf(stderr, "fail on write to test.txt\n");
            return -1;
        }
        
        //unlock
        fcntl(fd, F_SETLKW, &fl);

        sleep(3);

        char str[20];
        lseek(fd, 0, SEEK_SET);

        if (read(fd, str, 20) != 15) {
            fprintf(stderr, "fail on read to test.txt\n");
            return -1;
        }

        printf("%s", str); // the feedback should be 'hello fcntl!ba'
        
        exit(0);

    } else {
        // CHILD PROCESS
        sleep(2);
        //get the lock
        fcntl(dfd, F_SETLKW, &fl);
        
        //append 'a'
        lseek(dfd, 0, SEEK_END);

        if (write(dfd, "a", 2) != 2) {
            fprintf(stderr, "fail on write to test.txt\n");
            return -1;
        }

        fcntl(dfd, F_SETLKW, &fl);

        exit(0);
    }
    close(fd);
    return 0;
}