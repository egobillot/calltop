#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>

#define RSIZE 1

int main(int argc, char ** argv){
    void * mem;
    int r=0;
    int fd;
    mem = malloc(RSIZE);
    fd = open("/dev/null", O_RDONLY);
    
    // generate write with error
    // I do not want to write, just generate syscall.
    while(r < (long)1000*1000*10 * RSIZE) {
        r-=write(fd, mem, 1); // return EBADF = -1
    }
}
