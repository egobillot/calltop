#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>

#define RSIZE 1

int main(int argc, char ** argv){
    void * mem;
    long r=0;
    int fd;
    mem = malloc(RSIZE);
    fd = open("/dev/zero", O_RDONLY);
    while(r < (long)1000*1000*10 * RSIZE) {
        r+=read(fd, mem, RSIZE);
    }
}
