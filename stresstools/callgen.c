#include <sys/types.h>
#include <sys/stat.h>
#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main(int argc, char **argv)
{
    struct stat sb;
    int i = 0;
    while (i++<10000000){
        /* if (stat(".", &sb) == -1) {
            perror("stat");
            exit(EXIT_SUCCESS);
        }*/
        stat(".", &sb);
    }
}