#include <stdlib.h>
#include <stdio.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <unistd.h>
#include <fcntl.h>


// write and read test
int main(int argc, char* argv[])
{
    long long target_size = atoi(argv[1]);
    char buf[512];
    char c[1] = {'*'};
    int iter = atoi(argv[2]);
    int ofp = open("1GBWrite", O_RDWR);

    if (ofp == -1) {
            printf("cannot open it\n");
            return -1;
    }

    for (int i = 0; i < iter; i++)
            for (long long i = 0; i < target_size; i++) {
                write(ofp, c, 1); 
            }
    close(ofp);

    ofp = open("1GBWrite", O_RDONLY);
    if (ofp == -1) {
            printf("cannot open it\n");
            return -1;
    }

    for (long long i = 0; i < target_size-512; i++) {
            for (int j = 0; j < 512; j++)
                read(ofp, buf, 512);
            for (int j = 0; j < 16; j++) {
                volatile char *a;
                char c;
                for (int k = 0; k < 512; k++) {
                    a = &buf[k];
                }
            }
    }
    
    close(ofp);
    return 0;
}
