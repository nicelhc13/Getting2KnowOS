#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>


// read test
int main(int argc, char* argv[])
{
    int ofp;
    long long target_size = atoi(argv[1]);
    char c[1];

    ofp = open("1GBWrite", O_RDONLY);
    if (ofp == -1) {
            printf("cannot open it\n");
            return -1;
    }
    for (long long i = 0; i < target_size; i++) {
            read(ofp, c, 1); 
    }
    close(ofp);

    return 0;
}
