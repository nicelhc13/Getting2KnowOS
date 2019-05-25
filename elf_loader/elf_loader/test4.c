#include <stdio.h>
#include <stdlib.h>

#define BUCKET_SIZE 1<<25
int main(void)
{
    char* test;
    int i;
    for (i = 0; i < BUCKET_SIZE; i++) {
        test = (char *) malloc (100*sizeof(char));
        free(test);
    }

    return 0;
}
