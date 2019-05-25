#include <stdio.h>

#define BUCKET_SIZE 1<<25
int bucket[BUCKET_SIZE];
int i,j;
int main(void)
{
    for (i = 0; i < BUCKET_SIZE; i++)
        j = bucket[i];

    return 0;
}
