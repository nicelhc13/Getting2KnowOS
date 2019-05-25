#include <stdio.h>

#define BUCKET_SIZE 1<<25
int bucket[BUCKET_SIZE];

int main(void)
{
    int i;
    for (i = 0; i < BUCKET_SIZE; i++)
        bucket[0] = i;

    return 0;
}
