#include <stdio.h>
/* read_self_maps()
 *
 * Read virtual memory space of the current process.
 */
void read_self_maps() {
    FILE* fp = fopen("/proc/self/maps", "r");
    char buf[1024];

    while (!feof(fp)) {
        printf("%s", fgets(buf, 1024, (FILE *)fp));
    }
    
    fclose(fp);
}

int main(int argc, char **argv, char** envp) {
    // printf("argv:%x\n", *argv);
    // read_self_maps();
    printf("Hello\n PRESS ENTER TO TERMINATE\n");
    return 0;
}
