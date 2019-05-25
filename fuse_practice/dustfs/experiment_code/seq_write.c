#include <stdlib.h>
#include <stdio.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>


// write test
int main(int argc, char* argv[])
{
    int ofp = open("1GBWrite", O_RDWR);;
    long long target_size = atoi(argv[1]);
    char c[1] = {0};

    if (ofp == -1) {
            printf("cannot open it\n");
            return -1;
    }
    for (long long i = 0; i < target_size; i++) {
            write(ofp, c, 1);
    }
    close(ofp);

    /*
	struct rusage buf;
	getrusage(RUSAGE_SELF, &buf);
	if (errno == EFAULT) {
		printf("usage points outside the accessible address \
				space,\n");
		exit(EXIT_FAILURE);
	} else if (errno == EINVAL) {
		printf("'who' is invalid.\n");
		exit(EXIT_FAILURE);
	}
	printf("\n\n **** Getrusage Results ****\n");
	printf("[user CPU time used],seconds,%ld,microseconds,%ld\n", \
					buf.ru_utime.tv_sec, buf.ru_utime.tv_usec);
	printf("[system CPU time used],seconds,%ld,microseconds,%ld\n", \
					buf.ru_stime.tv_sec, buf.ru_stime.tv_usec);
	printf("[maximum resident set size],%ld\n", buf.ru_maxrss);
	printf("[page reclaims (soft page faults)],%ld\n", buf.ru_minflt);
	printf("[page faults (hard page faults)],%ld\n", buf.ru_majflt);
	printf("[block input operations],%ld\n", buf.ru_inblock);
	printf("[block output operations],%ld\n", buf.ru_oublock);
	printf("[the number of swaps],%ld\n", buf.ru_nswap);
	printf("[the number of voluntary context switches],%ld\n", \
				buf.ru_nvcsw);
	printf("[the number of involuntary context switches],%ld\n", \
				buf.ru_nivcsw);

    */
    return 0;
}
