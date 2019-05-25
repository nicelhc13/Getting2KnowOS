#define _GNU_SOURCE

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <sched.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <asm/unistd.h>
#include <linux/perf_event.h>
#include <linux/hw_breakpoint.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/resource.h>

//{@@ Option MACRO
// @  To execute the experiments,
// @  several options should be chosen.
// @  
// @  1) Memory Access Method
// @     - Sequential Access
// @     - Random Access
// @  2) Memory Map Method
// @     - Anonymous Area
// @     - File
#define ANON_MODE 0
#define FILEB_MODE 1
#define OPT_RANDOM_ACCESS 0
#define OPT_SEQ_ACCESS 1
#define FILEB_SHARED 0
#define FILEB_PRIVATE 1
#define FILEB_PRIVATE_POPULATE 2
#define ANON_SHARED 3
#define ANON_PRIVATE 4
#define ANON_PRIVATE_POPULATE 5
// @@}

#define GB_SIZE	1<<30
#define L1D_CACHE_SIZE 1<<15 // 1024*32

#define handle_error(msg) \
	do { perror(msg); exit(EXIT_FAILURE); } while (0)

//{@@ Architecture dependent information
// @  Since sysconf uses a systemcall,
// @  calling process takes a long time.
// @  To avoid slow call and consider
// @  the characteristics of the values
// @  (All the code would use the same sizes)
// @  those are declared as global variables.
uint32_t CACHE_LINE_SIZE;
uint32_t PAGE_SIZE; 
uint64_t PHYS_PAGES; /* the # of pages of physical mem */
// @@}

//{@@ perf would follow the below structure
// @  when it reads results of grouped event counters 
// @  [NOTE] Size 3 of value is hardcoded.
// @         It should be changed as the number of 
// @         members on a group. 
struct read_format {
	uint64_t nr;
	struct {
		uint64_t value;
		uint64_t id;
	} values[4];
};
// @@}

/* random generator parameters */
long x = 1, y = 4, z = 7, w = 13;

/**
 * print_usage()
 *
 * Track and print out resource consumption statistics.
 */
void print_rusage(void) {
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
}

/**
 * read_self_maps()
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
	print_rusage();
}

/**
 * perf_event_open()
 *
 * A wrapper function for a system call.
 *
 * Return: file descriptor.
 */
long
perf_event_open(struct perf_event_attr *hw_event, \
		pid_t pid, int cpu, int group_fd, \
		unsigned long flags) {
	int ret;
	ret = syscall(__NR_perf_event_open, hw_event, \
			pid, cpu, group_fd, flags);

	return ret;
}

/**
 *  simplerand()
 *  
 * Simple, fast random number generator.
 * It will be used to generate random address.
 *
 * Return: random long value.
 */
long simplerand(void) {
	long t = x;
	t ^= t << 11;
	t ^= t >> 8;
	x = y;
	y = z;
	z = w;
	w ^= w >> 19;
	w ^= t;
	return w;
}

/**
 *  cache_flush()
 *
 * Flush cache lines.
 * Instead of using Intel flush operation,
 * bulk reading is performed.
 */
void cache_flush(void) {
	char *temp = (char *)malloc(L1D_CACHE_SIZE*sizeof(char));
	for (int i = 0; i < L1D_CACHE_SIZE; i++)
		temp[i] = simplerand(); 
	free(temp);
}

/**
 * do_mem_access()
 * @p: Temporary date. 
 * @size: Byte size of the p.
 * @a_type: Memory access method (RANDOM or SEQUENTIAL).
 *
 * Access p randomly or sequnetially. 
 * Then, access specific addresses 512 times.
 * Those addresses would stay in 512 lines of the cache memory.
 * Therefore, as the locality loop is iterated over and over,
 * cache miss would be decreased and execution time would be decreased too.
 */
void do_mem_access (char *p, int size, int a_type) {
    int i, j, count, outer, locality;
	int ws_base = 0;
	int max_base = ((size / CACHE_LINE_SIZE) - 512);
	for (outer = 0; outer < (1<<20); ++outer) {
		long r = simplerand() % max_base;
		// Pick a starting offset
		if (a_type == OPT_RANDOM_ACCESS) {
			ws_base = r;
		} else {
			ws_base += 512;
			if (ws_base >= max_base) {
				ws_base = 0;
			}
		}
		for (locality = 0; locality < 16; locality++) {
			volatile char *a;
			char c;
			for (i = 0; i < 512; i++) {
				// Working set of 512 cache lines, 32KB
				a = p + ws_base + i * CACHE_LINE_SIZE;
				if ((i%8) == 0) {
					*a = 1;
				} else {
					c = *a;
				}
			}
		}
	}
}

/**
 * lock_process()
 * @coreid: A core to be activated.
 *
 * Lock the process and activate only
 * the specified core.
 */
void lock_process(int coreid) {
	cpu_set_t mask;
	CPU_ZERO(&mask);
	CPU_SET(coreid, &mask);
	if (sched_setaffinity(0, \
			sizeof(cpu_set_t), \
			&mask) == -1) {
		perror("Fail to set CPU affinity.\n");
		assert(false);
	}	
}

/**
 * perf_set()
 * @config: Type specific configuration.
 * @is_leader: If it is a leader, 1. Otherwise, 0.
 * @leader_fd: If want to make a group, 
 *             then should pass a leader file descriptor.
 * @id: Event id to be registered.
 *
 * Configure a perf_event_attr structure.
 * [NOTE] if a leader calls this function,
 *        the leader_fd should be -1 or dummy values.
 * 
 * Return: File descriptor
 */
int perf_set(int config, int is_leader, \
				int leader_fd, uint64_t *id) {
	struct perf_event_attr pe;
	int fd;
	int group = is_leader?-1:leader_fd; 
	memset(&pe, 0, sizeof(struct perf_event_attr));
	pe.size = sizeof(struct perf_event_attr);
	pe.type = PERF_TYPE_HW_CACHE;
	pe.config = config;
	pe.disabled = is_leader?1:0;
	pe.exclude_kernel = 1;
	pe.exclude_hv = 1;
	pe.read_format = PERF_FORMAT_GROUP | \
						PERF_FORMAT_ID;
	fd = perf_event_open(&pe, 0, 0, group, 0);
	if (fd == -1) {
		printf("Error: %s\n", strerror(errno));
		exit(EXIT_FAILURE);
	}
	ioctl(fd, PERF_EVENT_IOC_ID, id);
	return fd;
}

/**
 * init_perf()
 * @c_acc_id: An id obj for cache access event counter.
 * @c_miss_id: An id obj for cache miss event counter.
 * @tlb_acc_id: An id obj for TLB access event counter.
 * @tlb_miss_id: An id obj for TLB miss event counter.
 *
 * Prepare perf in order to measure HW events.
 * This function will call perf_set() to process detail setting.
 *
 * Return: A leader file descriptor. 
 */
int init_perf(uint64_t *c_acc_id, uint64_t *c_miss_id, \
			uint64_t *tlb_acc_id, uint64_t *tlb_miss_id) {
	/* cache access */
	int leader = perf_set(PERF_COUNT_HW_CACHE_L1D | \
					(PERF_COUNT_HW_CACHE_OP_READ << 8) | \
					(PERF_COUNT_HW_CACHE_RESULT_ACCESS << 16),
					1 /* yes, leader */, \
					-1, c_acc_id);

	/* cache miss */
	perf_set(PERF_COUNT_HW_CACHE_L1D | \
			(PERF_COUNT_HW_CACHE_OP_READ << 8) | \
			(PERF_COUNT_HW_CACHE_RESULT_MISS << 16),
			0 /* no, member */, \
			leader, c_miss_id);

	/* tlb access */
	perf_set(PERF_COUNT_HW_CACHE_DTLB | \
			(PERF_COUNT_HW_CACHE_OP_READ << 8) | \
			(PERF_COUNT_HW_CACHE_RESULT_ACCESS << 16),
			0 /* no, member */, \
			leader, tlb_acc_id);

	/* tlb miss */
	perf_set(PERF_COUNT_HW_CACHE_DTLB | \
			(PERF_COUNT_HW_CACHE_OP_READ << 8) | \
			(PERF_COUNT_HW_CACHE_RESULT_MISS << 16),
			0 /* no, member */, \
			leader, tlb_miss_id);
	return leader;
} 

/**
 * init_perf_wrpr()
 * @c_acc_id: An id obj for cache access event counter.
 * @c_miss_id: An id obj for cache miss event counter.
 * @tlb_acc_id: An id obj for TLB access event counter.
 * @tlb_miss_id: An id obj for TLB miss event counter.
 *
 * Prepare perf in order to measure HW events.
 * This function will call perf_set() to process detail setting.
 * This is exploited to calculate write counts and prefetch counts
 * since the number of HW event counter is limited.
 *
 * Return: A leader file descriptor. 
 */
int init_perf_2nd(uint64_t *c_acc_id, uint64_t *c_pre_acc_id, \
			uint64_t *c_pre_miss_id, uint64_t *null) {
	/* cache write access */
	int leader = perf_set(PERF_COUNT_HW_CACHE_L1D | \
					(PERF_COUNT_HW_CACHE_OP_WRITE << 8) | \
					(PERF_COUNT_HW_CACHE_RESULT_ACCESS << 16),
					1 /* yes, leader */, \
					-1, c_acc_id);

	/* cache prefetch access */
	//perf_set(PERF_COUNT_HW_CACHE_L1D | \
	//		(PERF_COUNT_HW_CACHE_OP_PREFETCH << 8) | \
	//		(PERF_COUNT_HW_CACHE_RESULT_ACCESS << 16),
	//		0 /* no, member */, \
	//		leader, c_pre_acc_id);

	/* cache prefetch access */
	perf_set(PERF_COUNT_HW_CACHE_L1D | \
			(PERF_COUNT_HW_CACHE_OP_PREFETCH << 8) | \
			(PERF_COUNT_HW_CACHE_RESULT_MISS << 16),
			0 /* no, member */, \
			leader, c_pre_miss_id);

	return leader;
}

/**
 * start_perf()
 * @leader_fd: Leader file descriptor.
 *
 * Start perf: measure specified HW events.
 */
void start_perf(int leader_fd) {
	ioctl(leader_fd, PERF_EVENT_IOC_RESET, PERF_IOC_FLAG_GROUP);
	ioctl(leader_fd, PERF_EVENT_IOC_ENABLE, PERF_IOC_FLAG_GROUP);
}

/**
 * end_perf()
 * @leader_fd: Leader file descriptor.
 *
 * End perf: Finalize specified HW events measurements.
 */
void end_perf(int leader_fd) {
	ioctl(leader_fd, PERF_EVENT_IOC_DISABLE, PERF_IOC_FLAG_GROUP);
}

/**
 * print_perf()
 * @c_acc_id: An id obj for cache access event counter.
 * @c_miss_id: An id obj for cache miss event counter.
 * @tlb_acc_id: An id obj for TLB access event counter.
 * @tlb_miss_id: An id obj for TLB miss event counter.
 * @leader_fd: Leader file descriptor.
 *
 * Print out perf results.
 */
void print_perf(uint64_t *c_acc_id, uint64_t *c_miss_id, \
			uint64_t *tlb_acc_id, uint64_t *tlb_miss_id, int leader_fd) {
	char buf_tmp[4096];
	struct read_format* rf = (struct read_format *) buf_tmp;

	printf("**** Perf Results ****\n");
	read(leader_fd, buf_tmp, sizeof(buf_tmp)); 
	for (int i = 0; i < rf->nr; i++) {
		int id = rf->values[i].id;
		uint64_t value = rf->values[i].value;
		if (id == *c_acc_id) {
			printf("Data Cache Access, %ld\n", value);
		} else if (id == *c_miss_id) {
			printf("Data Cache Miss, %ld\n", value);
		} else if (id == *tlb_acc_id) {
			printf("Data TLB Access, %ld\n", value);
		} else if (id == *tlb_miss_id) {
			printf("Data TLB Miss, %ld\n", value);
		}
	}	
}

/**
 * perf_event_test()
 * @a_type: Memory access type.
 *
 * Access memory randomly or sequentially.
 * Then, undertand HW usage results.
 */
void perf_event_test(int a_type) {
	int leader_fd;
	char* buf;
	ssize_t s;
	uint64_t c_acc_id, c_miss_id, tlb_acc_id, tlb_miss_id;
	char* p; 

	/* Only allow specified core to proceed the process */
	lock_process(0);

	p = (char *) malloc(sizeof(char)*GB_SIZE);
	/* Clear cache lines */
	cache_flush();

	leader_fd = init_perf(&c_acc_id, &c_miss_id, \
								&tlb_acc_id, &tlb_miss_id);
	//leader_fd = init_perf_2nd(&c_acc_id, &c_miss_id, \
	//							&tlb_acc_id, &tlb_miss_id);

	start_perf(leader_fd);

	/* Test memory access performance */
	do_mem_access(p, GB_SIZE, a_type);

	/* Get and print out perf results */
	end_perf(leader_fd);
	
	/* Get and print out resource usage information */
	print_perf(&c_acc_id, &c_miss_id, \
				&tlb_acc_id, &tlb_miss_id, leader_fd);

	print_rusage();

	free(p);
}

/**
 * get_mem_size()
 *
 * Calculate actual DRAM size.
 *
 * Return: physical DRAM size (Byte).
 */ 
long get_mem_size(void) {
	return PHYS_PAGES*PAGE_SIZE; 
}

/**
 * compete_for_memory()
 *
 * Infinite loop for child process.
 * Keep accessing a memory space across entire DRAM and
 * interfere parent process memory access.
 */
void compete_for_memory(void) {
	long mem_size = get_mem_size();
	printf("Total memsize is %3.2f GBs\n", (double)mem_size/(1024*1024*1024));
	fflush(stdout);
	char* p = mmap(NULL, mem_size, PROT_READ | PROT_WRITE,
                MAP_NORESERVE|MAP_PRIVATE|MAP_ANONYMOUS, -1, (off_t) 0);
	if (p == MAP_FAILED) {
		perror("Failed anon MMAP competition");
		exit(EXIT_FAILURE);
	}

	int i = 0;
	while(1) {
		volatile char *a;
		long r = simplerand() % (mem_size/PAGE_SIZE);
		char c;
		if(i >= mem_size/PAGE_SIZE) {
			i = 0;
		}
		// One read and write per page
		//a = p + i * page_sz; // sequential access
		a = p + r * PAGE_SIZE;
		c += *a;
		if((i%8) == 0) {
			*a = 1;
		}
		i++;
	}

	/* write back to a disk */
	msync(p, mem_size, MS_SYNC);
	
	munmap(p, mem_size);
}

/**
 * mmap_test_start()
 * @m_type: Mmap type. [FILEB_MODE | ANONYMOUS_MODE]
 * @mo_type: Mmap detail option type.
 *           [FILEB_SHARED | FILEB_PRIVATE | FILEB_PRIVATE_POPULAR]
 * @a_type: Memory access method. 
 *
 * mmap() test.
 * Execute mmap() with specified options and test performances.
 */ 
void mmap_test_start(int m_type, int mo_type, int a_type) {
	int fd, flags, leader_fd;
	struct stat sb;
	off_t offset, pa_offset;
	char* fname = "test1_input";
	char* buf;
	ssize_t s;
	int length = GB_SIZE;
	uint64_t c_acc_id, c_miss_id, tlb_acc_id, tlb_miss_id;
	
	/* Clear cache lines */
	cache_flush();

	/* Only allow specified core to proceed the process */
	lock_process(0);

	if (m_type == FILEB_MODE) {
	/* 
	   @SET CONFIGURATION FOR MAPPING FILE-BACKED MEMORY	
	   File descriptor and offset are
	   only used for
	   file-backed memory option. */

		fd = open(fname, O_RDWR);
		if (fd == -1) {
			handle_error("open");
			exit(EXIT_FAILURE);
		}
		if (fstat(fd, &sb) == -1) handle_error("fstat");
		/* To obtain file size */

		offset = 0;
		pa_offset = offset & ~(- 1);
		/* Offset for mmap() must be page aligned */

		if (offset >= sb.st_size) {
			fprintf(stderr, "offset is past end of file\n");
			exit(EXIT_FAILURE);
		}

		if (offset + length > sb.st_size)
			length = sb.st_size - offset;

		if (mo_type == FILEB_SHARED) {
			flags = MAP_SHARED;
		}
		else if (mo_type == FILEB_PRIVATE) {
			flags = MAP_PRIVATE;
		}
		else if (mo_type == FILEB_PRIVATE_POPULATE) {
		/* MAP_POPULATE can work with MAP_PRIVATE */
			flags = MAP_POPULATE | MAP_PRIVATE;
		}
	} else if (m_type == ANON_MODE) {
	/* 
	   @SET CONFIGURATION FOR MAPPING ANONYMOUS MEMORY	
	   Anonymous mmap does not need
	   offset or file descriptor. */

		length = GB_SIZE;
		offset = 0;
		pa_offset = 0;
		fd = -1;
		/* MAP_ANONYMOUS can work with MAP_SHARED */
//		flags = MAP_ANONYMOUS | MAP_SHARED; 
//		flags = MAP_ANONYMOUS | MAP_SHARED | MAP_NORESERVE;

		flags = MAP_ANONYMOUS;
		if (mo_type == ANON_SHARED) {
			flags |= MAP_SHARED;
		}
		else if (mo_type == ANON_PRIVATE) {
			flags |= MAP_PRIVATE;
		}
		else if (mo_type == ANON_PRIVATE_POPULATE) {
		/* MAP_POPULATE can work with MAP_PRIVATE */
			flags |= MAP_POPULATE | MAP_PRIVATE;
		}
	}

	/* MMAP could be either Anonymous memory mapping
  	   or file mapping. Proper options are set by 
	   the upper phases. */ 
	buf = mmap(NULL, (length + offset - pa_offset), \
			(PROT_READ | PROT_WRITE), \
	/* Require PROT_WRITE in order to perform memset */
			flags, fd, pa_offset);
	if (buf == MAP_FAILED) {
		handle_error("mmap");
		exit(EXIT_FAILURE);
	}
	
	leader_fd = init_perf(&c_acc_id, &c_miss_id, \
								&tlb_acc_id, &tlb_miss_id);
//	leader_fd = init_perf_2nd(&c_acc_id, &c_miss_id, \
//								&tlb_acc_id, &tlb_miss_id);

	start_perf(leader_fd);

	memset(buf, '-', length);
	/* write back to a disk */
	msync(buf, length, MS_SYNC);

	/* Test memory access performance */
	do_mem_access(buf, length, a_type);

	/* Get and print out perf results */
	end_perf(leader_fd);
	
	/* Get and print out resource usage information */
	print_perf(&c_acc_id, &c_miss_id, \
				&tlb_acc_id, &tlb_miss_id, leader_fd);

	munmap(buf, length + offset - pa_offset);

	close(fd);
	
	print_rusage();
}

/**
 * mmap_test()
 * @f_type: Perf flag type.
 * @a_type: Memory access type.
 *
 * Start point of mmap test.
 * Memory competition is not considered.
 */ 
void mmap_test(int f_type, int a_type) {
	if (f_type == 0 || f_type == 1 || f_type == 2)
		mmap_test_start(FILEB_MODE, f_type, a_type);
	else if (f_type == 3 || f_type == 4 || f_type == 5)
		mmap_test_start(ANON_MODE, f_type, a_type);
}

/**
 * option_description()
 * @fname: Current process name.
 *
 * Available options are printed.
 */
void option_description(char *fname) {
	printf("Usage: %s [-p problem_number] [-f mmap flag]"
			" [-a memory access method]\n", \
					fname);
	printf("\n++ p options ++++\n");
	printf(" Select a type of the experiment you want to perform.\n");
	printf("\t0: print /proc/self/maps\n");
	printf("\t1: perf_event_open test\n");
	printf("\t2: mmap test\n");
	printf("\t3: mmap test with memory competition\n");
	printf("\n++ f options ++++\n");
	printf(" Select a flag type for mmap.\n");
	printf(" [NOTE] it is only valid option for");
	printf(" `-p 2` or `-p 3` (mmap test).\n");
	printf("        In addition, with `-p 2` and `-p 3` options,");
	printf(" it must be selected.\n");
	printf("\t0: FIE_BACKED + MAP_SHARED\n");
	printf("\t1: FIE_BACKED + MAP_PRIVATE\n");
	printf("\t2: FIE_BACKED + MAP_PRIVAE + MAP_POPULATE\n");
	printf("\t3: ANONYMOUS + MAP_SHARED\n");
	printf("\n++ a options ++++\n");
	printf(" Select memory access type.\n");
	printf("\t0: Random access\n");
	printf("\t1: Sequential access\n");
}

int main(int argc, char **argv) {
	int opt, ptype = -1, ftype = -1, atype = -1;
	pid_t pid;

	CACHE_LINE_SIZE = sysconf(_SC_LEVEL1_DCACHE_LINESIZE);
	PAGE_SIZE = sysconf(_SC_PAGE_SIZE);
	PHYS_PAGES = sysconf(_SC_PHYS_PAGES);
	
	while ((opt = getopt(argc, argv, "p:f:a:")) != -1) {
		switch (opt) {
		case 'p':
			ptype = atoi(optarg);
			printf("Selected problem type: %d\n", ptype);
			break;
		case 'f':
			ftype = atoi(optarg);
			printf("Selected flag type: %d\n", ftype);
			break;
		case 'a':
			atype = atoi(optarg);
			printf("Selected memory access type: %d\n", atype);	
			break;
		case 'h':
		default:
			option_description(argv[0]);
			exit(EXIT_FAILURE);
		}
	}
	
	if (ptype == -1 || (ptype == 2 && ftype == -1) || 
				(ptype == 3 && ftype == -1)) {
		option_description(argv[0]);
		exit(EXIT_FAILURE);
	}
	
	switch(ptype) {
	case 0:
		read_self_maps();
		break;
	case 1:
	/* section: perf_event_open */
		perf_event_test(atype);
		break;
	case 2:
	/* section: measuring memory access behavior 
				first step: without competition	*/
		mmap_test(ftype, atype);
		break;
	case 3:
	/* section: measuring memory access behavior
				final step: with competition 
				with cloned process */ 
		pid = fork();
		if (pid == -1) {
			printf("fork failed\n");
			exit(EXIT_FAILURE);
		} else if (pid == 0) {
		/* child process section */
			compete_for_memory();
		} else {
		/* parent process section */
			printf("mmap_test\n");
			mmap_test(ftype, atype);
			/* when parent process finishes its job,
			   child process is killed. */
			kill(pid, SIGKILL);
		}
		break;
	case 4:
		compete_for_memory();
		break;

	}
	
	return 0;
}
