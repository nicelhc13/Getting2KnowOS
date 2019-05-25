#include <errno.h>
#include <fcntl.h>
//#include <libelf.h>
#include <elf.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/resource.h>

#define DEBUG 1
#define PRED_OPT 0

#define PAGE_SIZE 	 getpagesize()
#define ALIGN	 (PAGE_SIZE-1)
#define PAGE_ALIGN(p) (((p)+(ALIGN)) & ~(ALIGN))
#define PAGE_OFFSET(p) ((p) & (ALIGN))
#define PAGE_START(p) ((p) & ~(ALIGN))

typedef int bool;
enum { false, true };

unsigned long base_addr = NULL;
unsigned long predict_level = 0;
unsigned long predict_addr = 0;
unsigned long consumed_memory = 0;
int fd;
void *buf;
void *prg_hdr;
extern char **environ;

/**
 * read_file()
 * @f_name: File name.
 * @buf: Mapped memory for file.
 * @f_size: File size to be read.
 *
 * Read specified file and check whether it successfully reads or not.
 */
bool read_file(const char* f_name, void **buf, size_t *f_size)
{
    struct stat st;
    void *tmp_buf;
    off_t pos = 0;
    ssize_t read_bytes;

    if (DEBUG)
    printf("Start reading file.\n");

    fd = open(f_name, O_RDONLY, 0);
    if (fd < 0) {
        fprintf(stderr, "Failed file open\n");
        return false;
    }

    if (stat(f_name, &st) == -1) {
        fprintf(stderr, "Failed to get file information (stat)\n"); 
        return false;
    }

    /* Get file size */
    tmp_buf = malloc(st.st_size);
    memset(tmp_buf, 0, st.st_size);
    if (tmp_buf == NULL) {
        fprintf(stderr, "Failed to malloc()\n");
        return false;
    }

    /* It is possible that a file exceeds read limits */
    while (pos < st.st_size) {
        read_bytes = read(fd, tmp_buf + pos, st.st_size - pos);
        if (read_bytes <= 0) {
            fprintf(stderr, "Failed to read specified file.\n");
            return false;
        }
        pos += read_bytes;
    }

    *buf = tmp_buf;
    *f_size = st.st_size;

    return true;
free:
    free(tmp_buf);
    //close(*fd);
    return false;
}

/*
 *  read_self_maps()
 *
 * Read virtual memory space of the current process.
 */
void read_self_maps() {
    FILE* fp = fopen("/proc/self/maps", "r");
    char buf[1024];

    while (!feof(fp)) {
        printf("%s", fgets(buf, 1024, (FILE *)fp));
    }
    
    printf("\n");
    fclose(fp);
}

/*
 * process_predict()
 * @ addr: Mapped address for BSS.
 * @ prot
 * @ flag
 *
 * It predicts like a 1-bit branch prediction but in this case three states.
 * Just increase counter whenver prediction is correct.
 * Otherwise, decrease it.
 * Depending on the counter, performs mmap() for next pages.
 */
void process_predict(unsigned long addr, int prot, int flag) {
    unsigned long offset = PAGE_SIZE;          
    unsigned long* pre_mapped;

    if (predict_addr == addr) {
        predict_level++;
    } else {
        if (predict_level > 0)
            predict_level--;
    }

    if (predict_level >= 1) {
    /* Prediction Level 1. mapped one more page */
        pre_mapped = mmap((void *) (addr + PAGE_SIZE),
            PAGE_SIZE, prot, flag, -1, 0);
        if (pre_mapped == NULL)
                fprintf(stderr, "[PREDICT] failed to mmap()\n");
        consumed_memory += PAGE_SIZE;
        if (DEBUG)
                printf("Consumed Memory; %ld\n", consumed_memory);


        if (DEBUG)
        fprintf(stderr, "[mmap(): Prediction #1]\n\tStart address: %lx\n" 
                "\tMapped size: %x\n\tOffset: %x\n\n", (uint64_t)pre_mapped, PAGE_SIZE, 0);
    }

    //if (predict_level >= 2) {
    /* Prediction Level 2. mapped two pages */
    /*
        pre_mapped = mmap((void *) (addr + PAGE_SIZE),
            PAGE_SIZE, prot, flag, -1, 0);
        offset += PAGE_SIZE;
        if (pre_mapped == NULL)
                fprintf(stderr, "[PREDICT] failed to mmap()\n");
        consumed_memory += PAGE_SIZE;

        if (DEBUG)
                printf("Consumed Memory; %ld\n", consumed_memory);
        if (DEBUG)
        fprintf(stderr, "[mmap(): Prediction #2]\n\tStart address: %lx\n" 
                "\tMapped size: %x\n\tOffset: %x\n\n", (uint64_t)pre_mapped, PAGE_SIZE, 0);
    } */

    predict_addr = addr + offset;
}

/**
 * load_image()
 * @bin: File mapped area.
 * @v_addr: If sigsev is occurred, handler requests new area. It is for that.
 * @is_start: We perform mmap for initial phase or segfault phase.
 *
 * Traverse memory mapping file, check each ELF header, mmaping properly.
 * When SIGSEV calls this function, it carries out mapping fo BSS area.
 *
 * Return: entry point
 */
void *load_image(void *bin, uint64_t r_vaddr, int is_start, uint64_t loader_addr)
{
    int i, error;
    void *mapped_area, *start, *segment_start;
    unsigned long min_va = (unsigned long) -1, max_va = 0;
    unsigned long source_addr, dest_addr;
    Elf64_Ehdr *hdr  = NULL;
    Elf64_Phdr *phdr = NULL, *elf_ppnt;
    Elf64_Shdr *shdr = NULL;
    Elf64_Sym  *sysm = NULL;

    hdr = (Elf64_Ehdr *) bin;
    phdr = (Elf64_Phdr *) (bin + hdr->e_phoff);
    shdr = (Elf64_Shdr *) (bin + hdr->e_shoff);
    bool is_first = true;
    bool invalid = true; /* Check whether the request is correct or not */

    if ((uint64_t *)loader_addr != NULL
            && (uint64_t) hdr->e_entry == loader_addr) {
        fprintf(stderr, "[WARNING!]\nMemory Start Addresses of loader"
                " and loaded application are overlapped.\n");
        fprintf(stderr, "Exit the loader.. \n");
        exit(1);
    }

    for (i = 0; i < hdr->e_phnum; i++) {
            if (phdr[i].p_type != PT_LOAD) {
                    continue;
            }

            if (!phdr[i].p_filesz) {
                    fprintf(stderr, "File size is 0\n");
                    continue;
            }
  
            /* Protect and mapping option */
            int prot = PROT_READ;
            if (phdr[i].p_flags & PF_W) prot |= PROT_WRITE;
            if (phdr[i].p_flags & PF_X) prot |= PROT_EXEC;

            int flag = MAP_PRIVATE | MAP_DENYWRITE;
            //flag |= MAP_FIXED;
            if (hdr->e_type == ET_EXEC) flag |= MAP_FIXED;

            unsigned long mstart_addr;
            unsigned long moffset;
            unsigned long msize;

            if (is_start) { // First map everything except bss
                mstart_addr = PAGE_START(phdr[i].p_vaddr);
                moffset = phdr[i].p_offset - PAGE_OFFSET(phdr[i].p_vaddr);
                msize = PAGE_ALIGN((phdr[i].p_filesz)+PAGE_OFFSET(phdr[i].p_vaddr));
            } else { // BSS
                if (DEBUG)
                fprintf(stderr, "[BSS mapping]\n");
                mstart_addr = PAGE_START(r_vaddr);
                msize = PAGE_SIZE;
                moffset = 0;
                flag |= MAP_ANONYMOUS;
                mapped_area = mmap((void *) mstart_addr,
                                PAGE_SIZE,
                                PROT_READ | PROT_WRITE | PROT_EXEC, 
                                MAP_PRIVATE | MAP_FIXED | MAP_ANONYMOUS, -1, 0);
                memset((void *) mstart_addr, 0, PAGE_SIZE);
                munmap((void*) mstart_addr, PAGE_SIZE);

            }

            mapped_area = mmap((void *) mstart_addr,
                            msize, prot, flag, fd, moffset);

            if (!mapped_area) {
                fprintf(stderr, "[SEGMENTS] failed to mmap()\n");
            }
            consumed_memory += msize;
            if (DEBUG)
                    printf("Consumed Memory; %ld\n", consumed_memory);

            if (DEBUG)
            fprintf(stderr, "[mmap(): Segments]\n\tStart address: %lx\n" 
                            "\tMapped size: %lx\n\tOffset: %lx\n\n", (uint64_t) mapped_area,
                                                 (uint64_t) PAGE_SIZE, (uint64_t) moffset);
//          read_self_maps();

            if (PRED_OPT && !is_start) /* For BSS mapping, apply prediction optimization */
                process_predict(mstart_addr, prot, flag);

            invalid = false;
            if (is_first) {
                    prg_hdr = mapped_area + hdr->e_phoff;
                    base_addr = (unsigned long) mapped_area;
                    is_first = false;
            }
    }

    if (invalid) raise(SIGSEGV);
    return (void *)(hdr->e_entry);
}

/**
 * setup_stack()
 * @bin: Same with load_image()
 * @argc
 * @argv
 * @envp
 *
 * Construct stack for loaded program.
 * Reuse a loader's stack information.
 *
 * Return: Stack address. 
 */ 
void* setup_stack(void *bin, int argc, char **argv, char **envp)
{
    Elf64_Ehdr *hdr  = (Elf64_Ehdr *) bin;
    Elf64_Phdr *phdr = (Elf64_Phdr *) (bin + hdr->e_phoff);

    /* Find Auxv address */
    size_t envc = 0;    
    char **env = envp;
    for (; *env != NULL; ++env, ++envc) ;
    *env++;
    /* Find Auxv address */

    Elf64_auxv_t* auxv_ptr = (Elf64_auxv_t *) env;

    uint64_t *last_stack_ptr;
    for (; auxv_ptr->a_type != AT_NULL; auxv_ptr++) {
	    if (auxv_ptr->a_type == AT_PLATFORM) {
		    last_stack_ptr = (uint64_t*) auxv_ptr->a_un.a_val;
	    }
    }
    auxv_ptr++;

    void *stack_bottom = auxv_ptr;
    unsigned long stack_size = (unsigned long) stack_bottom -
                                        (unsigned long) &argv[0];

    /* Allocate initial stack */
    uint64_t *mapped_area = mmap(NULL, stack_size,
		    PROT_READ | PROT_WRITE | PROT_EXEC,
		    MAP_PRIVATE | MAP_ANONYMOUS | MAP_GROWSDOWN, -1, 0);
    if (!mapped_area)
        fprintf(stderr, "[STACK] failed to mmap()\n");
    memset(mapped_area, 0 ,stack_size);
    if (DEBUG)
    fprintf(stderr, "[mmap(): Stack]\n\tStart address: %lx\n" 
                    "\tMapped size: %lx (%ld)\n\n",
                    (unsigned long) mapped_area,
                    stack_size, stack_size);
    consumed_memory += stack_size;
    if (DEBUG)
            printf("Consumed Memory; %ld\n", consumed_memory);


    /* Reuse a loader's stack */
    uint64_t *h = memcpy(mapped_area, (uint64_t *)(&argv[0]), stack_size); 
    if (h != mapped_area)
        fprintf(stderr, "[STACK] failed to copy previous stack\n");

    void *start_point = mapped_area;
    *(int *) mapped_area = argc - 1;
    char *moving_ptr = ((char *) mapped_area) + 
                ((unsigned long) envp - (unsigned long) argv);
    auxv_ptr = (Elf64_auxv_t *) moving_ptr;
    for (; auxv_ptr->a_type != AT_NULL; auxv_ptr++) {
	   //printf("%ld %d\n", auxv_ptr, auxv_ptr->a_type); 
	    uint64_t *a_val = &auxv_ptr->a_un.a_val;
	    switch (auxv_ptr->a_type) {
		    case AT_PHDR:
                *a_val = (uint64_t) prg_hdr;
			    break;
		    case AT_PHENT:
			    *a_val = (uint64_t) hdr->e_phentsize; 
			    break;
		    case AT_PHNUM:
			    *a_val = (uint64_t) (hdr->e_phnum);
			    break;
		    case AT_ENTRY:
			    *a_val = (uint64_t) hdr->e_entry;
			    break;
		    case AT_EXECFN:
			   //printf("EXECFN: %s\n", *a_val);
    		   *a_val = *((uint64_t *)mapped_area+1);
			   //printf("Modified EXECFN: %s\n", *a_val);
			    break;
	    }
    }

    return start_point;
}

/**
 * seghandler()
 * @sig
 * @info
 * @uap
*/
static void seghandler(int sig, siginfo_t *info, void *uap) {
    load_image(buf, (unsigned long) info->si_addr, 0, (unsigned long) NULL);
}

int main(int argc, char** argv, char** envp)
{
    size_t f_size;
    char* f_name;

    char** overlap = envp;
    uint64_t loader_addr;
    while ( *(overlap++) == NULL ) ;
    Elf64_auxv_t* auxv_ptr = (Elf64_auxv_t *) overlap;
    for (; auxv_ptr->a_type != AT_NULL; auxv_ptr++) {
	    switch (auxv_ptr->a_type) {
		    case AT_ENTRY:
			    loader_addr = auxv_ptr->a_un.a_val;
			    break;
	    }
    }

    /* File processing */
    if (argc < 2) {
        fprintf(stderr, "Omit input binary file.\n");
        return -1;
    }

    if (strlen(argv[1]) > PATH_MAX) {
        fprintf(stderr, "Path length limit is %ul\n", PATH_MAX);
        return -1;
    }

    f_name = (char *) malloc(PATH_MAX);

    strcpy(f_name, argv[1]);

    if (access(f_name, F_OK) == -1) {
        fprintf(stderr, "File:%s does not exist.\n", f_name);
        return -1;
    }

    if(!read_file(f_name, &buf, &f_size)) return -1;
    /* File processing */

    /* Load binary program image */
    void *func = (void*)load_image(buf, 0, 1, loader_addr);
    /* Construct stack */
    void *stack_ptr = setup_stack(buf, argc, argv, envp);
	
    
    if (DEBUG) {
        printf(" ---> Entry point %lx Stack %lx\n", (uint64_t) func,
                            (uint64_t)stack_ptr);
        printf("*********** Program (%s) Loading Start! *******\n", f_name);
    }

    /* Register segmentfault handler */
    struct sigaction sa;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_SIGINFO;
    sa.sa_sigaction = seghandler;
    if (sigaction(SIGSEGV, &sa, NULL) == -1)
        fprintf(stderr, "Sigaction Error!\n");

	asm(" xor %%rax, %%rax;"
	" xor %%rbx, %%rbx;"
	" xor %%rcx, %%rcx;"
	" xor %%rsi, %%rsi;"
	" xor %%rdi, %%rdi;"
	" xor %%r8, %%r8;"
	" xor %%r9, %%r9;"
	" xor %%r10, %%r10;"
	" xor %%r11, %%r11;"
	" xor %%r12, %%r12;"
	" xor %%r13, %%r13;"
	" xor %%r14, %%r14;"
	" xor %%r15, %%r15;"
	: : : "%rax", "%rbx", "%rcx", "%rsi", "%rdi", "%r8", 
    "%r9", "%r10", "%r11", "%r12", "%r13", "%r14", "%r15"); 

    asm("movq $0, %rdx");

    asm(" movq %0, %%rsp;" : :"a"(stack_ptr):"%rsp");
    asm(" jmp %0" : :"a"(func):);
    return 0;
}
