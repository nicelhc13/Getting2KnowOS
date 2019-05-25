#define FUSE_USE_VERSION 29
#define _XOPEN_SOURCE 500

#define _GNU_SOURCE
#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <fuse.h>
#include <libgen.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

#include "dustfs.h"

#define TMP_HANDLE_MODE  0
#define NORM_HANDLE_MODE 1

#define PRIVATE_DATA ((struct dust_state*) fuse_get_context()->private_data)

char target_dir[PATH_MAX];
struct dust_state* dust_dinfo;

/**
 * generate_cid()
 *
 * Generate a client unique id.
 * Whenever a client handles files on server,
 * there might be some conflicts with other customers.
 * To make consistency for this case,
 * files are separatedly managed on /tmp/[CID] directory.
 * Basic CID format is [HOSTNAME][UID]
 * TODO: need merging system.
 */
char* generate_cid()
{
    char *cid = malloc(PATH_MAX*sizeof(char)); 
    char uid[20];
    int uid_int = getuid();
    snprintf(uid, 20, "%d", uid_int);
    gethostname(cid, PATH_MAX);
    strncat(cid, uid, sizeof(uid));
    return cid;
}

/**
 * mk_server_cid_dir()
 *
 * Make CID directory on the /tmp of server.
 * Existing directory does not matter since
 * it does not overwrite the directory, 
*/
void mk_server_cid_dir(void)
{
    char *cid = generate_cid();
    char *cmd = malloc(sizeof(char)*(4096));
    strcpy(cmd, "scp ");
    strncat(cmd, cid, PATH_MAX);
    strncat(cmd, " ", sizeof(" "));
    strncat(cmd, dust_dinfo->server, 4096);
    system(cmd); 
}

/**
 * get_full_path()
 * @fpath: Path buffer to be filled.
 * @path: Relative path.
 *
 * Generate full path.
 */
void get_fullpath(char *fpath, const char *path)
{
    strcpy(fpath, PRIVATE_DATA->rootdir);
	strncat(fpath, path, PATH_MAX);
}

void get_tmp_path(char *fpath, const char *path)
{
    strcpy(fpath, "/tmp/");
	strncat(fpath, path, PATH_MAX);
}

/* */
#ifdef HAVE_SYS_XATTR_H
int dust_setaxttr(const char *path, const char *name, const char *value, 
                    size_t size, int flags)
{
    char fpath[PATH_MAX];
    get_fullpath(fpath, path);

    return lsetxattr(fpath, name, value, size, flags);
}

int dust_getxattr(const char *path, const char *name, char *value, size_t size)
{
    int retstat = 0;
    char fpath[PATH_MAX];

    get_fullpath(fpath, path);
    retstat = lgetxattr(fpath, name, value, size);
    return retstat;
}

int dust_listxattr(const char *path, char *list, size_t size)
{
    int retstat = 0;
    char fpath[PATH_MAX];
    char *ptr;

    get_fullpath(fpath, path);
    retstat = llistxattr(fpath, list, size);

    return retstat;
}

int dust_removexattr(const char *path, const char *name)
{
    char fpath[PATH_MAX];

    get_fullpath(fpath, path);
    return lremovexattr(fpath, name);
}
#endif

/**
 * dust_open()
 * @path: Target path.
 * @fi: Information of open file.
 * 
 * Open a file and set the handle.
 */
static int dust_open(const char *path, struct fuse_file_info *fi)
{
	int fd, ret = 0;
	char fpath[PATH_MAX];

	//get_full_path(fpath, path);
	get_fullpath(fpath, path);

    if (strstr(path, "server_tmp") != NULL) {
        char *cmd = malloc(sizeof(char)*(4096));
        char *fname = strrchr(path, '/')+1;
        strcpy(cmd, "scp ");
        strncat(cmd, dust_dinfo->server, 4096);
        strncat(cmd, fname, 4096);
        strncat(cmd, " .", sizeof(" ."));
        system(cmd); 
    }

	fd = open(fpath, fi->flags);
	if (fd < 0) {
		printf("failed to open a file\n");	
        ret = -errno;
    }

    // set handle.
    fi->fh = fd;
	return ret;
}

/**
 * dust_read()
 * @path: Target path.
 * @buf: Buffer to be filled by read data.
 * @size: Read size.
 * @offset: Target data offset on a file.
 * @fi: Information of open file. 
 * 
 * Read file.
 */
static int dust_read(const char *path, char *buf, size_t size, off_t offset, 
                     struct fuse_file_info *fi) {
    int fd, ret = 0;
    char fpath[PATH_MAX];
    
    //get_full_path(fpath, path);
	get_fullpath(fpath, path);

    if (fi == NULL)
        fd = open(fpath, O_RDWR);
    else
        fd = fi->fh;

    /* Fail to et file descriptor */
    if (fd == -1)
        return -errno;

    ret = pread(fd, buf, size, offset);
    if (ret == -1) ret = -errno;
    if (fi == NULL) {
        close(fd);
    }

	return ret;
}

/**
 * dust_rename()
 * @path: Old path.
 * @newpath: New path.
 * 
 * Rename a file.
 */
int dust_rename(const char *path, const char *newpath)
{
    int ret;
    char fpath[PATH_MAX];
    char fnewpath[PATH_MAX];

    /* get both full paths */
    get_fullpath(fpath, path);
    get_fullpath(fnewpath, newpath);
    if((ret = rename(fpath, fnewpath)) < 0) {
        return -errno;
    }

    return ret;
}

/**
 * dust_link()
 * @from: Target path to be linked.
 * @to: Linking path.
 * 
 * Create a hard link between 'from' file and 'to' file.
 */
static int dust_link(const char *from, const char *to)
{
    char fpath[PATH_MAX], fnewpath[PATH_MAX];
    int ret;

    get_fullpath(fpath, from);
    get_fullpath(fnewpath, to);
    ret = link(fpath, fnewpath);

    return ret;
}

/**
 * dust_getattr()
 * @path: Target path.
 * @statbuf: 
 * 
 * Get file attribute.
 */
static int dust_getattr(const char *path, struct stat *statbuf)
{
	char fpath[PATH_MAX];
    int ret;

	//get_full_path(fpath, path);
	get_fullpath(fpath, path);
    ret = lstat(fpath, statbuf);
    if (ret < 0) ret = -errno;
	return ret;
}

/**
 * dust_write()
 * @path
 * @buf
 * @size
 * @offset
 * @fi 
 *
 * Write file.
 */
static int dust_write(const char *path, const char *buf, size_t size, 
        off_t offset, struct fuse_file_info *fi)
{
    int fd, res;
    char fpath[PATH_MAX];

	get_fullpath(fpath, path);
    if (fi == NULL)
        fd = open(fpath, O_WRONLY);
    else
        fd = fi->fh;
    if (fd == -1) return -errno;
    res = pwrite(fd, buf, size, offset);

    if (res == -1) res = -errno;
    if (fi == NULL) {
        close(fd);
    }

	return res;
}

/**
 * dust_opendir()
 * @path
 * @fi
 *
 * Open directroy.
 */
static int dust_opendir(const char *path, struct fuse_file_info *fi)
{
	DIR *dp;
	char fpath[PATH_MAX];
	int retstat = 0;

	get_fullpath(fpath, path);

	if ((dp = opendir(fpath)) == NULL) {
		printf("failed to open a directory\n");
		retstat = -errno;
	}
	
	fi->fh = (intptr_t) dp;
	
	return retstat;
} 

/**
 * dust_readdir()
 * @path
 * @fi
 *
 * Read directroy.
 */
static int dust_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
							off_t offset, struct fuse_file_info *fi)
{
	int retstat = 0;
	DIR *dp;
	struct dirent *de;
    char fpath[PATH_MAX];

    get_fullpath(fpath, path);
    dp = opendir(fpath);

    de = readdir(dp);
    if (de == 0) {
        printf("failed to read a directory\n");
        retstat = -errno;	
        return retstat;
    }

    do {
        struct stat st;
        memset(&st, 0, sizeof(st));
        st.st_ino = de->d_ino;
        st.st_mode = de->d_type << 12;
        if (filler(buf, de->d_name, &st, 0) != 0) {
            printf("ERROR dust_reader filler: buffer full\n");
            break;
        }
    } while ((de = readdir(dp)) != NULL);
    closedir(dp);

	return retstat;
}

/**
 * dust_init()
 * @conn
 *
 * Initialize dustfs.
 * Make server_tmp directory which communicates with server.
 */
void *dust_init(struct fuse_conn_info *conn)
{
    /* make communication directory to server */
    char *server_dir = malloc(sizeof(char)*PATH_MAX);
    strcpy(server_dir, target_dir);
    strncat(server_dir, "/server_tmp", PATH_MAX);
    int ret = mkdir(server_dir, S_IRUSR | S_IWUSR | S_IXUSR);
    /* if it exists already, ignore */

    return ((struct dust_state *) fuse_get_context()->private_data);
}

/**
 * dust_access()
 * @path
 * @mask
 *
 * Access to file, check permission, get information..
 */
int dust_access(const char *path, int mask)
{
	int retstat = 0;
	char fpath[PATH_MAX];
	
	get_fullpath(fpath, path);

	if ((retstat = access(fpath, mask)) < 0)
        return -errno;
	
	return retstat;
}

/**
 * dust_chmod()
 * @path
 * @mode
 *
 * Change mode of file.
 */
int dust_chmod(const char *path, mode_t mode)
{
	int retstat = 0;
	char fpath[PATH_MAX];

	get_fullpath(fpath, path);
	if ((retstat = chmod(fpath, mode)) < 0)
		printf("failed to change a mode\n");
	return retstat;
}

/**
 * dust_chwon()
 * @path
 * @uid
 * @gid
 *
 * Change owner of file.
 */
int dust_chown(const char *path, uid_t uid, gid_t gid)
{
	int retstat = 0;
	char fpath[PATH_MAX];
	get_fullpath(fpath, path);
	if ((retstat = lchown(fpath, uid, gid)) < 0)
		printf("failed to chnage an owner\n"); 
	return retstat;
}

/**
 * dust_mkdir()
 * @path
 * @mode
 *
 * Make directory.
 */
int dust_mkdir(const char *path, mode_t mode)
{
    char fpath[PATH_MAX];

    get_fullpath(fpath, path);

    return mkdir(fpath, mode);
}

/**
 * dust_unlink()
 * @path
 *
 * Unlink the path.
 */
int dust_unlink(const char *path)
{
    char fpath[PATH_MAX];
    get_fullpath(fpath, path);

    return unlink(fpath);
}

/**
 * dust_rmdir()
 * @path
 *
 * Remove the path.
 */
int dust_rmdir(const char *path)
{
	int retstat = 0;
	char fpath[PATH_MAX];

	get_fullpath(fpath, path);
	if ((retstat = rmdir(fpath)) < 0)
		printf("failed to remove a directory\n");
	return retstat;	
}

/**
 * dust_mknod()
 * @path
 * @mode
 * @dev
 *
 * Make node for the path.
 */
int dust_mknod(const char *path, mode_t mode, dev_t dev)
{
	int retstat = 0;
	char fpath[PATH_MAX];

	get_fullpath(fpath, path);

    /* If it is a regular file */
	if (S_ISREG(mode)) {
		retstat = open(fpath, O_CREAT | O_EXCL | O_WRONLY, mode);
		if (retstat >= 0) {
            close(retstat);
        }
	} else {
		if (S_ISFIFO(mode)) {
			if ((retstat = mkfifo(fpath, mode)) < 0);
                retstat = -errno;
        }
		else {
			if((retstat = mknod(fpath, mode, dev)) < 0)
                retstat = -errno;
        }
	}

	return retstat;
}

/**
 * dust_fgetattr()
 * @path
 * @statbuf
 * @fi
 *
 * Get file attribute.
 */
int dust_fgetattr(const char *path, struct stat *statbuf, 
        struct fuse_file_info *fi)
{
    int retstat = 0;

    if (!strcmp(path, "/"))
        return dust_getattr(path, statbuf);

    retstat = fstat(fi->fh, statbuf);
    if (retstat < 0)
        retstat = -errno;

    return retstat;
}

int dust_truncate(const char *path, off_t size)
{
    int res;
    char fpath[PATH_MAX];

    get_fullpath(fpath, path);
    res = truncate(fpath, size);

    if (res == -1)
        return -errno;

    return res;
}

int dust_ftruncate(const char *path, off_t offset,
                        struct fuse_file_info *fi)
{
    int retstat = 0;

    if((retstat = ftruncate(fi->fh, offset)) < 0)
        retstat = -errno;

    return retstat;
}

int dust_fsync(const char *path, int datasync, struct fuse_file_info *fi)
{
    return fsync(fi->fh);
}

int dust_release(const char *path, struct fuse_file_info *fi)
{
    int ret = close(fi->fh);

    if (ret < 0) {
        return -errno;
    }
 
    return ret;
}

int dust_fsyncdir(const char *path, int datasync, struct fuse_file_info *fi)
{
    return 0;
}

int dust_releasedir(const char *path, struct fuse_file_info *fi)
{
    closedir((DIR *) (uintptr_t) fi->fh);
    return 0;
}

int dust_flush(const char *path, struct fuse_file_info *fi)
{
    if (strstr(path, "server_tmp") != NULL) {
        char fpath[PATH_MAX];
        get_fullpath(fpath, path);

        char *cmd = malloc(sizeof(char)*(4096));
        strcpy(cmd, "scp ");
        strncat(cmd, fpath, 4096);
        strncat(cmd, " ", sizeof(" "));
        strncat(cmd, dust_dinfo->server, 4096);
        system(cmd); 
    }

    return 0;
}

int dust_statfs(const char *path, struct statvfs *statv)
{
    int retstat = 0;
    char fpath[PATH_MAX];
    get_fullpath(fpath, path);
    retstat = statvfs(fpath, statv);
    return retstat;
}

int dust_symlink(const char *from, const char *to)
{
    int res;

    res = symlink(from, to);
    if (res == -1)
        return -errno;
    return 0;
}

int dust_create(const char *path, mode_t mode,
        struct fuse_file_info *fi)
{
    char fpath[PATH_MAX];
    int res;

	get_fullpath(fpath, path);
    res = open(fpath, fi->flags, mode);
    if (res == -1) return -errno;
    fi->fh = res;
    return 0;
}

int dust_utime(const char *path, struct utimbuf *ubuf)
{
    char fpath[PATH_MAX];
    
    get_fullpath(fpath, path);

    return utime(fpath, ubuf);
}

void dust_destroy(void *userdata)
{
}

int dust_readlink(const char *path, char *link, size_t size)
{
    int retstat;
    char fpath[PATH_MAX];
    
    get_fullpath(fpath, path);

    retstat = readlink(fpath, link, size - 1);
    if (retstat >= 0) {
	link[retstat] = '\0';
	retstat = 0;
    }
    
    return retstat;
}

static struct fuse_operations dust_oper = {
	.getattr = dust_getattr, //
	.open = dust_open,
	.read = dust_read,
	.write = dust_write,
    .create = dust_create,
    .utime = dust_utime,
	.opendir = dust_opendir,
    .rename = dust_rename,
	.readdir = dust_readdir,
	.init = dust_init,
	.access = dust_access,
	.chmod = dust_chmod,
    .chown = dust_chown,
	.rmdir = dust_rmdir,
    .mkdir = dust_mkdir,
	.mknod = dust_mknod,
    .statfs = dust_statfs,
    .destroy = dust_destroy,
    .readlink = dust_readlink,
#ifdef HAVE_SYS_XATTR_H
    .setxattr = dust_setxattr,
    .getxattr = dust_getxattr,
    .listxattr = dust_listxattr,
    .removexattr = dust_removexattr,
#endif
    .fgetattr = dust_fgetattr,
    .truncate = dust_truncate,
    .ftruncate = dust_ftruncate,
    .unlink = dust_unlink,
    .flush = dust_flush,
    .fsync = dust_fsync,
    .fsyncdir = dust_fsyncdir,
    .release = dust_release,
    .releasedir = dust_releasedir,
    .symlink = dust_symlink,
    .link = dust_link

};

int main(int argc, char *argv[])
{
    int fuse_stat;

    if ((getuid() == 0) || (geteuid() == 0)) {
        return 1;
    }
       
    if ((argc < 4) || 
        (argv[argc-3][0] == '-') ||
        (argv[argc-2][0] == '-') ||
        (argv[argc-1][0] == '-')) {
            fprintf(stderr, "usage :"
                    "dustfs [FUSE and mount options] rootDir mountPoint\n");
            return -1;
    }

    dust_dinfo = malloc(sizeof(struct dust_state));
    if (dust_dinfo == NULL) {
        perror("malloc dust_dinfo failed\n");
        return -1;
    }

    /* root dir */
    dust_dinfo->rootdir = realpath(argv[argc-3], NULL);
    strcpy(target_dir, dust_dinfo->rootdir);

    /* server host name i.e. hochan@ghostwheel2.ices.utexas.edu */
    dust_dinfo->server = argv[argc-1];
    /* NOTE! only communicate with /tmp/ of server */
    strncat(dust_dinfo->server, ":/tmp/", PATH_MAX);

    printf("Source directory: %s \n"
           "Destination directory: %s \n"
           "Local host name: %s\n", 
            argv[argc-3], argv[argc-2], argv[argc-1]);
    argv[argc-3] = argv[argc-2];
    argv[argc-2] = NULL;
    argv[argc-1] = NULL;
    argc-=2;

//  generate_cid();
    fprintf(stderr, "CALL fuse_main()\n");
    fuse_stat = fuse_main(argc, argv, &dust_oper, dust_dinfo);
    fprintf(stderr, "fuse_main returned %d\n", fuse_stat);

    return fuse_stat;
}
