#define _GNU_SOURCE

#include <time.h>
#include <stdio.h>
#include <dlfcn.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <limits.h>
#include <sys/types.h>
#include <errno.h>
#include <openssl/evp.h> //install the required package
#include <openssl/sha.h>

static const char *AUDIT_LOG_PATH = "./tmp/access_audit.log";

/* compute SHA-256 hash of file contents */
static void compute_file_hash(const char *path, char *hash_hex, size_t hex_len)
{
    hash_hex[0] = '\0';

    FILE *(*original_fopen)(const char*, const char*);
    original_fopen = dlsym(RTLD_NEXT, "fopen");
    if (!original_fopen) return;

    int (*original_fclose)(FILE*);
    original_fclose = dlsym(RTLD_NEXT, "fclose");
    if (!original_fclose) return;

    FILE *f = (*original_fopen)(path, "rb");

    if (!f) {
        strncpy(hash_hex, "N/A", hex_len - 1);
        return;
    }

    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int hash_len;
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    if (!mdctx) {
        fclose(f);
        strncpy(hash_hex, "N/A", hex_len - 1);
        return;
    }

    EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL);
    unsigned char buf[4096];
    size_t bytes;
    while ((bytes = fread(buf, 1, sizeof(buf), f)) > 0) {
        EVP_DigestUpdate(mdctx, buf, bytes);
    }
    EVP_DigestFinal_ex(mdctx, hash, &hash_len);
    EVP_MD_CTX_free(mdctx);
    //fclose(f);
    (*original_fclose)(f);

    /* convert to hex */
    for (unsigned int i = 0; i < hash_len && i * 2 + 1 < hex_len; i++) {
        snprintf(hash_hex + i * 2, 3, "%02x", hash[i]);
    }
}

/* resolve FILE* to filesystem path via /proc/self/fd/<fd> */
static void fd_to_path(FILE *stream, char *buf, size_t bufsz)
{
    buf[0] = '\0';
    if (!stream) return;
    int fd = fileno(stream);
    if (fd < 0) return;
    char linkpath[64];
    snprintf(linkpath, sizeof(linkpath), "/proc/self/fd/%d", fd);
    ssize_t len = readlink(linkpath, buf, bufsz - 1);
    if (len <= 0) { buf[0] = '\0'; return; }
    buf[len] = '\0';
}

/* get absolute path from relative or absolute */
static void get_absolute_path(const char *path, char *abs_path, size_t len)
{
    if (!path) {
        abs_path[0] = '\0';
        return;
    }
    if (path[0] == '/') {
        strncpy(abs_path, path, len - 1);
        abs_path[len - 1] = '\0';
    } else {
        char cwd[PATH_MAX];
        if (!getcwd(cwd, sizeof(cwd))) {
            strncpy(abs_path, path, len - 1);
            abs_path[len - 1] = '\0';
            return;
        }
        snprintf(abs_path, len, "%s/%s", cwd, path);
    }
}

/* timestamp helpers (UTC) */
static void make_timestamp_date(char *out, size_t outlen)
{
    time_t t = time(NULL);
    struct tm *tm = gmtime(&t);
    strftime(out, outlen, "%Y-%m-%d", tm);
}

static void make_timestamp_time(char *out, size_t outlen)
{
    time_t t = time(NULL);
    struct tm *tm = gmtime(&t);
    strftime(out, outlen, "%H:%M:%S", tm);
}



/* write to audit log using low-level syscalls to avoid recursion */
static void write_audit(const char *msg)
{
    mkdir("./tmp", 0755);
    int fd = open(AUDIT_LOG_PATH, O_WRONLY | O_APPEND | O_CREAT, 0644);
    if (fd >= 0) {
        size_t len = strlen(msg);
        ssize_t r = write(fd, msg, len);
        (void)r;
        close(fd);
    }

}

/* helper: is path a character device (tty) ? */
static int path_is_chardev(const char *path)
{
    struct stat st;
    if (lstat(path, &st) != 0) return 0;
    return S_ISCHR(st.st_mode);
}

FILE *fopen(const char *path, const char *mode) 
{
    FILE *(*original_fopen)(const char*, const char*);
    original_fopen = dlsym(RTLD_NEXT, "fopen");
    if (!original_fopen) return NULL;

    char abs_path[PATH_MAX];
    get_absolute_path(path, abs_path, sizeof(abs_path));

    /* avoid logging our own audit file */
    if (abs_path[0] != '\0' && strcmp(abs_path, AUDIT_LOG_PATH) == 0) {
        return (*original_fopen)(path, mode);
    }

    /* Check if file exists BEFORE fopen */
    struct stat st;
    int file_existed = (stat(abs_path, &st) == 0);
    
    /* Determine if this is a creation:
       - File didn't exist, AND
       - Mode contains 'w' (write/truncate) or 'a' (append)
    */
    int is_creation = !file_existed && mode && (strchr(mode, 'w') || strchr(mode, 'a'));
    char hash_hex[65] = "N/A";
    if (file_existed) {
        compute_file_hash(abs_path, hash_hex, sizeof(hash_hex));
    }

    /* Call original fopen */
    FILE *fp = (*original_fopen)(path, mode);

    /* Log the operation */
    uid_t uid = getuid();
    pid_t pid = getpid();
    char date[32], time_str[32];
    make_timestamp_date(date, sizeof(date));
    make_timestamp_time(time_str, sizeof(time_str));

    int operation = is_creation ? 0 : 1; /* 0=created, 1=opened */
    int denied = (fp == NULL) ? 1 : 0;
   
    char msg[2048];
    int n = snprintf(msg, sizeof(msg),
        "UID=%u|PID=%u|FILE=%s|DATE=%s|TIME=%s|OP=%d|DENIED=%d|HASH=%s\n",
        uid, pid, abs_path, date, time_str, operation, denied, hash_hex);
    if (n > 0) write_audit(msg);

    return fp;
}


size_t fwrite(const void *ptr, size_t size, size_t nmemb, FILE *stream) 
{
	size_t (*original_fwrite)(const void*, size_t, size_t, FILE*);
    original_fwrite = dlsym(RTLD_NEXT, "fwrite");
    if (!original_fwrite) return 0;

    size_t result = (*original_fwrite)(ptr, size, nmemb, stream);

    char pathbuf[PATH_MAX];
    fd_to_path(stream, pathbuf, sizeof(pathbuf));
    if (pathbuf[0] == '\0' || strcmp(pathbuf, AUDIT_LOG_PATH) == 0) {
        return result;
    }

    /* if TTY or char device, skip logging */
    if (path_is_chardev(pathbuf)) return result;
    
    uid_t uid = getuid();
    pid_t pid = getpid();
    char date[32], time_str[32];
    make_timestamp_date(date, sizeof(date));
    make_timestamp_time(time_str, sizeof(time_str));

    int operation = 2; /* 2=written */
    int denied = 0;
    char hash_hex[65] = "N/A";
    //fflush(stream);
    //compute_file_hash(pathbuf, hash_hex, sizeof(hash_hex));

    char msg[2048];
    int n = snprintf(msg, sizeof(msg),
        "UID=%u|PID=%u|FILE=%s|DATE=%s|TIME=%s|OP=%d|DENIED=%d|HASH=%s\n",
        uid, pid, pathbuf, date, time_str, operation, denied, hash_hex);
    if (n > 0) write_audit(msg);

    return result;
}


int  fclose(FILE *stream)
{
    int (*original_fclose)(FILE*);
    original_fclose = dlsym(RTLD_NEXT, "fclose");
    if (!original_fclose) return EOF;


    char pathbuf[PATH_MAX];
    fd_to_path(stream, pathbuf, sizeof(pathbuf));

    int result = (*original_fclose)(stream);
    //fprintf(stderr, "fclose called on file: %s\n", pathbuf);

    //if(strcmp(pathbuf, "/etc/ssl/openssl.cnf") == 0) return result;
    

     /* if TTY or char device, skip logging */

    if (pathbuf[0] == '\0' || strcmp(pathbuf, AUDIT_LOG_PATH) == 0 ||
     strncmp(pathbuf, "/dev/", 5) == 0) return result;


    char hash_hex[65] = "N/A";
    compute_file_hash(pathbuf, hash_hex, sizeof(hash_hex));


    uid_t uid = getuid();
    pid_t pid = getpid();
    char date[32], time_str[32];
    make_timestamp_date(date, sizeof(date));
    make_timestamp_time(time_str, sizeof(time_str));

    int operation = 3; /* 3=closed */
    int denied = (result == EOF) ? 1 : 0;
    

    char msg[2048];
    int n = snprintf(msg, sizeof(msg),
        "UID=%u|PID=%u|FILE=%s|DATE=%s|TIME=%s|OP=%d|DENIED=%d|HASH=%s\n\n\n",
        uid, pid, pathbuf, date, time_str, operation, denied, hash_hex);
    if (n > 0) write_audit(msg);

    return result;
}

int unlinkat(int dirfd, const char *pathname, int flags) 
{
    int (*original_unlinkat)(int, const char*, int);
    original_unlinkat = dlsym(RTLD_NEXT, "unlinkat");
    if (!original_unlinkat) return -1;

    char abs_path[PATH_MAX];
    get_absolute_path(pathname, abs_path, sizeof(abs_path));

    int result = original_unlinkat(dirfd, pathname, flags);

    if(strcmp(abs_path, AUDIT_LOG_PATH) == 0) return result;


    uid_t uid = getuid();
    pid_t pid = getpid();
    char date[32], time_str[32];
    make_timestamp_date(date, sizeof(date));
    make_timestamp_time(time_str, sizeof(time_str));

    int operation = 4; /* 4 = Delete */
    char hash_hex[65] = "N/A";
    char msg[2048];
    int denied = 0;

    
    if (result != 0) denied = 1;

    int n = snprintf(msg, sizeof(msg),
        "UID=%u|PID=%u|FILE=%s|DATE=%s|TIME=%s|OP=%d|DENIED=%d|HASH=%s\n",
        uid, pid, abs_path, date, time_str, operation, denied, hash_hex);
    if (n > 0) write_audit(msg);

    return result;
}
