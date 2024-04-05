//
//  autosign.c
//  autosign
//
//  Created by Nick Chan on 5/4/2024.
//

#include <spawn.h>
#include <stdio.h>
#include <sys/stat.h>
#include <unistd.h>
#include <limits.h>
#include <fcntl.h>
#include <errno.h>
#include <substrate.h>
#include <mach-o/loader.h>
#include <sys/types.h>
#include <sys/param.h>
#include <mach-o/dyld.h>
#include <mach-o/fat.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <arpa/inet.h>
#include <string.h>

int nick_chan_posix_spawn(pid_t * __restrict, const char * __restrict,
    const posix_spawn_file_actions_t *,
    const posix_spawnattr_t * __restrict,
    char *const __argv[__restrict],
    char *const __envp[__restrict]) asm("_posix_spawn");

#if DEBUG
#define log(...) fprintf(stderr, __VA_ARGS__)
#else
#define log(...)
#endif

extern char** environ;
int (*close_orig)(int fd);

bool stringEndsWith(const char* str, const char* suffix) {
    if (!str || !suffix) {
        return false;
    }

    size_t str_len = strlen(str);
    size_t suffix_len = strlen(suffix);

    if (str_len < suffix_len) {
        return false;
    }

    return !strcmp(str + str_len - suffix_len, suffix);
}

bool check_mach_header(const struct mach_header_64* hdr) {
    if (hdr->magic != MH_MAGIC_64) {
        log("slice is not a valid 64 bit little-endian macho\n");
        return false;
    }
    if (hdr->cputype != CPU_TYPE_ARM64) {
        log("ignoring non-arm64 slices/machos\n");
        return false;
    }
    if (hdr->filetype == MH_EXECUTE ||
        hdr->filetype == MH_BUNDLE  ||
        hdr->filetype == MH_DYLIB ||
        hdr->filetype == MH_DYLINKER) {
        log("found mach-o that needs to be resigned\n");
        return true;
    }
    return false;
}

// This function must not crash even against malicious inputs
bool resign_required(char* path, struct stat* st_p) {
    const uint8_t* data = MAP_FAILED;
    int retval = false;
    int fd = open(path, O_RDWR);
    if (fd == -1) {
        log("failed to open file %s: %d (%s)\n", path, errno, strerror(errno));
        goto cleanup;
    }
    data = mmap(NULL, st_p->st_size, PROT_READ, MAP_FILE | MAP_PRIVATE, fd, 0);
    if (data == MAP_FAILED) {
        log("failed to map file %s\n", path);
        goto cleanup;
    }
    
    //log("checking if file %s is a mach-o\n", path);
    const struct mach_header_64* hdr = (const struct mach_header_64*)data;
    if (hdr->magic != MH_MAGIC_64
        && hdr->magic != FAT_CIGAM_64
        && hdr->magic != FAT_CIGAM) {
        //log("file %s is not a mach-o\n", path);
        goto cleanup;
    }
    log("file %s is a mach-o!\n", path);
    
    if (hdr->magic == FAT_CIGAM) {
        const struct fat_header* fat = (const struct fat_header*) hdr;
        if (ntohl(fat->nfat_arch) > 30) {
            log("this is probably a java class file\n");
            goto cleanup;
        }
        size_t fat_headers_size = sizeof(struct fat_arch) * ntohl(fat->nfat_arch) + sizeof(struct fat_header);
        if (fat_headers_size > (size_t)st_p->st_size) {
            log("file %s is truncated\n", path);
            goto cleanup;
        }
        const struct fat_arch* archs = (const struct fat_arch*)(fat + 1);
        for (uint32_t i = 0; i < ntohl(fat->nfat_arch); i++) {
            if (ntohl(archs[i].cputype) != CPU_TYPE_ARM64) continue;
            if ((ntohl(archs[i].offset) + sizeof(struct mach_header_64*)) > (size_t)st_p->st_size) {
                log("file %s is truncated\n", path);
                goto cleanup;
            }
            const struct mach_header_64* arch_header = (struct mach_header_64*)(data + ntohl(archs[i].offset));
            if (check_mach_header(arch_header)) {
                retval = true;
                break;
            }
        }
    }
        
    if (hdr->magic == FAT_CIGAM_64) {
        const struct fat_header* fat = (const struct fat_header*) hdr;
        size_t fat_headers_size = sizeof(struct fat_arch_64) * ntohl(fat->nfat_arch) + sizeof(struct fat_header);
        if (fat_headers_size > (size_t)st_p->st_size) {
            log("file %s is truncated\n", path);
            goto cleanup;
        }
        const struct fat_arch_64* archs = (const struct fat_arch_64*)(fat + 1);
        for (uint32_t i = 0; i < ntohl(fat->nfat_arch); i++) {
            if (ntohl(archs[i].cputype) != CPU_TYPE_ARM64) continue;
            if ((ntohll(archs[i].offset) + sizeof(struct mach_header_64*)) > (size_t)st_p->st_size) {
                log("file %s is truncated\n", path);
                goto cleanup;
            }
            const struct mach_header_64* arch_header = (const struct mach_header_64*)(data + ntohll(archs[i].offset));
            if (check_mach_header(arch_header)) {
                retval = true;
                break;
            }
        }
    }
    
    if (hdr->magic == MH_MAGIC_64) retval = check_mach_header(hdr);
    
cleanup:
    if (data != MAP_FAILED) munmap((void*)data, st_p->st_size);
    if (fd != -1) close_orig(fd);
    return retval;
}

int autosign(char* path, struct stat* st_p) {
    if (!resign_required(path, st_p)) return 0;
    pid_t pid;
    int retval = nick_chan_posix_spawn(&pid, "/usr/bin/ldid", NULL, NULL, (char*[]){ "/usr/bin/ldid", "-s", path, NULL }, environ);
    if (retval) {
        log("posix_spawn ldid failed: %d (%s)\n", retval, strerror(retval));
        return -1;
    }
    int status = 0;
    while(waitpid(pid, &status, 0) != -1)
    {
        if (WIFSIGNALED(status)) {
            retval = 128 + WTERMSIG(status);
        } else if (WIFEXITED(status)) {
            retval = WEXITSTATUS(status);
        }
    };
    log("fixing file permissions: mode: %d\n", st_p->st_mode);
    retval = chmod(path, st_p->st_mode & 07777);
    if (retval) {
        log("chmod failed: %d (%s)\n", errno, strerror(errno));
    }
    
    return retval;
}

int close_hook(int fd) {
    struct stat st;
    int old_errno = errno;
    char path[PATH_MAX]={0};
    int fcntl_retval = fcntl(fd, F_GETPATH, path);
    errno = old_errno;
    int stat_retval = fstat(fd, &st);
    errno = old_errno;
    int close_retval = close_orig(fd);
    old_errno = errno;
    
    if (fcntl_retval == 0 && path[0] != '\0') {
        if (stat_retval == 0 
            && S_ISREG(st.st_mode)
            && st.st_size > 0x100
            && (stringEndsWith(path, ".dpkg-new") || strncmp(path, "/Library/dpkg/tmp.ci", 20) == 0)) {
            int autosign_retval = autosign(path, &st);
            if (autosign_retval) {
                log("autosign failed with code %d\n", autosign_retval);
            }
        }
    }
    errno = old_errno;
    
    return close_retval;
}

__attribute__((constructor)) void ctor(void) {
    log("Autosign loaded\n");
    MSHookFunction(close, (void*)&close_hook, (void**)&close_orig);
}
