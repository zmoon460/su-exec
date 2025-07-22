/* set user and group id and exec */

#include <sys/types.h>
#include <sys/stat.h>
#include <err.h>
#include <grp.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <limits.h>
#include <fcntl.h>
#include <paths.h>

extern char **environ;

/* Global variable for program name */
char *argv0;

static void usage(int exitcode);
static void sanitize_std_fds(void);
static void sanitize_environment(void);
static char* find_in_path(const char *prog, const char *path, char *result, size_t size);

/* Usage function */
static void usage(int exitcode)
{
        printf("Usage: %s user-spec command [args]\n", argv0);
        exit(exitcode);
}

int main(int argc, char *argv[])
{
        /* 只允许root运行 */
        if (getuid() != 0) {
                errx(1, "必须以root身份运行");
        }

        char *user, *group, **cmdargv;
        char *end;
        char *path;
        char exec_path[PATH_MAX];

        uid_t uid = 0;
        gid_t gid = 0;

        argv0 = argv[0];
        if (argc < 3)
                usage(0);

        /* 确保标准文件描述符存在 */
        sanitize_std_fds();

        /* 重置 umask */
        umask(S_IWGRP | S_IWOTH);

        /* 清理环境变量 */
        sanitize_environment();

        user = argv[1];
        group = strchr(user, ':');
        if (group) {
                *group++ = '\0';
        }

        cmdargv = &argv[2];

        /* 确保PATH环境变量存在 */
        if (!getenv("PATH")) {
                setenv("PATH", "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", 1);
        }

        /* 解析用户 - 要求必须指定有效用户 */
        if (user[0] == '\0') {
                errx(1, "必须指定用户");
        }
        
        uid_t nuid = strtol(user, &end, 10);
        if (*end == '\0') {
                /* 数字UID */
                if (nuid < 0 || nuid > 65535) {
                    errx(1, "UID must be in range 0-65535 (got %d)", nuid);
                }
                uid = nuid;
        } else {
                /* 用户名 */
                struct passwd *pw = getpwnam(user);
                if (!pw) {
                    errx(1, "user '%s' does not exist", user);
                }
                uid = pw->pw_uid;
                gid = pw->pw_gid;
        }

        /* Parse group */
        if (group && group[0] != '\0') {
                gid_t ngid = strtol(group, &end, 10);
                if (*end == '\0') {
                        /* Numeric GID */
                        if (ngid < 0 || ngid > 65535) {
                            errx(1, "GID must be in range 0-65535 (got %d)", ngid);
                        }
                        gid = ngid;
                } else {
                        /* Group name */
                        struct group *gr = getgrnam(group);
                        if (!gr) {
                                errx(1, "group '%s' does not exist", group);
                        }
                        gid = gr->gr_gid;
                }
        }

        /* Set group and user */
        if (setgid(gid) < 0 || setuid(uid) < 0) {
                err(1, "failed to drop privileges");
        }

        /* Find and execute command */
        path = getenv("PATH");
        if (!path) {
            path = _PATH_DEFPATH;
        }

        if (find_in_path(cmdargv[0], path, exec_path, sizeof(exec_path)) == NULL) {
            errx(1, "command not found: %s", cmdargv[0]);
        }

        execvp(exec_path, cmdargv);
        err(1, "failed to execute: %s", cmdargv[0]);

        return 1;
}

/* Standard file descriptor sanitization */
static void sanitize_std_fds(void) {
        /* Ensure stdin, stdout, stderr are opened */
        int fd = open(_PATH_DEVNULL, O_RDWR);
        if (fd < 0)
                err(1, "failed to open %s", _PATH_DEVNULL);

        while (fd <= 2) {
                fd++;
        }
        if (fd > 2)
                close(fd);
}

/* Environment sanitization */
static void sanitize_environment(void) {
    /* Remove dangerous environment variables */
    unsetenv("LD_PRELOAD");
    unsetenv("LD_LIBRARY_PATH");
}

/* Find executable in PATH */
static char* find_in_path(const char *prog, const char *path, char *result, size_t size) {
        struct stat st;

        /* If prog contains slash, check this path directly */
        if (strchr(prog, '/')) {
                if (access(prog, X_OK) == 0 && stat(prog, &st) == 0 && S_ISREG(st.st_mode)) {
                        strncpy(result, prog, size);
                        return result;
                }
                return NULL;
        }

        char *orig_p = NULL;
        char *p = strdup(path);
        if (!p) {
            return NULL;
        }
        orig_p = p;
        char *dir = strtok(p, ":");

        while (dir) {
                char fullpath[PATH_MAX];
                if (dir[0] == '\0') {
                        snprintf(fullpath, sizeof(fullpath), "./%s", prog);
                } else {
                        snprintf(fullpath, sizeof(fullpath), "%s/%s", dir, prog);
                }

                if (access(fullpath, X_OK) == 0 && stat(fullpath, &st) == 0 && S_ISREG(st.st_mode)) {
                        strncpy(result, fullpath, size);
                        free(orig_p);
                        return result;
                }

                dir = strtok(NULL, ":");
        }

        free(orig_p);
        return NULL;
}
