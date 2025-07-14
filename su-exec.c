/* set user and group id and exec */

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <err.h>
#include <errno.h>
#include <grp.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <limits.h>
#include <fcntl.h>
#include <paths.h>
#include <time.h>
#include <shadow.h>
#include <ctype.h>   /* For isalnum() */
#include <dirent.h>
#include <sys/wait.h>  /* For WEXITSTATUS */

/* Function declarations (C89 requires declarations before use) */
static int is_user_locked(const struct passwd *pw);
static void sanitize_std_fds(void);
static void sanitize_environment(void);
static char* find_in_path(const char *prog, const char *path, char *result, size_t size);
extern char **environ; /* Declare environ variable */

/* User lock detection function */
static int is_user_locked(const struct passwd *pw) {
        const char *passwd = pw->pw_passwd;
        if (passwd && (passwd[0] == '!' || passwd[0] == '*' || passwd[0] == 'L')) {
                return 1; /* Account locked */
        }

        /* Check /etc/login.deny file */
        FILE *deny_file = fopen("/etc/login.deny", "r");
        if (deny_file) {
                char line[1024];
                while (fgets(line, sizeof(line), deny_file)) {
                        /* Trim whitespace */
                        char *user = strtok(line, " \t\n");
                        if (!user) continue;

                        /* Check if user is in deny list */
                        if (strcmp(user, pw->pw_name) == 0) {
                                fclose(deny_file);
                                return 1; /* User in deny list */
                        }
                }
                fclose(deny_file);
        }

        return 0; /* Account not locked */
}

extern char **environ; /* 显式声明 environ 变量 */
extern int execvpe(const char *file, char *const argv[], char *const envp[]); /* 添加 execvpe 声明 */

/* Global variable for program name */
char *argv0;

/* Function declarations for C89 compliance */
static void usage(int exitcode);
static int is_user_locked(const struct passwd *pw);
static void sanitize_std_fds(void);
static void sanitize_environment(void);
static char* find_in_path(const char *prog, const char *path, char *result, size_t size);
static int is_valid_name(const char *name);

/* Name validation function */
static int is_valid_name(const char *name) {
    if (!name || !*name) return 0;

    const char *p = name;
    while (*p) {
        if (!(isalnum(*p) || *p == '_' || *p == '-' || *p == '.')) {
            return 0; /* 包含非法字符 */
        }
        p++;
    }
    return 1; /* 名称合法 */
}

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
                errx(1, "must be run as root");
        }

        char *user, *group, **cmdargv;
        char *end;
        char *path;
        char exec_path[PATH_MAX];

        uid_t uid = getuid();
        gid_t gid = getgid();

        argv0 = argv[0];
        if (argc < 3)
                usage(0);

        /* Save original user-spec for error messages */
        char *user_spec = strdup(argv[1]);
        if (!user_spec)
                err(1, "memory allocation failed");

        /* Prevent modification of original arguments */
        char *original_argv0 = strdup(argv[0]);
        if (!original_argv0)
                err(1, "memory allocation failed");

        /* Ensure standard file descriptors exist and are safely opened */
        sanitize_std_fds();

        /* 重置 umask */
        umask(S_IWGRP | S_IWOTH);

        /* 清理环境变量中的危险项 */
        sanitize_environment();

        user = strdup(argv[1]);  // 使用复制防止修改原始参数
        if (!user)
                err(1, "memory allocation failed");

        group = strchr(user, ':');
        if (group) {
                *group++ = '\0';
                // 验证组名长度
                long name_max = sysconf(_SC_LOGIN_NAME_MAX);
                if (name_max == -1) name_max = 32;  // Fallback

                if (strlen(group) >= name_max)
                        errx(1, "group name too long (max %ld chars)", name_max-1);
                if (!is_valid_name(group)) {
                    errx(1, "invalid group name: only alphanumeric/_-/. characters allowed");
                }
        }

        cmdargv = &argv[2];

        /* 确保PATH环境变量安全 */
        if (!getenv("PATH")) {
                setenv("PATH", "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", 1);
        }

        struct passwd *pw = NULL;
        /* Validate username format */
        /* Validate username format immediately */
        if (!is_valid_name(user)) {
            errx(1, "invalid username: only alphanumeric/_-/. allowed");
        }

        if (user[0] != '\0') {
                uid_t nuid = strtol(user, &end, 10);
                if (*end == '\0') {
                        /* 使用数字UID - 允许任意有效值 */
                        if (nuid < 0 || nuid > 65535) {
                            errx(1, "UID must be 0-65535 (got %d)", nuid);
                        }
                        uid = nuid;
                        pw = getpwuid(uid);  // 查询失败时pw=NULL仍继续执行
                } else {
                        /* 使用用户名 - 必须存在 */
                        struct passwd pwbuf;
                        char pwbuf_mem[PATH_MAX];

                        memset(&pwbuf, 0, sizeof(pwbuf));
                        memset(pwbuf_mem, 0, sizeof(pwbuf_mem));

                        if (getpwnam_r(user, &pwbuf, pwbuf_mem, sizeof(pwbuf_mem), &pw) != 0 || !pw) {
                                errx(1, "user '%s' does not exist", user);
                        }
                        uid = pw->pw_uid;

                        /* 仅对用户名检查锁定状态 */
                        if (is_user_locked(pw)) {
                                errx(1, "account '%s' is locked", user);
                        }
                }
        }



        if (group && group[0] != '\0') {
                /* When group is specified, ignore supplementary groups */
                pw = NULL;

                gid_t ngid = strtol(group, &end, 10);
                if (*end == '\0') {
                        /* 使用数字 GID */
                        if (ngid < 0 || ngid > 65535) {
                            errx(1, "GID must be 0-65535 (got %d)", ngid);
                        }
                        gid = ngid;
                } else {
                        /* 使用组名 */
                        struct group grpbuf;
                        char grpbuf_mem[PATH_MAX];
                        struct group *gr;

                        memset(&grpbuf, 0, sizeof(grpbuf));
                        memset(grpbuf_mem, 0, sizeof(grpbuf_mem));

                        if (getgrnam_r(group, &grpbuf, grpbuf_mem, sizeof(grpbuf_mem), &gr) != 0 || !gr) {
                                errx(1, "group '%s' does not exist", group);
                        }

                        gid = gr->gr_gid;
                }
        }

        /* 检查用户是否被锁定 */
        if (pw != NULL && is_user_locked(pw)) {
                errx(1, "user account locked: %s", user);
        }

        /* Set groups first */
        if (pw == NULL) {
                if (setgroups(1, &gid) < 0)
                        err(1, "setgroups(%i)", gid);
        } else {
                /* 获取组列表并检查数量 */
                int ngroups = NGROUPS_MAX;
                gid_t groups[NGROUPS_MAX];

                if (getgrouplist(pw->pw_name, gid, groups, &ngroups) == -1)
                        err(1, "getgrouplist");

                if (ngroups > NGROUPS_MAX)
                        errx(1, "too many groups (%d > %d)", ngroups, NGROUPS_MAX);

                if (setgroups(ngroups, groups) < 0)
                        err(1, "setgroups");
        }


        if (setgid(gid) < 0 || setuid(uid) < 0) {
                err(1, "permanent drop privileges failed");
        }

        (void)is_user_locked;  /* Suppress unused function warning */



        /* Set path for executable lookup */
        path = getenv("PATH");
        if (!path) {
            path = _PATH_DEFPATH;
        }

        /* Find executable in PATH */
        if (find_in_path(cmdargv[0], path, exec_path, sizeof(exec_path)) == NULL) {
            errx(1, "command not found: %s", cmdargv[0]);
        }

        /* Execute command */
        if (exec_path[0] == '\0') {
            errx(1, "empty executable path");
        }
        execvpe(exec_path, cmdargv, environ);
        err(1, "failed to execute %s", cmdargv[0]);

        free(user_spec);
        return 1;
}

/* 标准文件描述符安全化 */
static void sanitize_std_fds(void) {
        /* 如果 stdin、stdout、stderr 未打开，则打开 /dev/null */
        int fd = open(_PATH_DEVNULL, O_RDWR);
        if (fd < 0)
                err(1, "failed to open %s", _PATH_DEVNULL);

        while (fd <= 2) {  /* stdin, stdout, stderr */
                if (fd < 0)
                        fd = open(_PATH_DEVNULL, O_RDWR);
                else
                        fd++;
        }

        /* 关闭所有其他文件描述符 */
        int i;
        for (i = 3; i < FD_SETSIZE; i++) {
                close(i);
        }
}

/* Environment sanitization */
static void sanitize_environment(void) {
    /* Remove potentially dangerous environment variables */
    unsetenv("IFS");
    unsetenv("LD_PRELOAD");
    unsetenv("LD_LIBRARY_PATH");
    unsetenv("LD_TRACE_LOADED_OBJECTS");
    unsetenv("LD_BIND_NOW");
    unsetenv("LD_NOWARN");
    unsetenv("GCONV_PATH");
    unsetenv("GETCONF");
    unsetenv("ENV");
    unsetenv("BASH_ENV");
    unsetenv("PYTHONPATH");
    unsetenv("RUBYOPT");
    unsetenv("PERLLIB");

    /* Sanitize PATH if contains relative paths */
    char *path = getenv("PATH");
    if (path && strstr(path, "..")) {
        setenv("PATH", _PATH_DEFPATH, 1);
    }
}

/* 在路径中查找可执行文件 */
static char* find_in_path(const char *prog, const char *path, char *result, size_t size) {
        struct stat st;

        /* 如果prog包含斜杠，则直接检查该路径 */
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
