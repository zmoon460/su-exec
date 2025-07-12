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

/* Usage function */
static void usage(int exitcode)
{
        printf("Usage: %s user-spec command [args]\n", argv0);
        exit(exitcode);
}

int main(int argc, char *argv[])
{
        char *user, *group, **cmdargv;
        char *end;

        uid_t uid = getuid();
        gid_t gid = getgid();

        argv0 = argv[0];
        if (argc < 3)
                usage(0);

        /* Save original user-spec for error messages */
        char *user_spec = strdup(argv[1]);
        if (!user_spec)
                err(1, "memory allocation failed");

        /* 防止修改原始参数 */
        char *original_argv0 = strdup(argv[0]);
        if (!original_argv0)
                err(1, "内存分配失败");

        /* 确保标准文件描述符存在且安全打开 */
        sanitize_std_fds();

        /* 重置 umask */
        umask(S_IWGRP | S_IWOTH);

        /* 清理环境变量中的危险项 */
        sanitize_environment();

        user = strdup(argv[1]);  // 使用复制防止修改原始参数
        if (!user)
                err(1, "内存分配失败");

        group = strchr(user, ':');
        if (group) {
                *group++ = '\0';
                // 验证组名长度
#ifndef GROUP_NAME_MAX
#define GROUP_NAME_MAX 32
#endif

                if (strlen(group) >= GROUP_NAME_MAX)
                        err(1, "组名过长");
        }

        cmdargv = &argv[2];

        /* Find executable in PATH */
        char *path = getenv("PATH");
        if (!path)
                path = _PATH_DEFPATH;

        char exec_path[PATH_MAX];
        if (strchr(cmdargv[0], '/')) {
                /* Absolute or relative path */
                if (access(cmdargv[0], X_OK) == 0) {
                        strncpy(exec_path, cmdargv[0], sizeof(exec_path));
                } else {
                        err(1, "cannot access '%s'", cmdargv[0]);
                }
        } else {
                /* Search in PATH */
                if (find_in_path(cmdargv[0], path, exec_path, sizeof(exec_path)) == NULL) {
                        err(1, "cannot find executable '%s'", cmdargv[0]);
                }
        }

        struct passwd *pw = NULL;
        if (user[0] != '\0') {
                uid_t nuid = strtol(user, &end, 10);
                if (*end == '\0') {
                        /* 使用数字 UID */
                        uid = nuid;
                        pw = getpwuid(uid);
                } else {
                        // 使用用户名
                        struct passwd pwbuf;
                        char pwbuf_mem[PATH_MAX];

                        memset(&pwbuf, 0, sizeof(pwbuf));
                        memset(pwbuf_mem, 0, sizeof(pwbuf_mem));

                        if (getpwnam_r(user, &pwbuf, pwbuf_mem, sizeof(pwbuf_mem), &pw) != 0 || !pw) {
                                errx(1, "error: failed switching to \"%s\": unable to find user %s",
                                     user_spec, user);
                        }
                        uid = pw->pw_uid;

                        // 检查用户锁定状态
                        if (is_user_locked(pw)) {
                                errx(1, "error: failed switching to \"%s\": user is locked", user);
                        }
                }
        }

        /* If user is explicitly specified but not found, use current user */
        if (pw == NULL) {
                pw = getpwuid(getuid());
        }

        /* 如果仍然找不到用户信息，返回错误 */
        if (pw == NULL) {
                err(1, "无法获取用户信息");
        }

        /* 设置 HOME 环境变量 */
        if (pw != NULL && pw->pw_dir != NULL && pw->pw_dir[0] != '\0') {
                /* 直接使用用户家目录，不使用 realpath 避免将 /nonexistent 转换为 / */
                setenv("HOME", pw->pw_dir, 1);
        } else {
                setenv("HOME", "/", 1);
        }

        /* 如果用户有指定 shell，则设置 SHELL 环境变量 */
        if (pw != NULL && pw->pw_shell != NULL && pw->pw_shell[0] != '\0') {
                setenv("SHELL", pw->pw_shell, 1);
        } else {
                setenv("SHELL", "/bin/sh", 1);  /* 设置默认 SHELL */
        }

        if (group && group[0] != '\0') {
                /* 组被指定，忽略组列表以进行setgroups */
                pw = NULL;

                gid_t ngid = strtol(group, &end, 10);
                if (*end == '\0') {
                        /* 使用数字 GID */
                        gid = ngid;
                } else {
                        /* 使用组名 */
                        struct group grpbuf;
                        char grpbuf_mem[PATH_MAX];
                        struct group *gr;

                        memset(&grpbuf, 0, sizeof(grpbuf));
                        memset(grpbuf_mem, 0, sizeof(grpbuf_mem));

                        if (getgrnam_r(group, &grpbuf, grpbuf_mem, sizeof(grpbuf_mem), &gr) != 0 || !gr) {
                                errx(1, "error: failed switching to \"%s\": unable to find group %s",
                                     user_spec, group);
                        }

                        gid = gr->gr_gid;
                }
        }

        /* 检查用户是否被锁定 */
        if (pw != NULL && is_user_locked(pw)) {
                errx(1, "error: failed switching to \"%s\": user is locked", user);
        }

        /* Set groups first */
        if (pw == NULL) {
                if (setgroups(1, &gid) < 0)
                        err(1, "setgroups(%i)", gid);
        } else {
                if (initgroups(pw->pw_name, gid) < 0)
                        err(1, "initgroups");
        }


        if (setgid(gid) < 0)
                err(1, "setgid(%i)", gid);

        if (setuid(uid) < 0)
                err(1, "setuid(%i)", uid);

        (void)is_user_locked;  /* Suppress unused function warning */

        /* 设置 HOME 环境变量为用户家目录（如果尚未设置） */
        if (!getenv("HOME") && pw && pw->pw_dir && pw->pw_dir[0]) {
                setenv("HOME", pw->pw_dir, 1);
        }

        /* 设置 SHELL 环境变量为用户shell（如果尚未设置） */
        if (!getenv("SHELL") && pw && pw->pw_shell && pw->pw_shell[0]) {
                setenv("SHELL", pw->pw_shell, 1);
        }

        /* 确保标准文件描述符存在且安全打开 */
        sanitize_std_fds();

        /* 重置 umask */
        umask(S_IWGRP | S_IWOTH);

        /* Find executable in PATH */
        if (find_in_path(cmdargv[0], path, exec_path, sizeof(exec_path)) == NULL) {
                err(1, "cannot find executable '%s'", cmdargv[0]);
        }

        /* Execute command */
        execvpe(exec_path, cmdargv, environ);
        err(1, "exec failed for '%s'", cmdargv[0]);

        /* 清理敏感数据 */
        memset(original_argv0, 0, strlen(original_argv0));
        memset(user, 0, strlen(user));
        free(original_argv0);
        free(user);

        free(user_spec);
        return 1;
}

/* 标准文件描述符安全化 */
static void sanitize_std_fds(void) {
        /* 如果 stdin、stdout、stderr 未打开，则打开 /dev/null */
        int fd = open(_PATH_DEVNULL, O_RDWR);
        if (fd < 0)
                err(1, "无法打开 " _PATH_DEVNULL);

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

/* 环境变量清理 */
static void sanitize_environment(void) {
    /* 清除潜在危险的环境变量 */
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

    /* Keep original PATH if set */
    if (!getenv("PATH")) {
        setenv("PATH", "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", 1);
    }
    setenv("IFS", " \t\n", 1);

    /* 保留原始SHELL环境变量（如果存在） */
    const char *shell = getenv("SHELL");
    if (shell) {
        setenv("SHELL", shell, 0);
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

        char *p = strdup(path);
        if (!p) return NULL;

        char *orig_p = p;
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
