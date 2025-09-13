/*
 * secure_audit_logger.c - Secure audit log collector daemon (Final)
 *
 * This is a revised version to improve robustness and cross-platform compatibility.
 * Key changes:
 * - Replaced sscanf with a safer parsing method in load_config.
 * - Added O_EXCL to PID file open to prevent race conditions.
 * - Included setgroups() in privilege dropping for better security.
 * - Switched from Linux-specific fdatasync() to POSIX-compliant fsync().
 * - Adjusted permission checks for log files to be more robust.
 * - The main loop now uses non-blocking reads after select().
 * - Added a loop for write() to ensure full data is written.
 * - Reconfigured the signal handler with SA_RESTART for robustness.
 * - Added a loop for fsync() retries on temporary failures.
 * - Added logic to reload the config file on SIGHUP.
 * - Added FreeBSD-specific core dump disabling using setrlimit().
 * - Added unlink() to cleanup() to automatically remove the PID file.
 * - Added explicit permission checks (0600/0660) for log files.
 * - Truncated long log lines with a "..." suffix.
 * - Implemented configurable retry logic for write() and fsync() errors.
 * - Made FS_SYNC_INTERVAL and HEARTBEAT_INTERVAL configurable.
 * - Added a function to sanitize environment variable strings.
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <errno.h>
#include <pwd.h>
#include <signal.h>
#include <sys/file.h>
#include <syslog.h>
#include <time.h>
#include <grp.h>
#include <libgen.h>
#include <sys/select.h>
#include <sys/resource.h>

#ifdef __linux__
#include <sys/prctl.h>
#endif
#ifdef __FreeBSD__
#include <sys/resource.h>
#endif

#define CONF_FILE "/etc/secure_audit_logger.conf"
#define PID_FILE "/var/run/secure_audit_logger.pid"
#define MAX_PATH 512
#define MAX_LINE 2048

static volatile sig_atomic_t running = 1;
static volatile sig_atomic_t reopen_flag = 0;
static char log_dir[MAX_PATH] = {0};
static char log_rotation_type[32] = "none";
static int journal_replication_enabled = 0;
static int log_fd = -1;
static int pid_fd = -1;
static int fs_sync_interval = 100;
static int heartbeat_interval = 3600;
static int fs_retry_count = 3;

/*
 * Signal handler
 * SIGHUP: sets the reopen_flag
 * SIGTERM/SIGINT: sets the running flag to false
 */
void handle_signal(int sig) {
    if (sig == SIGHUP) {
        reopen_flag = 1;
    } else if (sig == SIGTERM || sig == SIGINT) {
        running = 0;
    }
}

/*
 * Proper daemonization routine
 * 1. Fork and exit parent
 * 2. Become session leader
 * 3. Fork again and exit parent to ensure no session leader
 * 4. Change working directory to root
 * 5. Close all file descriptors
 * 6. Redirect stdin, stdout, stderr to /dev/null
 */
void daemonize() {
    pid_t pid;

    // 1. Fork and exit parent process
    pid = fork();
    if (pid < 0) {
        perror("fork");
        exit(EXIT_FAILURE);
    }
    if (pid > 0) {
        exit(EXIT_SUCCESS);
    }

    // 2. Become session leader
    if (setsid() < 0) {
        perror("setsid");
        exit(EXIT_FAILURE);
    }

    // 3. Fork again to ensure we're not a session leader
    signal(SIGHUP, SIG_IGN); // Ignore SIGHUP for the second fork
    pid = fork();
    if (pid < 0) {
        perror("fork");
        exit(EXIT_FAILURE);
    }
    if (pid > 0) {
        exit(EXIT_SUCCESS);
    }

    // 4. Change current working directory to root
    if (chdir("/") < 0) {
        perror("chdir");
        exit(EXIT_FAILURE);
    }

    // 5. Close all open file descriptors
    long max_fd = sysconf(_SC_OPEN_MAX);
    if (max_fd < 0) max_fd = 256;
    for (int i = 0; i < max_fd; ++i) {
        close(i);
    }

    // 6. Redirect standard file descriptors
    open("/dev/null", O_RDWR);  // stdin
    dup(0);                     // stdout
    dup(0);                     // stderr
}

/*
 * Drops privileges to a specified user and group.
 * This function should be called after privileged operations.
 * It also clears supplementary groups for better security.
 */
int drop_privileges(const char *username, const char *groupname) {
    struct passwd *pw = getpwnam(username);
    if (pw == NULL) {
        syslog(LOG_ERR, "User '%s' not found.", username);
        return -1;
    }

    struct group *gr = getgrnam(groupname);
    if (gr == NULL) {
        syslog(LOG_ERR, "Group '%s' not found.", groupname);
        return -1;
    }
    
    // Clear supplementary groups for security
    if (setgroups(0, NULL) < 0) {
        syslog(LOG_ERR, "Failed to clear supplementary groups: %s", strerror(errno));
        return -1;
    }

    if (setgid(gr->gr_gid) < 0) {
        syslog(LOG_ERR, "Failed to set GID: %s", strerror(errno));
        return -1;
    }

    if (setuid(pw->pw_uid) < 0) {
        syslog(LOG_ERR, "Failed to set UID: %s", strerror(errno));
        return -1;
    }

    syslog(LOG_INFO, "Privileges dropped to user '%s' and group '%s'.", username, groupname);
    return 0;
}

/*
 * Load configuration from a file and validate log directory permissions.
 * Format: key=value
 * This version uses safe string operations to prevent buffer overflow.
 */
int load_config(const char *path) {
    FILE *fp = fopen(path, "r");
    if (!fp) {
        syslog(LOG_ERR, "Failed to open config file: %s", path);
        return -1;
    }
    
    char line[MAX_PATH * 2];
    
    while (fgets(line, sizeof(line), fp)) {
        // Strip leading/trailing whitespace and newline
        char *p = line;
        while (*p && (*p == ' ' || *p == '\t')) p++;
        
        char *eq_sign = strchr(p, '=');
        if (eq_sign) {
            *eq_sign = '\0';
            char *key = p;
            char *value = eq_sign + 1;
            
            // Trim trailing whitespace from key
            char *end_key = eq_sign - 1;
            while (end_key >= key && (*end_key == ' ' || *end_key == '\t')) {
                *end_key = '\0';
                end_key--;
            }
            
            // Trim trailing whitespace from value
            size_t len = strlen(value);
            while (len > 0 && (value[len-1] == ' ' || value[len-1] == '\t' || value[len-1] == '\n')) {
                value[len-1] = '\0';
                len--;
            }

            if (strcmp(key, "log_directory") == 0) {
                if (realpath(value, log_dir) == NULL) {
                    syslog(LOG_ERR, "Invalid log directory path in config: %s", value);
                    fclose(fp);
                    return -1;
                }
            } else if (strcmp(key, "log_rotation_type") == 0) {
                if (strcmp(value, "none") == 0 || strcmp(value, "daily") == 0) {
                    strncpy(log_rotation_type, value, sizeof(log_rotation_type) - 1);
                } else {
                    syslog(LOG_ERR, "Invalid log_rotation_type value in config: %s", value);
                }
            } else if (strcmp(key, "journal_replication") == 0) {
                if (strcmp(value, "yes") == 0) {
                    journal_replication_enabled = 1;
                } else if (strcmp(value, "no") == 0) {
                    journal_replication_enabled = 0;
                } else {
                    syslog(LOG_ERR, "Invalid journal_replication value in config: %s", value);
                }
            } else if (strcmp(key, "fs_sync_interval") == 0) {
                int val = atoi(value);
                if (val > 0) {
                    fs_sync_interval = val;
                }
            } else if (strcmp(key, "heartbeat_interval") == 0) {
                int val = atoi(value);
                if (val > 0) {
                    heartbeat_interval = val;
                }
            } else if (strcmp(key, "fs_retry_count") == 0) {
                int val = atoi(value);
                if (val >= 0) {
                    fs_retry_count = val;
                }
            }
        }
    }
    fclose(fp);
    
    if (log_dir[0] == '\0') {
        syslog(LOG_ERR, "Log directory not specified in config.");
        return -1;
    }

    struct stat st;
    if (stat(log_dir, &st) < 0) {
        syslog(LOG_ERR, "Failed to stat log directory '%s': %s", log_dir, strerror(errno));
        return -1;
    }
    
    if (!S_ISDIR(st.st_mode)) {
        syslog(LOG_ERR, "Log directory '%s' is not a directory.", log_dir);
        return -1;
    }
    
    if (st.st_uid != 0) {
        syslog(LOG_ERR, "Log directory '%s' is not owned by root.", log_dir);
        return -1;
    }

    // Check for insecure permissions (group or others having write permission)
    if ((st.st_mode & S_IWGRP) || (st.st_mode & S_IWOTH)) {
        syslog(LOG_ERR, "Log directory '%s' has insecure permissions.", log_dir);
        return -1;
    }

    return 0;
}

/*
 * Securely opens the log file, checking for ownership and permissions if it exists.
 * This is a privileged operation.
 */
int secure_open_logfile() {
    char log_file_path[MAX_PATH] = {0};
    if (strcmp(log_rotation_type, "daily") == 0) {
        time_t now = time(NULL);
        struct tm *t_local = localtime(&now);
        char date_str[16];
        if (t_local && strftime(date_str, sizeof(date_str), "%Y%m%d", t_local)) {
            snprintf(log_file_path, sizeof(log_file_path), "%s/audit-%s.log", log_dir, date_str);
        } else {
            snprintf(log_file_path, sizeof(log_file_path), "%s/audit.log", log_dir);
        }
    } else {
        snprintf(log_file_path, sizeof(log_file_path), "%s/audit.log", log_dir);
    }

    struct stat st;
    if (stat(log_file_path, &st) == 0) {
        // File exists, check ownership and permissions
        struct group *gr = getgrnam("logger");
        mode_t expected_mode = 0660; // We accept 0660 for log rotation, otherwise 0600
        if (gr && strcmp(log_rotation_type, "daily") != 0) {
            expected_mode = 0600;
        }

        // More robust permission check
        if (st.st_uid != 0 || st.st_gid != (gr ? gr->gr_gid : -1) || ((st.st_mode & 0777) != expected_mode)) {
             syslog(LOG_CRIT, "FATAL: Log file '%s' exists with incorrect permissions (expected %o, got %o). Aborting to prevent tampering.", log_file_path, expected_mode, st.st_mode & 0777);
             return -1;
        }
    }
    
    // Use 0660 permission so group can write for log rotation, otherwise 0600
    int fd = open(log_file_path, O_WRONLY | O_CREAT | O_APPEND | O_NOFOLLOW, (strcmp(log_rotation_type, "daily") == 0 ? 0660 : 0600));
    if (fd < 0) {
        syslog(LOG_ERR, "Failed to open log file at '%s': %s", log_file_path, strerror(errno));
    }
    return fd;
}

/*
 * Write PID file and acquire a lock.
 * This is a privileged operation. This version uses O_EXCL to prevent race conditions.
 */
int write_pidfile() {
    // Use O_EXCL to prevent race condition if file already exists
    int fd = open(PID_FILE, O_RDWR | O_CREAT | O_EXCL, 0600);
    if (fd < 0) {
        if (errno == EEXIST) {
            syslog(LOG_ERR, "PID file '%s' already exists. Another instance might be running.", PID_FILE);
            return -1;
        }
        syslog(LOG_ERR, "Failed to open PID file: %s", strerror(errno));
        return -1;
    }
    
    // Acquire exclusive lock immediately, non-blocking
    if (flock(fd, LOCK_EX | LOCK_NB) < 0) {
        syslog(LOG_ERR, "Failed to acquire lock on PID file: %s", strerror(errno));
        close(fd);
        return -1;
    }
    
    char buf[32];
    ftruncate(fd, 0); // Truncate the file to clear any old content
    snprintf(buf, sizeof(buf), "%d\n", getpid());
    write(fd, buf, strlen(buf));
    
    return fd;
}

/*
 * Securely writes a buffer to a file descriptor, ensuring all bytes are written.
 * @param fd The file descriptor to write to.
 * @param buf The buffer to write.
 * @param count The number of bytes to write.
 * @return 0 on success, -1 on permanent failure.
 */
int safe_write_all(int fd, const char *buf, size_t count) {
    size_t total_written = 0;
    int retry_count = 0;
    while (total_written < count) {
        ssize_t w = write(fd, buf + total_written, count - total_written);
        if (w < 0) {
            if (errno == EINTR) {
                continue; // Interrupted by a signal, retry
            }
            if ((errno == EAGAIN || errno == EWOULDBLOCK) && retry_count < fs_retry_count) {
                retry_count++;
                syslog(LOG_WARNING, "Temporary write error, retrying... (%d/%d)", retry_count, fs_retry_count);
                sleep(1);
                continue;
            }
            syslog(LOG_CRIT, "FATAL: Failed to write to log file after %d retries: %s", retry_count, strerror(errno));
            return -1;
        }
        total_written += w;
    }
    return 0;
}

/*
 * Securely flushes data to disk, retrying on temporary errors.
 * @param fd The file descriptor to flush.
 * @return 0 on success, -1 on permanent failure.
 */
int safe_fsync(int fd) {
    int retry_count = 0;
    while (fsync(fd) < 0) {
        if (errno == EINTR) {
            continue;
        }
        if ((errno == EAGAIN || errno == EWOULDBLOCK) && retry_count < fs_retry_count) {
            retry_count++;
            syslog(LOG_WARNING, "Temporary fsync error, retrying... (%d/%d)", retry_count, fs_retry_count);
            sleep(1);
            continue;
        }
        syslog(LOG_CRIT, "FATAL: Failed to flush data to disk after %d retries: %s", retry_count, strerror(errno));
        return -1;
    }
    syslog(LOG_DEBUG, "Data flushed to disk.");
    return 0;
}

/*
 * Sanitize a string by replacing control characters with spaces.
 * This prevents malformed log lines and injection of control characters.
 */
void sanitize_string(char *str, size_t max_len) {
    if (str == NULL) return;
    for (size_t i = 0; i < max_len && str[i] != '\0'; i++) {
        // Replace non-printable, non-space characters with a space
        if (str[i] < 32 || str[i] > 126) {
            str[i] = ' ';
        }
    }
}

/*
 * Cleanup function to be called on exit.
 */
void cleanup() {
    if (log_fd >= 0) close(log_fd);
    if (pid_fd >= 0) {
        close(pid_fd); // Close PID file descriptor to release lock
        unlink(PID_FILE); // Remove the PID file
    }
    syslog(LOG_INFO, "Secure audit logger stopped gracefully.");
    closelog();
}

int main(int argc, char *argv[]) {
    int daemonize_flag = 1;
    if (argc > 1 && strcmp(argv[1], "--no-daemon") == 0) {
        daemonize_flag = 0;
    }

    // Check for root privileges before doing anything else
    if (geteuid() != 0) {
        fprintf(stderr, "This program must be run as root to perform privileged operations.\n");
        exit(EXIT_FAILURE);
    }
    
    // Disable core dumps for security (OS-specific)
#ifdef __linux__
    prctl(PR_SET_DUMPABLE, 0);
#elif defined(__FreeBSD__)
    struct rlimit rlim = {0, 0};
    setrlimit(RLIMIT_CORE, &rlim);
#endif

    // First, set the umask to create files with strict permissions
    umask(077);

    // Initial logging setup before daemonization
    openlog("secure_audit_logger", LOG_PID | LOG_CONS, LOG_DAEMON);
    syslog(LOG_INFO, "Starting secure audit logger...");

    // Load config before daemonizing to get the log path
    if (load_config(CONF_FILE) < 0) {
        exit(EXIT_FAILURE);
    }
    
    if (daemonize_flag) {
        daemonize();
        // Re-open syslog after daemonization
        closelog();
        openlog("secure_audit_logger", LOG_PID, LOG_DAEMON);
        syslog(LOG_INFO, "Secure audit logger started successfully.");
    }
    
    // Perform privileged operations
    pid_fd = write_pidfile();
    if (pid_fd < 0) {
        syslog(LOG_ERR, "Another instance is already running.");
        exit(EXIT_FAILURE);
    }
    
    // Use the new secure_open_logfile function
    log_fd = secure_open_logfile();
    if (log_fd < 0) {
        close(pid_fd);
        exit(EXIT_FAILURE);
    }
    
    // Immediately drop privileges after privileged file operations
    // Note: 'nobody' user and 'logger' group are assumed to exist
    if (drop_privileges("nobody", "logger") < 0) {
        close(log_fd);
        close(pid_fd);
        exit(EXIT_FAILURE);
    }

    // Set up signal handlers using sigaction for reliability
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = handle_signal;
    sa.sa_flags = SA_RESTART; // Restart syscalls after signal
    sigaction(SIGTERM, &sa, NULL);
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGHUP, &sa, NULL);

    // Register cleanup function to be called on exit
    atexit(cleanup);

    char buf[MAX_LINE + 1]; // +1 for the null terminator
    int line_count = 0;
    time_t last_heartbeat = time(NULL);
    time_t last_daily_check = time(NULL);

    while (running) {
        // Check for reopen signal or daily rotation
        time_t current_time = time(NULL);
        if (reopen_flag || (strcmp(log_rotation_type, "daily") == 0 && (current_time / 86400) > (last_daily_check / 86400))) {
            syslog(LOG_INFO, "Re-opening/rotating log file and reloading config...");
            // Reload the config file first
            if (load_config(CONF_FILE) < 0) {
                syslog(LOG_CRIT, "FATAL: Failed to reload config on SIGHUP. Terminating.");
                running = 0;
                continue;
            }

            if (log_fd >= 0) {
                // Use safe_fsync before closing
                safe_fsync(log_fd);
                close(log_fd);
            }
            log_fd = secure_open_logfile();
            if (log_fd < 0) {
                syslog(LOG_CRIT, "FATAL: Failed to re-open log file: %s. Terminating.", strerror(errno));
                running = 0;
                continue;
            }
            reopen_flag = 0; // Reset the flag
            line_count = 0; // Reset line count after re-opening
            last_daily_check = current_time;
        }

        // Check for heartbeat
        if (current_time - last_heartbeat >= heartbeat_interval) {
            syslog(LOG_INFO, "Heartbeat: Secure audit logger is alive.");
            last_heartbeat = current_time;
        }

        // Use select with a timeout to make the read non-blocking
        fd_set fds;
        struct timeval tv;
        
        FD_ZERO(&fds);
        FD_SET(STDIN_FILENO, &fds);
        tv.tv_sec = 1;
        tv.tv_usec = 0;

        if (select(STDIN_FILENO + 1, &fds, NULL, NULL, &tv) > 0) {
            ssize_t bytes_read = read(STDIN_FILENO, buf, sizeof(buf) - 1);
            if (bytes_read > 0) {
                buf[bytes_read] = '\0';
                
                // Process the line and write to log
                char timestamp[64];
                time_t now = time(NULL);
                struct tm *t_local = localtime(&now);
                if (t_local) {
                    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", t_local);
                } else {
                    strcpy(timestamp, "YYYY-MM-DD HH:MM:SS");
                }

                struct passwd *pw = getpwuid(getuid());
                char *username = pw ? pw->pw_name : "UNKNOWN";
                struct group *gr = getgrgid(getgid());
                char *groupname = gr ? gr->gr_name : "UNKNOWN";

                char ttyname[64] = "UNKNOWN";
                char *ssh_tty = getenv("SSH_TTY");
                if (ssh_tty) {
                    sanitize_string(ssh_tty, strlen(ssh_tty));
                    strncpy(ttyname, basename(ssh_tty), sizeof(ttyname) - 1);
                    ttyname[sizeof(ttyname)-1] = '\0';
                } else {
                    char *tty = ttyname(STDIN_FILENO);
                    if (tty) {
                        strncpy(ttyname, tty, sizeof(ttyname) - 1);
                        ttyname[sizeof(ttyname)-1] = '\0';
                    }
                }

                char hostname[MAX_PATH] = "UNKNOWN";
                gethostname(hostname, sizeof(hostname));

                char *ssh_conn = getenv("SSH_CONNECTION");
                if (ssh_conn) {
                    sanitize_string(ssh_conn, strlen(ssh_conn));
                }
                
                buf[strcspn(buf, "\r\n")] = '\0';
                
                char final_log_line[MAX_LINE + 512];
                // Check and truncate SSH_CONNECTION to prevent excessively long logs
                char safe_ssh_conn[MAX_PATH];
                if (ssh_conn) {
                    strncpy(safe_ssh_conn, ssh_conn, sizeof(safe_ssh_conn) - 1);
                    safe_ssh_conn[sizeof(safe_ssh_conn) - 1] = '\0';
                } else {
                    strncpy(safe_ssh_conn, "N/A", sizeof(safe_ssh_conn));
                }
                
                int n = snprintf(final_log_line, sizeof(final_log_line),
                            "[%s] HOST=%s PID=%d R-UID=%d(%s) R-GID=%d(%s) TTY=%s SSH_CONN=\"%s\" %s\n",
                            timestamp, hostname, getpid(), getuid(), username, getgid(), groupname, ttyname,
                            safe_ssh_conn, buf);
                
                if (n >= sizeof(final_log_line)) {
                    // Truncate and add a suffix
                    size_t suffix_len = strlen("...(truncated)\n");
                    if (sizeof(final_log_line) > suffix_len) {
                        strncpy(final_log_line + sizeof(final_log_line) - suffix_len -1, "...(truncated)", sizeof(final_log_line) - (sizeof(final_log_line) - suffix_len) -1);
                        final_log_line[sizeof(final_log_line)-1] = '\n';
                    }
                }
                
                if (safe_write_all(log_fd, final_log_line, strlen(final_log_line)) < 0) {
                    running = 0; // Terminate on fatal write error
                }

                if (journal_replication_enabled) {
                    syslog(LOG_INFO, "%s", final_log_line);
                }

                line_count++;
                if (line_count >= fs_sync_interval) {
                    if (safe_fsync(log_fd) < 0) {
                        running = 0; // Terminate on fatal sync error
                    }
                    line_count = 0;
                }
            } else if (bytes_read == 0) {
                 // End of file
                running = 0;
            } else if (bytes_read < 0) {
                if (errno != EINTR && errno != EAGAIN) { // EINTR and EAGAIN are not fatal errors
                    syslog(LOG_ERR, "Read error from stdin: %s", strerror(errno));
                    sleep(1);
                }
            }
        }
    }

    // `cleanup` function will be called automatically on exit
    return 0;
}
