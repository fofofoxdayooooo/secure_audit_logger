/*
 * secure_audit_logger.c - Secure audit log collector daemon (Final)
 *
 * Features:
 * - Proper daemonization (forks, detaches from terminal) unless --no-daemon is used
 * - Reads lines from stdin
 * - Drops privileges to a non-privileged user (e.g., "nobody")
 * - Writes logs to a secure, configured directory
 * - Configurable via /etc/secure_audit_logger.conf
 * - PID file management (/var/run/secure_audit_logger.pid) with robust locking
 * - Improved data reliability with periodic fsync
 * - Enhanced logging with TTY, user, hostname, and SSH connection info
 * - Handles SIGHUP for external log rotation tools
 * - Supports simple daily log rotation via config file
 *
 * Security:
 * - O_APPEND + O_NOFOLLOW to avoid tampering
 * - umask(077) for strict permissions
 * - Drops to a non-privileged user after file creation
 * - Verifies log directory permissions
 * - Disables core dumps
 * - Prevents log file hijacking by checking ownership on rotation
 * - Supports optional dual logging to syslog/journald
 */

#define _GNU_SOURCE
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
#include <sys/prctl.h>
#include <libgen.h>

#define CONF_FILE "/etc/secure_audit_logger.conf"
#define PID_FILE "/var/run/secure_audit_logger.pid"
#define MAX_PATH 512
#define MAX_LINE 2048
#define FS_SYNC_INTERVAL 100 // Sync logs every 100 lines
#define HEARTBEAT_INTERVAL 3600 // Heartbeat log every 3600 seconds (1 hour)

static volatile sig_atomic_t running = 1;
static volatile sig_atomic_t reopen_flag = 0;
static char log_dir[MAX_PATH] = {0};
static char log_rotation_type[32] = "none";
static int journal_replication_enabled = 0;
static int log_fd = -1;
static int pid_fd = -1;

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
 */
int load_config(const char *path) {
    FILE *fp = fopen(path, "r");
    if (!fp) {
        syslog(LOG_ERR, "Failed to open config file: %s", path);
        return -1;
    }
    
    char line[MAX_PATH * 2];
    char key[MAX_PATH], value[MAX_PATH];
    
    while (fgets(line, sizeof(line), fp)) {
        // Strip leading/trailing whitespace and newline
        char *p = line;
        while (*p && (*p == ' ' || *p == '\t')) p++;
        if (sscanf(p, "%[^=]=%s", key, value) == 2) {
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
            }
        }
    }
    fclose(fp);
    
    if (log_dir[0] == '\0') {
        syslog(LOG_ERR, "Log directory not specified in config.");
        return -1;
    }

    // --- Directory permission validation added here ---
    struct stat st;
    if (stat(log_dir, &st) < 0) {
        syslog(LOG_ERR, "Failed to stat log directory '%s': %s", log_dir, strerror(errno));
        return -1;
    }
    
    // Check if it's a directory
    if (!S_ISDIR(st.st_mode)) {
        syslog(LOG_ERR, "Log directory '%s' is not a directory.", log_dir);
        return -1;
    }
    
    // Check ownership (must be root)
    if (st.st_uid != 0) {
        syslog(LOG_ERR, "Log directory '%s' is not owned by root.", log_dir);
        return -1;
    }

    // Check permissions explicitly. The group 'logger' should have write permission.
    mode_t mode = st.st_mode & 0777; // Mask to get only permission bits
    if (mode != 0770 && mode != 0700) {
        syslog(LOG_ERR, "Log directory '%s' has insecure permissions (expected 0770 or 0700). Current: %o", log_dir, mode);
        return -1;
    }
    // --- End of validation ---

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
            // Fallback to static file if date formatting fails
            snprintf(log_file_path, sizeof(log_file_path), "%s/audit.log", log_dir);
        }
    } else {
        snprintf(log_file_path, sizeof(log_file_path), "%s/audit.log", log_dir);
    }

    // Check if the file already exists and validate its permissions
    struct stat st;
    if (stat(log_file_path, &st) == 0) {
        // File exists, check ownership and permissions
        struct group *gr = getgrnam("logger");
        if (st.st_uid != 0 || st.st_gid != (gr ? gr->gr_gid : -1) || (st.st_mode & 0660) != 0660) {
            syslog(LOG_CRIT, "FATAL: Log file '%s' exists with incorrect permissions. Aborting to prevent tampering.", log_file_path);
            return -1;
        }
    }
    
    // Use 0660 permission so group can write for log rotation
    int fd = open(log_file_path, O_WRONLY | O_CREAT | O_APPEND | O_NOFOLLOW, 0660);
    if (fd < 0) {
        syslog(LOG_ERR, "Failed to open log file at '%s': %s", log_file_path, strerror(errno));
    }
    return fd;
}

/*
 * Write PID file and acquire a lock.
 * This is a privileged operation.
 */
int write_pidfile() {
    int fd = open(PID_FILE, O_RDWR | O_CREAT, 0600);
    if (fd < 0) {
        syslog(LOG_ERR, "Failed to open PID file: %s", strerror(errno));
        return -1;
    }
    
    // Acquire exclusive lock immediately, non-blocking
    if (flock(fd, LOCK_EX | LOCK_NB) < 0) {
        syslog(LOG_ERR, "Failed to acquire lock on PID file: %s", strerror(errno));
        close(fd);
        return -1;
    }
    
    // Check if another instance is running by reading the PID file
    char buf[32];
    ftruncate(fd, 0); // Truncate the file to clear any old content
    snprintf(buf, sizeof(buf), "%d\n", getpid());
    write(fd, buf, strlen(buf));
    
    return fd;
}

/*
 * Cleanup function to be called on exit.
 */
void cleanup() {
    if (log_fd >= 0) close(log_fd);
    if (pid_fd >= 0) close(pid_fd); // Close PID file descriptor to release lock
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
    
    // Disable core dumps for security
    prctl(PR_SET_DUMPABLE, 0);

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
            syslog(LOG_INFO, "Re-opening/rotating log file...");
            if (log_fd >= 0) {
                close(log_fd);
            }
            // Re-open the file securely
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
        if (current_time - last_heartbeat >= HEARTBEAT_INTERVAL) {
            syslog(LOG_INFO, "Heartbeat: Secure audit logger is alive.");
            last_heartbeat = current_time;
        }

        // Use select with a timeout to make the read non-blocking
        // This allows the heartbeat to work without blocking on stdin
        fd_set fds;
        struct timeval tv;
        
        FD_ZERO(&fds);
        FD_SET(STDIN_FILENO, &fds);
        tv.tv_sec = 1;
        tv.tv_usec = 0;

        if (select(STDIN_FILENO + 1, &fds, NULL, NULL, &tv) > 0) {
            // Read from stdin. fgets is blocking.
            if (fgets(buf, sizeof(buf), stdin) == NULL) {
                // Check for end-of-file (e.g., parent process piped and exited)
                if (feof(stdin)) {
                    running = 0;
                    continue;
                }
                // If it's not EOF, it's a read error
                syslog(LOG_ERR, "Read error from stdin: %s", strerror(errno));
                // A small sleep to prevent a tight loop on read errors
                sleep(1);
                continue;
            }

            // Check if the line was truncated
            if (strlen(buf) == MAX_LINE && buf[MAX_LINE-1] != '\n') {
                syslog(LOG_WARNING, "Input line truncated. MAX_LINE might be too small.");
                // Read and discard the rest of the long line
                int c;
                while ((c = getchar()) != '\n' && c != EOF);
            }

            // Add a timestamp and process information to the log entry before writing
            char timestamp[64];
            time_t now = time(NULL);
            struct tm *t_local = localtime(&now);
            if (t_local) {
                strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", t_local);
            } else {
                strcpy(timestamp, "YYYY-MM-DD HH:MM:SS");
            }

            // Get real user and group names
            struct passwd *pw = getpwuid(getuid());
            char *username = pw ? pw->pw_name : "UNKNOWN";
            struct group *gr = getgrgid(getgid());
            char *groupname = gr ? gr->gr_name : "UNKNOWN";

            // Get TTY name, prioritizing SSH_TTY
            char ttyname[64] = "UNKNOWN";
            char *ssh_tty = getenv("SSH_TTY");
            if (ssh_tty) {
                strncpy(ttyname, basename(ssh_tty), sizeof(ttyname) - 1);
                ttyname[sizeof(ttyname)-1] = '\0';
            } else {
                char *tty = ttyname(STDIN_FILENO);
                if (tty) {
                    strncpy(ttyname, tty, sizeof(ttyname) - 1);
                    ttyname[sizeof(ttyname)-1] = '\0';
                }
            }

            // Get hostname
            char hostname[MAX_PATH] = "UNKNOWN";
            gethostname(hostname, sizeof(hostname));

            // Get SSH connection info
            char *ssh_conn = getenv("SSH_CONNECTION");

            // Strip trailing newline from input buffer
            buf[strcspn(buf, "\r\n")] = '\0';
            
            // Prepare the final log message with additional info
            char final_log_line[MAX_LINE + 512];
            int n = snprintf(final_log_line, sizeof(final_log_line),
                     "[%s] HOST=%s PID=%d R-UID=%d(%s) R-GID=%d(%s) TTY=%s SSH_CONN=\"%s\" %s\n",
                     timestamp, hostname, getpid(), getuid(), username, getgid(), groupname, ttyname,
                     ssh_conn ? ssh_conn : "N/A", buf);
            
            // Check for truncation of the final log line
            if (n >= sizeof(final_log_line)) {
                 syslog(LOG_WARNING, "Final log line was truncated. Buffer might be too small.");
            }
            
            // Write the full line to the log file
            if (write(log_fd, final_log_line, strlen(final_log_line)) < 0) {
                syslog(LOG_CRIT, "FATAL: Failed to write to log file: %s. Terminating.", strerror(errno));
                running = 0;
            }

            // Optional: Replicate log to syslog/journald
            if (journal_replication_enabled) {
                syslog(LOG_INFO, "%s", final_log_line);
            }

            // Periodically sync data to disk
            line_count++;
            if (line_count >= FS_SYNC_INTERVAL) {
                if (fdatasync(log_fd) == 0) {
                    syslog(LOG_DEBUG, "Flushed %d lines to disk.", line_count);
                } else {
                    syslog(LOG_ERR, "Failed to flush data to disk: %s", strerror(errno));
                }
                line_count = 0;
            }
        }
    }

    // `cleanup` function will be called automatically on exit
    return 0;
}
