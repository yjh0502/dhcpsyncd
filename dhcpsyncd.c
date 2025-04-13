// dhcpsyncd.c
// OpenBSD daemon to monitor dhcpd.leases and update Unbound hosts.
// Compile with: cc -Wall -Wextra -o dhcpsyncd dhcpsyncd.c

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/event.h>
#include <sys/time.h>
#include <sys/wait.h>   // <--- Added for WIFEXITED etc.
#include <fcntl.h>
#include <signal.h>
#include <time.h>
#include <syslog.h>
#include <err.h>
#include <errno.h>
#include <limits.h>
#include <stdarg.h>

// --- Constants ---
#define PIDFILE         "/var/run/dhcpsyncd.pid"
#define LEASEFILE       "/var/db/dhcpd.leases"
#define HOSTSFILE       "/var/unbound/etc/hosts.local"
#define HOSTSFILE_TMP   "/var/unbound/etc/hosts.local.tmp" // For atomic write
#define UNBOUND_CONTROL "/usr/sbin/unbound-control"
#define RELOAD_CMD      "reload_keep_cache"
#define DAEMON_NAME     "dhcpsyncd"

// --- Globals ---
volatile sig_atomic_t terminate = 0;
volatile sig_atomic_t reload_request = 0; // For SIGHUP
int kq = -1; // kqueue descriptor
int lease_fd = -1; // lease file descriptor
char *current_hosts_content = NULL; // Store the last written content

// --- Data Structures ---
typedef struct {
    char *ip;
    char *hostname;
} LeaseEntry;

// --- Function Prototypes ---
void signal_handler(int sig);
int write_pidfile(const char *path);
void cleanup_resources(void); // Cleans up pidfile, fds, memory
int monitor_lease_file(const char *filename);
int process_leases(const char *lease_filename, const char *hosts_filename, const char *hosts_tmp_filename);
int parse_leases(FILE *fp, LeaseEntry **leases_out, size_t *count_out);
int compare_lease_entries(const void *a, const void *b);
char* generate_hosts_string(LeaseEntry *leases, size_t count);
int write_atomic(const char *dest_filename, const char *tmp_filename, const char *content);
int reload_unbound(void);
void free_leases(LeaseEntry *leases, size_t count);
void logmsg(int priority, const char *fmt, ...);

// --- Main Function ---
int main(void) {
    // 1. Set Timezone to UTC (as per script)
    if (setenv("TZ", "UTC", 1) == -1) {
        err(EXIT_FAILURE, "Failed to set TZ=UTC");
    }
    tzset(); // Apply the timezone setting

    // 2. Setup Logging
    openlog(DAEMON_NAME, LOG_PID | LOG_NDELAY, LOG_DAEMON);
    logmsg(LOG_INFO, "Starting up");

    // 3. Unveil necessary paths
    if (unveil(LEASEFILE, "r") == -1) {
        err(EXIT_FAILURE, "unveil %s failed", LEASEFILE);
    }
    if (unveil("/var/unbound/etc", "rwc") == -1) {
        err(EXIT_FAILURE, "unveil /var/unbound/etc failed");
    }
    if (unveil(PIDFILE, "rwc") == -1) {
       err(EXIT_FAILURE, "unveil %s failed", PIDFILE);
    }
    if (unveil(UNBOUND_CONTROL, "x") == -1) {
        err(EXIT_FAILURE, "unveil %s failed", UNBOUND_CONTROL);
    }
    // Block further unveil calls
    if (unveil(NULL, NULL) == -1) {
        err(EXIT_FAILURE, "unveil lock failed");
    }


    // 4. Daemonize
    if (daemon(0, 0) == -1) {
        logmsg(LOG_ERR, "Failed to daemonize: %s", strerror(errno));
        closelog();
        exit(EXIT_FAILURE);
    }

    logmsg(LOG_INFO, "Daemonized successfully");

    // 5. Write PID file
    if (write_pidfile(PIDFILE) == -1) {
        logmsg(LOG_ERR, "Failed to write PID file %s: %s", PIDFILE, strerror(errno));
        cleanup_resources(); // Cleanup needed even if PID fails after daemonize
        exit(EXIT_FAILURE);
    }
    logmsg(LOG_DEBUG, "PID file %s written", PIDFILE);


    // 6. Setup Signal Handlers
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = signal_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART; // Restart syscalls if possible

    if (sigaction(SIGTERM, &sa, NULL) == -1) {
        logmsg(LOG_ERR, "Failed to set SIGTERM handler: %s", strerror(errno));
        cleanup_resources(); exit(EXIT_FAILURE);
    }
    if (sigaction(SIGINT, &sa, NULL) == -1) {
        logmsg(LOG_ERR, "Failed to set SIGINT handler: %s", strerror(errno));
        cleanup_resources(); exit(EXIT_FAILURE);
    }
    if (sigaction(SIGHUP, &sa, NULL) == -1) {
        logmsg(LOG_ERR, "Failed to set SIGHUP handler: %s", strerror(errno));
        cleanup_resources(); exit(EXIT_FAILURE);
    }


    // 7. Pledge promises
    if (pledge("stdio rpath wpath cpath proc exec", NULL) == -1) {
         logmsg(LOG_ERR, "pledge failed: %s", strerror(errno));
         cleanup_resources(); exit(EXIT_FAILURE);
    }
     logmsg(LOG_DEBUG, "Pledged promises");


    // 8. Initialize kqueue and monitor lease file
    if ((kq = kqueue()) == -1) {
        logmsg(LOG_ERR, "kqueue failed: %s", strerror(errno));
        cleanup_resources(); exit(EXIT_FAILURE);
    }
    if (monitor_lease_file(LEASEFILE) == -1) {
        // monitor_lease_file logs errors
        cleanup_resources(); exit(EXIT_FAILURE);
    }


    // 9. Initial lease processing
    logmsg(LOG_INFO, "Performing initial lease processing");
    if (process_leases(LEASEFILE, HOSTSFILE, HOSTSFILE_TMP) == -1) {
        logmsg(LOG_WARNING, "Initial lease processing failed, continuing...");
        // Don't exit, maybe the file will become valid later
    }

    // 10. Main Loop
    logmsg(LOG_INFO, "Entering main event loop");
    while (!terminate) {
        struct kevent ev;
        int nev;

        // Check for pending reload first
        if (reload_request) {
             logmsg(LOG_INFO, "SIGHUP received, reprocessing leases");
             reload_request = 0; // Reset flag
             if (process_leases(LEASEFILE, HOSTSFILE, HOSTSFILE_TMP) == -1) {
                 logmsg(LOG_WARNING, "Lease processing triggered by SIGHUP failed");
             }
             // Continue to kevent wait after processing
        }

        // Wait for events
        nev = kevent(kq, NULL, 0, &ev, 1, NULL); // Wait indefinitely

        if (terminate) break; // Exit loop if signal received during wait

        if (nev == -1) {
            if (errno == EINTR) continue; // Interrupted by signal (likely caught by handler)
            logmsg(LOG_ERR, "kevent wait failed: %s", strerror(errno));
            break; // Exit loop on other errors
        }

        if (nev > 0) {
            if (ev.filter == EVFILT_VNODE) {
                logmsg(LOG_DEBUG, "Lease file event detected (flags: 0x%x)", ev.fflags);

                 // Check if file was deleted or renamed - need to re-monitor
                if (ev.fflags & (NOTE_DELETE | NOTE_RENAME)) {
                    logmsg(LOG_INFO, "Lease file deleted or renamed, re-monitoring");
                    if (lease_fd != -1) {
                         // No need to EV_DELETE explicitly, closing fd removes watches
                         close(lease_fd);
                         lease_fd = -1;
                    }
                    // Attempt to re-monitor immediately
                    if (monitor_lease_file(LEASEFILE) == -1) {
                        logmsg(LOG_ERR, "Failed to re-monitor lease file, stopping watch");
                        // Can't monitor anymore, maybe exit? Or just log and wait for SIGHUP?
                        // For now, just log and rely on SIGHUP or restart.
                        // break; // Option: Exit the loop if monitoring fails critically
                    } else {
                         // Successfully re-monitored, process the (potentially new) file
                         if (process_leases(LEASEFILE, HOSTSFILE, HOSTSFILE_TMP) == -1) {
                            logmsg(LOG_WARNING, "Lease processing after re-monitor failed");
                         }
                    }
                } else if (ev.fflags & (NOTE_WRITE | NOTE_ATTRIB | NOTE_EXTEND)) {
                     // File written to or attributes changed
                     logmsg(LOG_INFO, "Lease file changed, reprocessing");
                     if (process_leases(LEASEFILE, HOSTSFILE, HOSTSFILE_TMP) == -1) {
                         logmsg(LOG_WARNING, "Lease processing failed");
                     }
                }
            }
        }
    }

    // 11. Cleanup
    logmsg(LOG_INFO, "Shutting down");
    cleanup_resources();
    closelog();
    return EXIT_SUCCESS;
}

// --- Function Implementations ---

void logmsg(int priority, const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    vsyslog(priority, fmt, ap);
    va_end(ap);
}


void signal_handler(int sig) {
    switch (sig) {
        case SIGTERM:
        case SIGINT:
            // Use write for signal safety if possible, but syslog is generally okay here
            // write(STDERR_FILENO, "Signal received\n", 16); // Alternative for pure async-signal-safety
            logmsg(LOG_INFO, "Received signal %d, initiating shutdown", sig);
            terminate = 1;
            break;
        case SIGHUP:
             logmsg(LOG_INFO, "Received SIGHUP, scheduling reload");
             reload_request = 1;
            // Don't terminate, just flag for reload in main loop
            break;
        default:
            logmsg(LOG_WARNING, "Received unexpected signal %d", sig);
            break;
    }
}

int write_pidfile(const char *path) {
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd == -1) {
        return -1;
    }

    char pid_str[32];
    snprintf(pid_str, sizeof(pid_str), "%ld\n", (long)getpid());

    if (write(fd, pid_str, strlen(pid_str)) == -1) {
        int saved_errno = errno;
        close(fd); // Close before unlinking on error
        unlink(path);
        errno = saved_errno;
        return -1;
    }

    close(fd);
    return 0;
}

void cleanup_resources(void) {
    logmsg(LOG_DEBUG, "Cleaning up resources");
    if (kq != -1) {
        close(kq);
        kq = -1;
    }
    if (lease_fd != -1) {
        close(lease_fd);
        lease_fd = -1;
    }
    if (unlink(PIDFILE) == -1 && errno != ENOENT) {
        logmsg(LOG_WARNING, "Failed to remove PID file %s: %s", PIDFILE, strerror(errno));
    }
    free(current_hosts_content);
    current_hosts_content = NULL;
}

int monitor_lease_file(const char *filename) {
    struct kevent kev;

    if (lease_fd != -1) {
        close(lease_fd); // Close previous handle if re-monitoring
    }

    lease_fd = open(filename, O_RDONLY | O_NONBLOCK);
    if (lease_fd == -1) {
        // Log specific error only if file doesn't exist yet is ok, otherwise error
        if (errno == ENOENT) {
             logmsg(LOG_INFO, "Lease file %s does not exist yet, will monitor for creation", filename);
             // We still need to monitor the *directory* or retry opening later.
             // kqueue on a non-existent file descriptor won't work.
             // For simplicity here, we'll just fail to monitor initially if it's absent.
             // A more robust solution monitors the directory or retries open().
             return -1; // Let's treat non-existent as needing retry/re-monitor later
        } else {
            logmsg(LOG_ERR, "Failed to open lease file %s for monitoring: %s", filename, strerror(errno));
            return -1;
        }
    }

    // Monitor VNODE events: Write, Delete, Rename, Attribute changes, Extend
    EV_SET(&kev, lease_fd, EVFILT_VNODE, EV_ADD | EV_ENABLE | EV_CLEAR,
           NOTE_WRITE | NOTE_DELETE | NOTE_RENAME | NOTE_ATTRIB | NOTE_EXTEND, 0, (void *)filename); // Pass filename as udata for logging

    if (kevent(kq, &kev, 1, NULL, 0, NULL) == -1) {
        logmsg(LOG_ERR, "Failed to register kqueue event for %s: %s", filename, strerror(errno));
        close(lease_fd);
        lease_fd = -1;
        return -1;
    }
    logmsg(LOG_DEBUG, "Successfully monitoring %s (fd %d)", filename, lease_fd);
    return 0;
}


int process_leases(const char *lease_filename, const char *hosts_filename, const char *hosts_tmp_filename) {
    FILE *fp = NULL;
    LeaseEntry *leases = NULL;
    size_t lease_count = 0;
    char *new_hosts_content = NULL;
    int result = -1; // Assume failure

    fp = fopen(lease_filename, "r");
    if (!fp) {
        // Don't log an error if file just doesn't exist, might be temporary
        if (errno != ENOENT) {
            logmsg(LOG_ERR, "Failed to open lease file %s: %s", lease_filename, strerror(errno));
        } else {
             logmsg(LOG_DEBUG, "Lease file %s not found for processing.", lease_filename);
             // If file doesn't exist, treat as empty lease list. Clear existing hosts?
             // Current behavior: does nothing, keeps old hosts file.
             // Alternative: generate empty hosts content to clear entries.
             // Let's stick to current behavior unless specified otherwise.
        }
        goto cleanup; // Proceed as if lease list is empty
    }

    if (parse_leases(fp, &leases, &lease_count) == -1) {
        logmsg(LOG_ERR, "Failed to parse lease file %s", lease_filename);
        goto cleanup;
    }
    logmsg(LOG_INFO, "Parsed %zu active leases", lease_count);

    // Sort leases (important for consistent comparison)
    qsort(leases, lease_count, sizeof(LeaseEntry), compare_lease_entries);

    new_hosts_content = generate_hosts_string(leases, lease_count);
    if (!new_hosts_content) {
        logmsg(LOG_ERR, "Failed to generate hosts file content string");
        goto cleanup;
    }

    // Compare with current content
    if (current_hosts_content && strcmp(current_hosts_content, new_hosts_content) == 0) {
        logmsg(LOG_DEBUG, "Lease data unchanged, no update needed.");
        result = 0; // Success, but no action taken
        goto cleanup; // Skips writing and reloading
    }

    logmsg(LOG_INFO, "Lease data changed (or initial run), updating %s", hosts_filename);

    // Write to temporary file, then rename for atomicity
    if (write_atomic(hosts_filename, hosts_tmp_filename, new_hosts_content) == -1) {
         // Error logged in write_atomic
         goto cleanup;
    }

    // Reload Unbound
    if (reload_unbound() == -1) {
        // Error logged in reload_unbound
        goto cleanup; // Consider the update failed if reload fails
    }

    // Update successful, store the new content
    free(current_hosts_content);
    current_hosts_content = new_hosts_content;
    new_hosts_content = NULL; // Prevent double free in cleanup

    result = 0; // Success

cleanup:
    if (fp) fclose(fp);
    free_leases(leases, lease_count);
    free(new_hosts_content); // Free if not transferred to current_hosts_content
    return result;
}


// Replicates the awk logic
int parse_leases(FILE *fp, LeaseEntry **leases_out, size_t *count_out) {
    char line[1024];
    char current_ip[40] = {0}; // Max IPv6 length + safety
    char current_hostname[256] = {0}; // Max DNS label length
    time_t current_end_time = 0;
    int in_lease_block = 0;
    time_t now;

    LeaseEntry *leases = NULL;
    size_t count = 0;
    size_t capacity = 0;

    now = time(NULL);
    if (now == (time_t)-1) {
        logmsg(LOG_ERR, "Failed to get current time: %s", strerror(errno));
        return -1;
    }

    while (fgets(line, sizeof(line), fp)) {
        char *trimmed_line = line;
        // Trim leading/trailing whitespace/newline
        while (*trimmed_line == ' ' || *trimmed_line == '\t') trimmed_line++;
        char *end = trimmed_line + strlen(trimmed_line) - 1;
        while (end >= trimmed_line && (*end == '\n' || *end == '\r' || *end == ' ' || *end == '\t' || *end == ';')) { // Also trim trailing semicolon for robustness
            *end-- = '\0';
        }
        // Skip empty lines or comments
        if (*trimmed_line == '\0' || *trimmed_line == '#') continue;


        if (strncmp(trimmed_line, "lease ", 6) == 0) {
            if (sscanf(trimmed_line, "lease %39s {", current_ip) == 1) {
                in_lease_block = 1;
                current_hostname[0] = '\0';
                current_end_time = 0;
            } else {
                in_lease_block = 0;
            }
            continue;
        }

        if (in_lease_block) {
            if (strncmp(trimmed_line, "ends ", 5) == 0) {
                struct tm lease_tm = {0};
                char date_str[11]; // YYYY/MM/DD + null
                char time_str[9];  // HH:MM:SS + null
                int weekday;

                // Use corrected width specifier %8 for time_str
                if (sscanf(trimmed_line, "ends %d %10[0-9/] %8[0-9:] UTC", &weekday, date_str, time_str) == 3) {
                     char time_buf[20]; // YYYY/MM/DD HH:MM:SS + null
                     snprintf(time_buf, sizeof(time_buf), "%s %s", date_str, time_str);

                     if (strptime(time_buf, "%Y/%m/%d %H:%M:%S", &lease_tm) != NULL) {
                         current_end_time = mktime(&lease_tm);
                         if (current_end_time == (time_t)-1) {
                              logmsg(LOG_WARNING, "mktime failed for lease %s end time: %s", current_ip, time_buf);
                         }
                     } else {
                         logmsg(LOG_WARNING, "strptime failed for lease %s end time: %s (raw: %s)", current_ip, time_buf, trimmed_line);
                     }
                }
            } else if (strncmp(trimmed_line, "client-hostname ", 16) == 0) {
                char *start = strchr(trimmed_line, '"');
                char *end_quote = NULL;
                if (start) {
                    start++;
                    end_quote = strchr(start, '"');
                    if (end_quote) {
                        size_t len = end_quote - start;
                        if (len < sizeof(current_hostname)) {
                            memcpy(current_hostname, start, len); // Use memcpy as strncpy pads
                            current_hostname[len] = '\0';
                        } else {
                             logmsg(LOG_WARNING, "Hostname too long for lease %s: %s", current_ip, trimmed_line);
                             current_hostname[0] = '\0';
                        }
                    } else {
                         current_hostname[0] = '\0';
                    }
                } else {
                     current_hostname[0] = '\0';
                }
            } else if (strcmp(trimmed_line, "}") == 0) {
                // End of lease block
                if (in_lease_block && current_ip[0] != '\0' && current_hostname[0] != '\0' && current_end_time > now) {
                    if (count >= capacity) {
                        capacity = (capacity == 0) ? 16 : capacity * 2;
                        LeaseEntry *tmp = reallocarray(leases, capacity, sizeof(LeaseEntry));
                        if (!tmp) {
                            logmsg(LOG_ERR, "Failed to allocate memory for leases: %s", strerror(errno));
                            free_leases(leases, count);
                            return -1;
                        }
                        leases = tmp;
                    }

                    leases[count].ip = strdup(current_ip);
                    leases[count].hostname = strdup(current_hostname);
                    if (!leases[count].ip || !leases[count].hostname) {
                        logmsg(LOG_ERR, "Failed to duplicate strings for lease entry: %s", strerror(errno));
                        free(leases[count].ip);
                        free(leases[count].hostname);
                        free_leases(leases, count);
                        return -1;
                    }
                    count++;
                }
                // Reset state for next lease block
                in_lease_block = 0;
                current_ip[0] = '\0';
                current_hostname[0] = '\0';
                current_end_time = 0;
            }
        } // end if(in_lease_block)
    } // end while(fgets)

    *leases_out = leases;
    *count_out = count;
    return 0;
}

// Comparison function for qsort
int compare_lease_entries(const void *a, const void *b) {
    const LeaseEntry *entry_a = (const LeaseEntry *)a;
    const LeaseEntry *entry_b = (const LeaseEntry *)b;

    int ip_cmp = strcmp(entry_a->ip, entry_b->ip);
    if (ip_cmp != 0) {
        return ip_cmp;
    }
    return strcmp(entry_a->hostname, entry_b->hostname);
}


// Generates the string content for hosts.local
char* generate_hosts_string(LeaseEntry *leases, size_t count) {
    char *buffer = NULL;
    size_t buf_size = 0;
    FILE *memstream = open_memstream(&buffer, &buf_size);
    time_t current_time = time(NULL);

    if (!memstream) {
        logmsg(LOG_ERR, "open_memstream failed: %s", strerror(errno));
        return NULL;
    }

    // Use strftime for a cleaner timestamp format
    char time_str[64];
    strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S %Z", localtime(&current_time));
    fprintf(memstream, "# Generated by %s on %s\n", DAEMON_NAME, time_str);

    for (size_t i = 0; i < count; i++) {
        int valid_hostname = 1;
        for(char *p = leases[i].hostname; *p; ++p) {
            if (!((*p >= 'a' && *p <= 'z') || (*p >= 'A' && *p <= 'Z') || (*p >= '0' && *p <= '9') || *p == '-' || *p == '.')) {
                 if (*p == '_') continue;
                 logmsg(LOG_WARNING, "Skipping entry with potentially invalid hostname characters: %s -> %s", leases[i].ip, leases[i].hostname);
                 valid_hostname = 0;
                 break;
            }
            // Also check initial/trailing hyphen, double dots etc if needed
            if (p == leases[i].hostname && *p == '-') valid_hostname = 0;
            if (*p == '.' && *(p+1) == '.') valid_hostname = 0;
            if (*p == '.' && *(p+1) == '\0') valid_hostname = 0; // Trailing dot (allow for FQDN?) - unbound local-data usually wants non-FQDN.
            if (*p == '-' && *(p+1) == '\0') valid_hostname = 0; // Trailing hyphen

        }
        if (!valid_hostname) {
             logmsg(LOG_WARNING, "Skipping entry due to invalid hostname format: %s -> %s", leases[i].ip, leases[i].hostname);
             continue;
        }

        if (fprintf(memstream, "local-data: \"%s. IN A %s\"\n", leases[i].hostname, leases[i].ip) < 0) goto error;
        if (fprintf(memstream, "local-data: \"%s.5ml.io. IN A %s\"\n", leases[i].hostname, leases[i].ip) < 0) goto error;
    }

    if (fclose(memstream) != 0) {
        memstream = NULL;
        logmsg(LOG_ERR, "fclose on memstream failed: %s", strerror(errno));
        free(buffer);
        return NULL;
    }

    return buffer;

error:
    logmsg(LOG_ERR, "fprintf failed writing to memory stream: %s", strerror(errno));
    if (memstream) fclose(memstream);
    free(buffer);
    return NULL;
}

// Writes content to a temporary file, then renames it over the destination
int write_atomic(const char *dest_filename, const char *tmp_filename, const char *content) {
    int fd = open(tmp_filename, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd == -1) {
        logmsg(LOG_ERR, "Failed to open temporary hosts file %s: %s", tmp_filename, strerror(errno));
        return -1;
    }

    size_t len = strlen(content);
    if (write(fd, content, len) != (ssize_t)len) {
        logmsg(LOG_ERR, "Failed to write content to %s: %s", tmp_filename, strerror(errno));
        close(fd);
        unlink(tmp_filename);
        return -1;
    }

    if (fsync(fd) == -1) {
         logmsg(LOG_WARNING, "fsync failed for %s: %s", tmp_filename, strerror(errno));
    }

    if (close(fd) == -1) {
         logmsg(LOG_WARNING, "close failed for %s: %s", tmp_filename, strerror(errno));
    }


    if (rename(tmp_filename, dest_filename) == -1) {
        logmsg(LOG_ERR, "Failed to rename %s to %s: %s", tmp_filename, dest_filename, strerror(errno));
        unlink(tmp_filename);
        return -1;
    }

    logmsg(LOG_DEBUG, "Successfully wrote and renamed %s", dest_filename);
    return 0;
}

int reload_unbound(void) {
    pid_t pid;
    int status;

    logmsg(LOG_INFO, "Forking to execute: %s %s", UNBOUND_CONTROL, RELOAD_CMD);

    pid = fork();

    if (pid == -1) {
        // Fork failed
        logmsg(LOG_ERR, "Failed to fork to run unbound-control: %s", strerror(errno));
        return -1;
    } else if (pid == 0) {
        // --- Child Process ---
        char *argv[] = {
            UNBOUND_CONTROL, // Convention: argv[0] is the program path/name
            RELOAD_CMD,
            NULL            // Argument list must be NULL-terminated
        };
        // Optional: Provide environment variables if needed, otherwise NULL is fine.
        // char *envp[] = { "PATH=/usr/bin:/bin:/usr/sbin:/sbin", NULL };

        execve(UNBOUND_CONTROL, argv, NULL /* or envp */);

        // If execve returns, an error occurred
        logmsg(LOG_ERR, "execve failed for %s: %s", UNBOUND_CONTROL, strerror(errno));
        _exit(127); // Use _exit() in child after fork, 127 indicates exec error
        // --- End of Child ---
    } else {
        // --- Parent Process ---
        logmsg(LOG_DEBUG, "Waiting for child process %ld", (long)pid);

        // Wait for the specific child process to finish
        if (waitpid(pid, &status, 0) == -1) {
            logmsg(LOG_ERR, "waitpid failed for child %ld: %s", (long)pid, strerror(errno));
            return -1; // Error waiting for child
        }

        logmsg(LOG_DEBUG, "Child process %ld finished", (long)pid);

        // Check how the child terminated
        if (WIFEXITED(status)) {
            int exit_status = WEXITSTATUS(status);
            if (exit_status == 0) {
                logmsg(LOG_INFO, "Unbound reloaded successfully (child exited 0)");
                return 0; // Success
            } else {
                logmsg(LOG_ERR, "Unbound reload command failed (child exited %d)", exit_status);
                return -1; // Child indicated failure
            }
        } else if (WIFSIGNALED(status)) {
            logmsg(LOG_ERR, "Unbound reload command terminated by signal %d", WTERMSIG(status));
            return -1; // Child killed by signal
        } else {
            logmsg(LOG_ERR, "Unbound reload command terminated abnormally (status %d)", status);
            return -1; // Unknown termination
        }
        // --- End of Parent ---
    }
    // Should not be reached normally
    return -1;
}

// Frees memory allocated for the lease array
void free_leases(LeaseEntry *leases, size_t count) {
    if (!leases) return;
    for (size_t i = 0; i < count; i++) {
        free(leases[i].ip);
        free(leases[i].hostname);
    }
    free(leases);
}
