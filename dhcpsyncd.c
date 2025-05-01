// dhcpsyncd.c
// OpenBSD daemon to monitor dhcpd.leases and update Unbound hosts.
// Compile with: cc -Wall -Wextra -o dhcpsyncd dhcpsyncd.c

#include <arpa/inet.h> // For inet_pton
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h> // For struct in_addr
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/event.h>
#include <sys/socket.h> // For AF_INET
#include <sys/time.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>

// --- Constants ---
#define PIDFILE "/var/run/dhcpsyncd.pid"
#define LEASEFILE "/var/db/dhcpd.leases"
#define HOSTSFILE "/var/unbound/etc/hosts.local"
#define HOSTSFILE_TMP "/var/unbound/etc/hosts.local.tmp" // For atomic write
#define UNBOUND_CONTROL "/usr/sbin/unbound-control"
#define RELOAD_CMD "reload_keep_cache"
#define DAEMON_NAME "dhcpsyncd"

// --- Globals ---
volatile sig_atomic_t terminate = 0;
volatile sig_atomic_t reload_request = 0; // For SIGHUP
int kq = -1;                              // kqueue descriptor
int lease_fd = -1;                        // lease file descriptor
char *current_hosts_content = NULL;       // Store the last written content
int foreground = 0;

// Subnet filtering globals
int subnet_filter_enabled = 0;
struct in_addr target_subnet_addr;
int target_prefix;

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
int process_leases(const char *lease_filename, const char *hosts_filename,
                   const char *hosts_tmp_filename);
int parse_leases(FILE *fp, LeaseEntry **leases_out, size_t *count_out);
int compare_lease_entries(const void *a, const void *b);
char *generate_hosts_string(LeaseEntry *leases, size_t count);
int write_atomic(const char *dest_filename, const char *tmp_filename,
                 const char *content);
int reload_unbound(void);
void free_leases(LeaseEntry *leases, size_t count);
void logmsg(int priority, const char *fmt, ...);
int parse_subnet(const char *subnet_str);
int is_in_subnet(
    const char *ip_str); // Check if IP string is in the configured subnet

__dead void usage(void) {
  extern char *__progname;
  // Updated usage message
  fprintf(stderr, "usage: %s [-d] [-s subnet]\n", __progname);
  fprintf(stderr, "  -d: run in foreground\n");
  fprintf(stderr, "  -s subnet: only process leases within the specified "
                  "subnet (e.g., 192.168.1.0/24)\n");
  exit(1);
}

// --- Main Function ---
int main(int argc, char *argv[]) {
  int ch;
  char *subnet_str = NULL;

  // Add 's:' to getopt string
  while ((ch = getopt(argc, argv, "ds:")) != -1) {
    switch (ch) {
    case 'd':
      foreground = 1;
      break; // Use break instead of continue for clarity
    case 's':
      subnet_filter_enabled = 1;
      subnet_str = optarg;
      break; // Use break
    default:
      usage();
    }
  }
  argc -= optind;
  argv += optind;

  if (argc > 0) { // Check for extraneous arguments
    usage();
  }

  // 1. Parse Subnet (if provided) *before* dropping privileges
  if (subnet_filter_enabled && parse_subnet(subnet_str) == -1) {
    // Error logged in parse_subnet
    exit(EXIT_FAILURE);
  }

  // 2. Set Timezone to UTC (as per script)
  if (setenv("TZ", "UTC", 1) == -1) {
    // Use err directly here as syslog isn't open yet
    err(EXIT_FAILURE, "Failed to set TZ=UTC");
  }
  tzset(); // Apply the timezone setting

  // 3. Setup Logging
  openlog(DAEMON_NAME, LOG_PID | LOG_NDELAY, LOG_DAEMON);
  logmsg(LOG_INFO, "Starting up");
  if (subnet_filter_enabled) { // Log again now that syslog is open
    char net_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &target_subnet_addr, net_str, sizeof(net_str));
    logmsg(LOG_INFO, "Filtering enabled for subnet: %s/%d", net_str,
           target_prefix);
  }

  // 4. Unveil necessary paths
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

  // 5. Daemonize
  if (!foreground) {
    if (daemon(0, 0) == -1) {
      logmsg(LOG_ERR, "Failed to daemonize: %s", strerror(errno));
      closelog();
      exit(EXIT_FAILURE);
    }
    // Don't log after daemon() success here, parent might exit before log is
    // written Log after pidfile write instead
  }

  // 6. Write PID file
  if (write_pidfile(PIDFILE) == -1) {
    logmsg(LOG_ERR, "Failed to write PID file %s: %s", PIDFILE,
           strerror(errno));
    cleanup_resources(); // Cleanup needed even if PID fails after daemonize
    exit(EXIT_FAILURE);
  }
  // Log daemonization success and PID file write *after* it's written
  if (!foreground) {
    logmsg(LOG_INFO, "Daemonized successfully, PID %ld", (long)getpid());
  }
  logmsg(LOG_DEBUG, "PID file %s written", PIDFILE);

  // 7. Setup Signal Handlers
  struct sigaction sa;
  memset(&sa, 0, sizeof(sa));
  sa.sa_handler = signal_handler;
  sigemptyset(&sa.sa_mask);
  sa.sa_flags = SA_RESTART; // Restart syscalls if possible

  if (sigaction(SIGTERM, &sa, NULL) == -1) {
    logmsg(LOG_ERR, "Failed to set SIGTERM handler: %s", strerror(errno));
    cleanup_resources();
    exit(EXIT_FAILURE);
  }
  if (sigaction(SIGINT, &sa, NULL) == -1) {
    logmsg(LOG_ERR, "Failed to set SIGINT handler: %s", strerror(errno));
    cleanup_resources();
    exit(EXIT_FAILURE);
  }
  if (sigaction(SIGHUP, &sa, NULL) == -1) {
    logmsg(LOG_ERR, "Failed to set SIGHUP handler: %s", strerror(errno));
    cleanup_resources();
    exit(EXIT_FAILURE);
  }

  // 8. Pledge promises
  // No new promises needed for inet_pton or basic IP math
  if (pledge("stdio rpath wpath cpath proc exec", NULL) == -1) {
    logmsg(LOG_ERR, "pledge failed: %s", strerror(errno));
    cleanup_resources();
    exit(EXIT_FAILURE);
  }
  logmsg(LOG_DEBUG, "Pledged promises");

  // 9. Initialize kqueue and monitor lease file
  if ((kq = kqueue()) == -1) {
    logmsg(LOG_ERR, "kqueue failed: %s", strerror(errno));
    cleanup_resources();
    exit(EXIT_FAILURE);
  }
  if (monitor_lease_file(LEASEFILE) == -1) {
    // monitor_lease_file logs errors
    cleanup_resources();
    exit(EXIT_FAILURE);
  }

  // 10. Initial lease processing
  logmsg(LOG_INFO, "Performing initial lease processing");
  if (process_leases(LEASEFILE, HOSTSFILE, HOSTSFILE_TMP) == -1) {
    logmsg(LOG_WARNING, "Initial lease processing failed, continuing...");
    // Don't exit, maybe the file will become valid later
  }

  // 11. Main Loop
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

    if (terminate)
      break; // Exit loop if signal received during wait

    if (nev == -1) {
      if (errno == EINTR)
        continue; // Interrupted by signal (likely caught by handler)
      logmsg(LOG_ERR, "kevent wait failed: %s", strerror(errno));
      break; // Exit loop on other errors
    }

    if (nev > 0) {
      if (ev.filter == EVFILT_VNODE &&
          ev.ident ==
              (unsigned long)lease_fd) { // Check if event is for our lease fd
        logmsg(LOG_DEBUG, "Lease file event detected (flags: 0x%x)", ev.fflags);

        // Check if file was deleted or renamed - need to re-monitor
        if (ev.fflags & (NOTE_DELETE | NOTE_RENAME)) {
          logmsg(LOG_INFO, "Lease file deleted or renamed, re-monitoring");
          // No need to EV_DELETE explicitly, closing fd removes watches
          // associated with it
          close(lease_fd);
          lease_fd = -1;

          // Attempt to re-monitor immediately
          if (monitor_lease_file(LEASEFILE) == -1) {
            logmsg(LOG_ERR, "Failed to re-monitor lease file, stopping watch");
            // Consider breaking the loop or setting a retry timer
            // For now, rely on SIGHUP/restart
          } else {
            // Successfully re-monitored, process the (potentially new) file
            if (process_leases(LEASEFILE, HOSTSFILE, HOSTSFILE_TMP) == -1) {
              logmsg(LOG_WARNING, "Lease processing after re-monitor failed");
            }
          }
        } else if (ev.fflags & (NOTE_WRITE | NOTE_ATTRIB | NOTE_EXTEND |
                                NOTE_TRUNCATE)) { // Added TRUNCATE
          // File written to, truncated, or attributes changed
          logmsg(LOG_INFO, "Lease file changed, reprocessing");
          if (process_leases(LEASEFILE, HOSTSFILE, HOSTSFILE_TMP) == -1) {
            logmsg(LOG_WARNING, "Lease processing failed");
          }
        }
      } else if (ev.filter == EVFILT_VNODE) {
        // Event for a file descriptor we *thought* we closed? Log it.
        logmsg(LOG_WARNING, "Received VNODE event for unexpected fd %lu",
               ev.ident);
      }
    }
  }

  // 12. Cleanup
  logmsg(LOG_INFO, "Shutting down");
  cleanup_resources();
  closelog();
  return EXIT_SUCCESS;
}

// --- Function Implementations ---

// Parses the CIDR subnet string (e.g., "192.168.1.0/24")
// Stores network address in target_subnet_addr and netmask in target_netmask.
int parse_subnet(const char *subnet_str) {
  int prefix_len;
  struct in_addr ip_addr, ip_netmask;
  uint32_t mask; // Use uint32_t for bit shifting

  prefix_len = inet_net_pton(AF_INET, subnet_str, &ip_addr, sizeof(ip_addr));
  if (prefix_len < 0) {
    perror("inet_net_pton");
    return 1;
  }
  mask = 0xFFFFFFFFU << (32 - prefix_len);

  target_prefix = prefix_len;
  ip_netmask.s_addr = htonl(mask);
  target_subnet_addr.s_addr = ip_addr.s_addr & ip_netmask.s_addr;

  return 0; // Success
}

// Check if the given IP address string falls within the configured subnet
int is_in_subnet(const char *ip_str) {
  struct in_addr lease_ip_addr;

  // If filtering isn't enabled, always return true
  if (!subnet_filter_enabled) {
    return 1;
  }

  // Parse the lease IP string
  if (inet_pton(AF_INET, ip_str, &lease_ip_addr) != 1) {
    logmsg(LOG_WARNING,
           "Failed to parse lease IP address '%s' for subnet check", ip_str);
    return 0; // Treat parse failure as not in subnet
  }

  // Check if (lease_ip & netmask) == target_subnet_address
  uint32_t mask = 0xFFFFFFFFU << (32 - target_prefix);
  return (lease_ip_addr.s_addr & htonl(mask)) == target_subnet_addr.s_addr;
}

void logmsg(int priority, const char *fmt, ...) {
  va_list ap;
  va_start(ap, fmt);
  if (foreground) {
    // Add timestamp and level prefix when running in foreground for clarity
    time_t now = time(NULL);
    char timebuf[30];
    strftime(timebuf, sizeof(timebuf), "%Y-%m-%d %H:%M:%S", localtime(&now));
    const char *level = (priority == LOG_ERR)       ? "ERR"
                        : (priority == LOG_WARNING) ? "WARN"
                        : (priority == LOG_INFO)    ? "INFO"
                        : (priority == LOG_DEBUG)   ? "DEBUG"
                                                    : "UNK";
    fprintf(stdout, "[%s] [%s] ", timebuf, level);
    vfprintf(stdout, fmt, ap);
    fprintf(stdout, "\n");
    fflush(stdout); // Ensure it's visible immediately
  } else {
    vsyslog(priority, fmt, ap);
  }
  va_end(ap);
}

void signal_handler(int sig) {
  // This function is mostly safe for signals as syslog is generally considered
  // safe, and atomics are used. Direct file IO or complex logic should be
  // avoided.
  switch (sig) {
  case SIGTERM:
  case SIGINT:
    // Use write for highest signal safety if paranoia is high, but logmsg is
    // likely fine. write(STDERR_FILENO, "Signal received, shutting down\n",
    // 30); // Alternative
    terminate = 1;
    // No syslog call here - let main loop detect terminate flag and log
    // shutdown message.
    break;
  case SIGHUP:
    reload_request = 1;
    // No syslog call here - let main loop detect flag and log reload message.
    break;
  default:
    // write(STDERR_FILENO, "Unexpected signal\n", 18); // Alternative
    // Avoid logging unknown signals from handler if possible, maybe flag it?
    // For now, we keep the log, but be aware it's less safe than setting a
    // flag.
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
    close(fd);    // Close before unlinking on error
    unlink(path); // Attempt removal on write error
    errno = saved_errno;
    return -1;
  }

  // fsync pid file for robustness? Often overkill but possible.
  // if (fsync(fd) == -1) { /* Handle error */ }

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
  // Only try to unlink if not in foreground (or based on pidfile write
  // success?) If pid write failed, unlink might have already happened. Check
  // existence before unlinking or just ignore ENOENT.
  if (unlink(PIDFILE) == -1 && errno != ENOENT) {
    logmsg(LOG_WARNING, "Failed to remove PID file %s: %s", PIDFILE,
           strerror(errno));
  }
  free(current_hosts_content);
  current_hosts_content = NULL;
}

int monitor_lease_file(const char *filename) {
  struct kevent kev;

  if (lease_fd != -1) {
    // Should not happen if called correctly, but defensively close.
    logmsg(LOG_WARNING, "Closing existing lease_fd (%d) in monitor_lease_file",
           lease_fd);
    close(lease_fd);
    lease_fd = -1;
  }

  lease_fd =
      open(filename, O_RDONLY | O_NONBLOCK | O_CLOEXEC); // Added O_CLOEXEC
  if (lease_fd == -1) {
    if (errno == ENOENT) {
      logmsg(
          LOG_INFO,
          "Lease file %s does not exist yet, will retry on next event/SIGHUP",
          filename);
      // Cannot monitor a non-existent file with VNODE. Rely on SIGHUP or later
      // modification event that might trigger re-monitoring logic. Returning 0
      // allows loop to continue. A better approach might involve monitoring the
      // parent directory for file creation.
      return 0; // Indicate monitoring not active, but not a fatal error
    } else {
      logmsg(LOG_ERR, "Failed to open lease file %s for monitoring: %s",
             filename, strerror(errno));
      return -1; // Fatal error opening file
    }
  }

  // Monitor VNODE events: Write, Delete, Rename, Attribute changes, Extend,
  // Truncate
  EV_SET(&kev, lease_fd, EVFILT_VNODE, EV_ADD | EV_ENABLE | EV_CLEAR,
         NOTE_WRITE | NOTE_DELETE | NOTE_RENAME | NOTE_ATTRIB | NOTE_EXTEND |
             NOTE_TRUNCATE,
         0, (void *)filename); // Pass filename as udata for logging (optional)

  if (kevent(kq, &kev, 1, NULL, 0, NULL) == -1) {
    logmsg(LOG_ERR, "Failed to register kqueue event for %s (fd %d): %s",
           filename, lease_fd, strerror(errno));
    close(lease_fd);
    lease_fd = -1;
    return -1; // Fatal kqueue error
  }
  logmsg(LOG_DEBUG, "Successfully monitoring %s (fd %d)", filename, lease_fd);
  return 0; // Monitoring successfully started
}

// Skips the first line (comment generated by this daemon) for comparison
const char *skip_first_line(const char *str) {
  if (!str) {
    return NULL;
  }
  const char *next_line = strchr(str, '\n');
  return (next_line != NULL) ? next_line + 1
                             : str; // Return original if no newline
}

// Compares content skipping the first line
int compare_content(const char *file0, const char *file1) {
  if (!file0 || !file1) {
    return (file0 == file1) ? 0 : -1; // Nulls match, null vs non-null don't
  }
  const char *content0 = skip_first_line(file0);
  const char *content1 = skip_first_line(file1);
  if (!content0 || !content1) {
    // Handle case where one or both files have only one line (or less)
    return (content0 == content1) ? 0 : (content0 ? 1 : -1);
  }
  return strcmp(content0, content1);
}

int process_leases(const char *lease_filename, const char *hosts_filename,
                   const char *hosts_tmp_filename) {
  FILE *fp = NULL;
  LeaseEntry *leases = NULL;
  size_t lease_count = 0;
  char *new_hosts_content = NULL;
  int result = -1; // Assume failure

  fp = fopen(lease_filename, "r");
  if (!fp) {
    // Don't log an error if file just doesn't exist, might be temporary
    if (errno != ENOENT) {
      logmsg(LOG_ERR, "Failed to open lease file %s: %s", lease_filename,
             strerror(errno));
      // If we can't open it (and it's not ENOENT), it's an error state.
      return -1; // Return error, don't proceed with empty list
    } else {
      logmsg(LOG_DEBUG, "Lease file %s not found for processing.",
             lease_filename);
    }
  } else {
    // File opened successfully, parse it.
    if (parse_leases(fp, &leases, &lease_count) == -1) {
      logmsg(LOG_ERR, "Failed to parse lease file %s", lease_filename);
      fclose(fp);
      return -1; // Parsing failed, return error
    }
    fclose(fp); // Close file pointer once parsing is done
    fp = NULL;
    logmsg(LOG_INFO, "Parsed %zu leases%s", lease_count,
           subnet_filter_enabled ? " matching subnet" : "");
  }

  // Sort leases (important for consistent comparison and output)
  qsort(leases, lease_count, sizeof(LeaseEntry), compare_lease_entries);

  new_hosts_content = generate_hosts_string(leases, lease_count);
  if (!new_hosts_content) {
    logmsg(LOG_ERR, "Failed to generate hosts file content string");
    goto cleanup; // Uses goto for centralized cleanup
  }

  // Compare with current content (skipping first line)
  if (current_hosts_content != NULL &&
      compare_content(current_hosts_content, new_hosts_content) == 0) {
    logmsg(LOG_DEBUG, "Lease data unchanged, no update needed.");
    result = 0; // Success, but no action taken
    // Free the newly generated content as it's identical and not needed
    free(new_hosts_content);
    new_hosts_content = NULL;
    goto cleanup; // Skips writing and reloading
  }

  logmsg(LOG_INFO,
         "Lease data changed (or initial run/empty file), updating %s",
         hosts_filename);

  // Write to temporary file, then rename for atomicity
  if (write_atomic(hosts_filename, hosts_tmp_filename, new_hosts_content) ==
      -1) {
    // Error logged in write_atomic
    goto cleanup;
  }

  // Reload Unbound
  if (reload_unbound() == -1) {
    // Error logged in reload_unbound
    // Consider the update failed if reload fails
    // Should we restore the old hosts file? Maybe too complex. Log and
    // continue. result remains -1 if reload fails? Let's set it to error.
    result = -1;
    goto cleanup;
  }

  // Update successful, store the new content
  free(current_hosts_content);               // Free the old content
  current_hosts_content = new_hosts_content; // Store the new content
  new_hosts_content = NULL;                  // Prevent double free in cleanup

  result = 0; // Success

cleanup:
  // fp is already closed if it was opened
  free_leases(leases, lease_count);
  free(new_hosts_content); // Free if not transferred to current_hosts_content
                           // or if comparison matched
  return result;
}

// Replicates the awk logic, adding subnet filtering
int parse_leases(FILE *fp, LeaseEntry **leases_out, size_t *count_out) {
  char line[1024];
  char current_ip[INET_ADDRSTRLEN] = {0}; // Use INET_ADDRSTRLEN
  char current_hostname[256] = {0};       // Max DNS label length
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

  int line_num = 0;
  while (fgets(line, sizeof(line), fp)) {
    line_num++;
    char *trimmed_line = line;
    // Trim leading whitespace
    while (*trimmed_line == ' ' || *trimmed_line == '\t')
      trimmed_line++;
    // Trim trailing whitespace/newline/semicolon
    char *end = trimmed_line + strlen(trimmed_line) - 1;
    while (end >= trimmed_line &&
           (*end == '\n' || *end == '\r' || *end == ' ' || *end == '\t' ||
            *end == ';')) {
      *end-- = '\0';
    }
    // Skip empty lines or comments
    if (*trimmed_line == '\0' || *trimmed_line == '#')
      continue;

    if (strncmp(trimmed_line, "lease ", 6) == 0) {
      if (sscanf(trimmed_line, "lease %15s {", current_ip) == 1) {
        // Validate IP format basic check here before proceeding? Optional.
        struct in_addr tmp_addr;
        if (inet_pton(AF_INET, current_ip, &tmp_addr) != 1) {
          logmsg(LOG_WARNING, "Line %d: Invalid IP format in lease line: %s",
                 line_num, trimmed_line);
          current_ip[0] = '\0'; // Invalidate IP
          in_lease_block = 0;   // Don't enter block
        } else {
          in_lease_block = 1;
          current_hostname[0] = '\0';
          current_end_time = 0;
        }
      } else {
        logmsg(LOG_WARNING, "Line %d: Malformed lease line: %s", line_num,
               trimmed_line);
        in_lease_block = 0;
      }
      continue;
    }

    if (in_lease_block) {
      if (strncmp(trimmed_line, "ends ", 5) == 0) {
        struct tm lease_tm = {0};
        char date_str[11]; // YYYY/MM/DD + null
        char time_str[9];  // HH:MM:SS + null

        // Example: ends 4 2023/10/27 10:00:00 UTC; (UTC is not always present)
        // Scan for the core date/time parts first. Allow missing UTC keyword.
        if (sscanf(trimmed_line, "ends %*d %10[0-9/ ] %8[0-9:]", date_str,
                   time_str) == 2) {
          // strptime expects YYYY/MM/DD HH:MM:SS
          char time_buf[20];
          snprintf(time_buf, sizeof(time_buf), "%s %s", date_str, time_str);

          // IMPORTANT: dhcpd.leases times are usually GMT/UTC.
          // strptime uses local timezone by default. We need timegm or
          // equivalent. OpenBSD libc has timegm. We already set TZ=UTC so
          // mktime should work correctly here.
          if (strptime(time_buf, "%Y/%m/%d %H:%M:%S", &lease_tm) != NULL) {
            current_end_time = mktime(&lease_tm); // mktime respects TZ=UTC
            if (current_end_time == (time_t)-1) {
              logmsg(LOG_WARNING,
                     "Line %d: mktime failed for lease %s end time: %s",
                     line_num, current_ip, time_buf);
              current_end_time = 0; // Mark as invalid
            }
          } else {
            logmsg(
                LOG_WARNING,
                "Line %d: strptime failed for lease %s end time: %s (raw: %s)",
                line_num, current_ip, time_buf, trimmed_line);
            current_end_time = 0; // Mark as invalid
          }
        } else {
          logmsg(LOG_WARNING, "Line %d: Malformed 'ends' line for lease %s: %s",
                 line_num, current_ip, trimmed_line);
          current_end_time = 0; // Mark as invalid
        }
      } else if (strncmp(trimmed_line, "client-hostname ", 16) == 0) {
        char *start = strchr(trimmed_line, '"');
        char *end_quote = NULL;
        current_hostname[0] = '\0'; // Reset hostname
        if (start) {
          start++; // Move past the opening quote
          end_quote = strchr(start, '"');
          if (end_quote) {
            size_t len = end_quote - start;
            if (len > 0 &&
                len < sizeof(current_hostname)) { // Ensure non-empty and fits
              memcpy(current_hostname, start, len);
              current_hostname[len] = '\0';
              // Add validation for hostname characters here?
              // E.g., check for invalid chars like spaces, etc.
            } else if (len >= sizeof(current_hostname)) {
              logmsg(LOG_WARNING, "Line %d: Hostname too long for lease %s: %s",
                     line_num, current_ip, trimmed_line);
            } // else len == 0, keep hostname empty
          } else {
            logmsg(LOG_WARNING,
                   "Line %d: Malformed client-hostname (missing closing quote) "
                   "for lease %s: %s",
                   line_num, current_ip, trimmed_line);
          }
        } else {
          // Handle case where hostname is not quoted? e.g., client-hostname
          // myhost; Standard ISC dhcpd usually quotes it. If needed, add logic
          // here.
          logmsg(LOG_DEBUG,
                 "Line %d: client-hostname format may not be quoted for lease "
                 "%s: %s",
                 line_num, current_ip, trimmed_line);
        }
      } else if (strcmp(trimmed_line, "}") == 0) {
        // End of lease block
        // Check if lease is active (time) and has required fields (IP,
        // hostname)
        if (in_lease_block && current_ip[0] != '\0' &&
            current_hostname[0] != '\0' && current_end_time > now &&
            (!subnet_filter_enabled || is_in_subnet(current_ip))) {
          size_t idx = count;
          for (size_t i = 0; i < count; i++) {
            if (strcmp(leases[i].ip, current_ip) == 0 ||
                strcmp(leases[i].hostname, current_hostname) == 0) {
              logmsg(LOG_DEBUG, "Updating entry for %s / %s", current_ip,
                     current_hostname);
              idx = i;
              break;
            }
          }

          // Ensure capacity
          if (idx >= capacity) {
            size_t old_capacity = capacity;
            capacity = (capacity == 0) ? 16 : capacity * 2;
            LeaseEntry *tmp = recallocarray(leases, old_capacity, capacity,
                                            sizeof(LeaseEntry));
            if (!tmp) {
              logmsg(LOG_ERR, "Failed to reallocate memory for leases: %s",
                     strerror(errno));
              free_leases(leases, count);
              return -1;
            }
            leases = tmp;
          }

          // Free old strings if overwriting
          if (idx < count) {
            free(leases[idx].ip);
            free(leases[idx].hostname);
          }

          // Allocate and copy new strings
          leases[idx].ip = strdup(current_ip);
          leases[idx].hostname = strdup(current_hostname);

          if (!leases[idx].ip || !leases[idx].hostname) {
            logmsg(LOG_ERR, "Failed to duplicate strings for lease entry: %s",
                   strerror(errno));
            free_leases(leases, count); // Free everything allocated so far
            return -1;
          }

          // If it was a new entry, increment count
          if (idx == count) {
            count++;
          }
        } else if (in_lease_block && current_end_time <= now &&
                   current_end_time != 0) {
          // logmsg(LOG_DEBUG, "Skipping expired lease for IP %s", current_ip);
        } else if (in_lease_block &&
                   (current_ip[0] == '\0' || current_hostname[0] == '\0')) {
          /*
          logmsg(LOG_DEBUG, "Skipping incomplete lease block ending at line %d",
            line_num);
          */
        }

        // Reset state for next lease block regardless of success
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

  // Primary sort by hostname
  int host_cmp = strcmp(entry_a->hostname, entry_b->hostname);
  if (host_cmp != 0) {
    return host_cmp;
  }
  // Secondary sort by IP if hostnames are identical (should be rare)
  return strcmp(entry_a->ip, entry_b->ip);
}

// Generates the string content for hosts.local
char *generate_hosts_string(LeaseEntry *leases, size_t count) {
  char *buffer = NULL;
  size_t buf_size = 0;
  FILE *memstream = open_memstream(&buffer, &buf_size);
  time_t current_time_t;
  struct tm current_tm;
  char time_str[64];

  if (!memstream) {
    logmsg(LOG_ERR, "open_memstream failed: %s", strerror(errno));
    return NULL;
  }

  current_time_t = time(NULL);
  localtime_r(&current_time_t, &current_tm); // Use re-entrant version
  // Format timestamp according to RFC 3339 / ISO 8601 for clarity
  strftime(time_str, sizeof(time_str), "%Y-%m-%dT%H:%M:%S%z", &current_tm);
  fprintf(memstream, "# Generated by %s on %s\n", DAEMON_NAME, time_str);
  if (subnet_filter_enabled) {
    char net_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &target_subnet_addr, net_str, sizeof(net_str));
    fprintf(memstream, "# Filtered for subnet %s/%d\n", net_str,
            target_prefix);
  }

  for (size_t i = 0; i < count; i++) {
    int valid_hostname = 1;
    const char *host = leases[i].hostname;
    const char *ip = leases[i].ip;

    // Basic hostname validation (RFC 1123 subset: letters, digits, hyphen)
    // Allow '.' for potential multi-label hostnames, but check start/end/double
    if (!host || host[0] == '\0' || host[0] == '-' || host[0] == '.') {
      valid_hostname = 0;
    } else {
      for (const char *p = host; *p; ++p) {
        if (!((*p >= 'a' && *p <= 'z') || (*p >= 'A' && *p <= 'Z') ||
              (*p >= '0' && *p <= '9') || *p == '-' || *p == '.')) {
          // Allow underscore? Some systems use it, though not standard. Let's
          // allow it for now.
          if (*p == '_')
            continue;
          valid_hostname = 0;
          break;
        }
        // Check for invalid patterns like "..", ".-", "-.", "--" within labels?
        // Maybe overkill.
        if (*p == '.' && (p[1] == '.' || p[1] == '\0' || p[1] == '-'))
          valid_hostname = 0;
        if (*p == '-' && (p[1] == '.' || p[1] == '\0'))
          valid_hostname = 0; // hostname can end in label ending with digit
      }
      if (host[strlen(host) - 1] == '-')
        valid_hostname = 0; // Cannot end with hyphen
      // Allow ending with '.' for FQDN? Unbound local-data often prefers
      // non-FQDN. Let's disallow trailing dot for now.
      if (host[strlen(host) - 1] == '.')
        valid_hostname = 0;
    }

    if (!valid_hostname) {
      logmsg(
          LOG_WARNING,
          "Skipping entry with invalid hostname format: IP %s, Hostname '%s'",
          ip, host);
      continue;
    }

    // Use unbound's local-zone / local-data format
    // local-data: "<hostname>. IN A <ip>"
    // local-data-ptr: "<ip> <hostname>." (Reverse entry) - Optional, adds
    // complexity
    if (fprintf(memstream, "local-data: \"%s. IN A %s\"\n", host, ip) < 0)
      goto error;

    // Check if hostname already contains a domain (e.g., "myhost.example.com")
    // Only add the ".5ml.io" suffix if it's a simple hostname.
    // Simple check: does it contain a '.'?
    if (strchr(host, '.') == NULL) {
      if (fprintf(memstream, "local-data: \"%s.5ml.io. IN A %s\"\n", host, ip) <
          0)
        goto error;
    } else {
      logmsg(LOG_DEBUG,
             "Skipping .5ml.io suffix for already qualified hostname: %s",
             host);
    }
  }

  if (fflush(memstream) != 0) {
    logmsg(LOG_ERR, "fflush on memstream failed: %s", strerror(errno));
    // continue to fclose, but buffer might be inconsistent
  }
  if (fclose(memstream) != 0) {
    memstream = NULL; // Avoid double close attempt
    logmsg(LOG_ERR, "fclose on memstream failed: %s", strerror(errno));
    free(buffer); // Free buffer even if fclose failed
    return NULL;
  }

  return buffer;

error:
  logmsg(LOG_ERR, "fprintf failed writing to memory stream: %s",
         strerror(errno));
  if (memstream)
    fclose(memstream); // Close if fprintf failed
  free(buffer);
  return NULL;
}

// Writes content to a temporary file, then renames it over the destination
int write_atomic(const char *dest_filename, const char *tmp_filename,
                 const char *content) {
  int fd = open(tmp_filename, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC,
                0644); // Added O_CLOEXEC
  if (fd == -1) {
    logmsg(LOG_ERR, "Failed to open temporary hosts file %s: %s", tmp_filename,
           strerror(errno));
    return -1;
  }

  size_t len = strlen(content);
  ssize_t written = write(fd, content, len);

  if (written == -1) {
    logmsg(LOG_ERR, "Failed to write content to %s: %s", tmp_filename,
           strerror(errno));
    close(fd);
    unlink(tmp_filename); // Attempt cleanup
    return -1;
  }
  if ((size_t)written != len) {
    logmsg(LOG_ERR, "Failed to write full content to %s (%zd out of %zu bytes)",
           tmp_filename, written, len);
    close(fd);
    unlink(tmp_filename); // Attempt cleanup
    return -1;
  }

  // Sync data to disk before renaming
  if (fsync(fd) == -1) {
    logmsg(LOG_WARNING, "fsync failed for %s: %s (continuing rename)",
           tmp_filename, strerror(errno));
    // Don't necessarily fail the whole operation on fsync error, but log it.
  }

  // Close the file descriptor *before* renaming
  if (close(fd) == -1) {
    logmsg(LOG_WARNING, "close failed for %s: %s (continuing rename)",
           tmp_filename, strerror(errno));
    // Log error but proceed with rename attempt
  }
  fd = -1; // Mark as closed

  if (rename(tmp_filename, dest_filename) == -1) {
    logmsg(LOG_ERR, "Failed to rename %s to %s: %s", tmp_filename,
           dest_filename, strerror(errno));
    unlink(tmp_filename); // Attempt cleanup of tmp file if rename failed
    return -1;
  }

  logmsg(LOG_DEBUG, "Successfully wrote and renamed %s", dest_filename);
  return 0;
}

int reload_unbound(void) {
  pid_t pid;
  int status;

  logmsg(LOG_INFO, "Executing: %s %s", UNBOUND_CONTROL, RELOAD_CMD);

  // Flush stdio buffers before fork to avoid duplicate output? Probably not
  // needed here. fflush(stdout); fflush(stderr);

  pid = fork();

  if (pid == -1) {
    // Fork failed
    logmsg(LOG_ERR, "Failed to fork to run unbound-control: %s",
           strerror(errno));
    return -1;
  } else if (pid == 0) {
    // --- Child Process ---
    // Should be careful about what's done here. Avoid complex ops, just exec.

    char *cmd_path = UNBOUND_CONTROL;
    char *cmd_name = "unbound-control"; // Argv[0] convention
    char *cmd_arg1 = RELOAD_CMD;

    // Prepare arguments for execve
    char *argv[] = {
        cmd_name, // Typically the command name itself
        cmd_arg1,
        NULL // Argument list must be NULL-terminated
    };

    // Reset signal handlers to default? Might be overkill.
    // signal(SIGTERM, SIG_DFL); signal(SIGINT, SIG_DFL); signal(SIGHUP,
    // SIG_DFL);

    // Execute the command
    // execvp might be simpler if PATH is needed, but execve is more secure.
    // Assuming UNBOUND_CONTROL is the full path.
    execve(cmd_path, argv, NULL /* Use existing environment */);

    // If execve returns, an error occurred. Log to stderr (might not be visible
    // from daemon) Using err/warn here might pull in unwanted stdio after fork.
    // Use raw write.
    char err_buf[256];
    snprintf(err_buf, sizeof(err_buf), "%s: execve failed for %s: %s\n",
             DAEMON_NAME, cmd_path, strerror(errno));
    write(STDERR_FILENO, err_buf,
          strlen(err_buf)); // Best effort error reporting from child
    _exit(127); // Use _exit() in child after fork, 127 indicates exec error

  } else {
    // --- Parent Process ---
    logmsg(LOG_DEBUG, "Waiting for unbound-control process %ld", (long)pid);

    // Wait for the specific child process to finish
    pid_t waited_pid = waitpid(pid, &status, 0);

    if (waited_pid == -1) {
      if (errno == EINTR) {
        // Interrupted by signal (e.g. SIGTERM/SIGINT). Check terminate flag.
        logmsg(LOG_INFO, "waitpid interrupted, checking termination status");
        // Might need to re-wait or handle partial state if needed.
        // For reload, maybe just fail it if interrupted.
        return -1;
      }
      logmsg(LOG_ERR, "waitpid failed for child %ld: %s", (long)pid,
             strerror(errno));
      return -1; // Error waiting for child
    }

    if (waited_pid == pid) {
      logmsg(LOG_DEBUG, "Child process %ld finished", (long)pid);

      // Check how the child terminated
      if (WIFEXITED(status)) {
        int exit_status = WEXITSTATUS(status);
        if (exit_status == 0) {
          logmsg(LOG_INFO,
                 "Unbound reloaded successfully via %s (child exited 0)",
                 UNBOUND_CONTROL);
          return 0; // Success
        } else {
          logmsg(LOG_ERR, "%s %s failed (child exited %d)", UNBOUND_CONTROL,
                 RELOAD_CMD, exit_status);
          return -1; // Child indicated failure
        }
      } else if (WIFSIGNALED(status)) {
        logmsg(LOG_ERR, "%s %s terminated by signal %d", UNBOUND_CONTROL,
               RELOAD_CMD, WTERMSIG(status));
        return -1; // Child killed by signal
      } else {
        logmsg(LOG_ERR, "%s %s terminated abnormally (status %d)",
               UNBOUND_CONTROL, RELOAD_CMD, status);
        return -1; // Unknown termination
      }
    } else {
      // This shouldn't happen with waitpid(pid, ...) unless pid was somehow
      // wrong.
      logmsg(LOG_ERR, "waitpid returned unexpected pid %ld (expected %ld)",
             (long)waited_pid, (long)pid);
      return -1;
    }
    // --- End of Parent ---
  }
}

// Frees memory allocated for the lease array
void free_leases(LeaseEntry *leases, size_t count) {
  if (!leases)
    return;
  for (size_t i = 0; i < count; i++) {
    free(leases[i].ip);
    free(leases[i].hostname);
  }
  free(leases);
}
