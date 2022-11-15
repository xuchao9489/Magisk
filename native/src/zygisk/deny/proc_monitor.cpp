#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <pthread.h>
#include <sys/ptrace.h>
#include <sys/inotify.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/mount.h>
#include <vector>
#include <bitset>

#include <base.hpp>
#include <magisk.hpp>
#include <daemon.hpp>

#include "deny.hpp"

#define WEVENT(s) (((s) & 0xffff0000) >> 16)

using namespace std;

static int inotify_fd = -1;

static void new_zygote(int pid);

static int fork_pid = 0;

pthread_t monitor_thread;

/******************
 * Data structures
 ******************/

#define PID_MAX 32768
struct pid_set {
    bitset<PID_MAX>::const_reference operator[](size_t pos) const { return set[pos - 1]; }
    bitset<PID_MAX>::reference operator[](size_t pos) { return set[pos - 1]; }
    void reset() { set.reset(); }
private:
    bitset<PID_MAX> set;
};

// true if pid is monitored
static pid_set attaches;

// zygote pid -> mnt ns
static map<int, struct stat> zygote_map;

/********
 * Utils
 ********/

static inline int read_ns(const int pid, struct stat *st) {
    char path[32];
    sprintf(path, "/proc/%d/ns/mnt", pid);
    return stat(path, st);
}

static int parse_ppid(int pid) {
    char path[32];
    int ppid;

    sprintf(path, "/proc/%d/stat", pid);

    auto stat = open_file(path, "re");
    if (!stat)
        return -1;

    // PID COMM STATE PPID .....
    fscanf(stat.get(), "%*d %*s %*c %d", &ppid);

    return ppid;
}

static bool is_zygote_done() {
#ifdef __LP64__
    int zygote_count = (HAVE_32)? 2:1;
    if (zygote_map.size() >= zygote_count)
        return true;
#else
    if (zygote_map.size() >= 1)
        return true;
#endif

    return false;
}

static bool read_file(const char *file, char *buf, int count){
    FILE *fp = fopen(file, "re");
    if (!fp) return false;
    fread(buf, count, 1, fp);
    fclose(fp);
    return true;
}


static bool check_process(int pid, const char *process = 0, const char *context = 0, const char *exe = 0) {
    char path[128];
    char buf[1024];
    ssize_t len;

    if (!process) goto check_context;
    sprintf(path, "/proc/%d/cmdline", pid);
    if (!read_file(path,buf,sizeof(buf)) ||
        strcmp(buf, process) != 0)
        return false;

    check_context:
    if (!context) goto check_exe;
    sprintf(path, "/proc/%d/attr/current", pid);
    if (!read_file(path,buf,sizeof(buf)) || 
        !str_contains(buf, context))
        return false;
    
    check_exe:
    if (!exe) goto final;
    sprintf(path, "/proc/%d/exe", pid);
    len = readlink(path, buf, sizeof(buf)-1);
    if (len != -1) {
      buf[len] = '\0';
    }
    if (strcmp(buf, exe) != 0)
        return false;

    final:
    return true;
}

static bool check_process2(int pid, const char *process, const char *context, const char *exe){
    if (access("/sys/fs/selinux",F_OK) == 0)
        return check_process(pid,process,context,exe);
    return check_process(pid,process,0,exe);
}

static bool is_zygote(int pid_){
    return check_process2(pid_, "zygote", "u:r:zygote:s0", "/system/bin/app_process32")  
            || check_process2(pid_, "zygote", "u:r:zygote:s0", "/system/bin/app_process64")
            || check_process2(pid_, "zygote", "u:r:zygote:s0", "/system/bin/app_process")
            || check_process2(pid_, "zygote64", "u:r:zygote:s0", "/system/bin/app_process64") 
            || check_process2(pid_, "zygote32", "u:r:zygote:s0", "/system/bin/app_process32")
            || check_process2(pid_, "zygote32", "u:r:zygote:s0", "/system/bin/app_process");
}

static void check_zygote(){
    crawl_procfs([](int pid) -> bool {
        if (is_zygote(pid) && parse_ppid(pid) == 1) {
            new_zygote(pid);;
        }
        return true;
    });
    if (is_zygote_done()) {
        // Stop periodic scanning
        timeval val { .tv_sec = 0, .tv_usec = 0 };
        itimerval interval { .it_interval = val, .it_value = val };
        setitimer(ITIMER_REAL, &interval, nullptr);
    }
}

#define APP_PROC "/system/bin/app_process"

static void setup_inotify() {
    inotify_fd = inotify_init1(IN_CLOEXEC);
    if (inotify_fd < 0)
        return;

    // Setup inotify asynchronous I/O
    fcntl(inotify_fd, F_SETFL, O_ASYNC);
    struct f_owner_ex ex = {
        .type = F_OWNER_TID,
        .pid = gettid()
    };
    fcntl(inotify_fd, F_SETOWN_EX, &ex);

    // Monitor packages.xml
    inotify_add_watch(inotify_fd, "/data/system", IN_CLOSE_WRITE);

    // Monitor app_process
    if (access(APP_PROC "32", F_OK) == 0) {
        inotify_add_watch(inotify_fd, APP_PROC "32", IN_ACCESS);
        if (access(APP_PROC "64", F_OK) == 0)
            inotify_add_watch(inotify_fd, APP_PROC "64", IN_ACCESS);
    } else {
        inotify_add_watch(inotify_fd, APP_PROC, IN_ACCESS);
    }
}

/************************
 * Async signal handlers
 ************************/

static void inotify_event(int) {
    // Make sure we can actually read stuffs
    // or else the whole thread will be blocked.
    struct pollfd pfd = {
        .fd = inotify_fd,
        .events = POLLIN,
        .revents = 0
    };
    if (poll(&pfd, 1, 0) <= 0)
        return;  // Nothing to read
    char buf[512];
    auto event = reinterpret_cast<struct inotify_event *>(buf);
    read(inotify_fd, buf, sizeof(buf));
    if ((event->mask & IN_CLOSE_WRITE) && event->name == "packages.xml"sv)
        rescan_apps();
    check_zygote();
}

static void term_thread(int) {
    LOGD("proc_monitor: cleaning up\n");
    zygote_map.clear();
    attaches.reset();
    close(inotify_fd);
    inotify_fd = -1;
    // Restore all signal handlers that was set
    sigset_t set;
    sigfillset(&set);
    pthread_sigmask(SIG_BLOCK, &set, nullptr);
    struct sigaction act{};
    act.sa_handler = SIG_DFL;
    sigaction(SIGTERMTHRD, &act, nullptr);
    sigaction(SIGIO, &act, nullptr);
    sigaction(SIGALRM, &act, nullptr);
    LOGD("proc_monitor: terminate\n");
    pthread_exit(nullptr);
}

/*********
 * Ptrace
 *********/

#define PTRACE_LOG(fmt, args...) LOGD("PID=[%d] " fmt, pid, ##args)
//#define PTRACE_LOG(...)

static void detach_pid(int pid, int signal = 0) {
    attaches[pid] = false;
    ptrace(PTRACE_DETACH, pid, 0, signal);
    PTRACE_LOG("detach\n");
}

static bool ino_equal(struct stat st, struct stat st2){
    if (st.st_dev == st2.st_dev &&
        st.st_ino == st2.st_ino)
        return true;
    return false;
}
        

static bool check_pid(int pid) {
    char path[128];
    char cmdline[1024];
    char context[1024];
    int ppid = -1;
    struct stat st;
    sprintf(path, "/proc/%d", pid);
    if (stat(path, &st)) {
        // Process died unexpectedly, ignore
        return true;
    }
    int uid = st.st_uid;
    // check context to know zygote is being forked into app process
    sprintf(path, "/proc/%d/attr/current", pid);
    if (auto f = open_file(path, "re")) {
        fgets(context, sizeof(context), f.get());
    } else {
        // Process died unexpectedly, ignore
        return true;
    }

    sprintf(path, "/proc/%d/cmdline", pid);
    if (auto f = open_file(path, "re")) {
        fgets(cmdline, sizeof(cmdline), f.get());
    } else {
        // Process died unexpectedly, ignore
        return true;
    }

    // if cmdline == zygote and context is changed, zygote is being forked into app process
    if ((cmdline == "zygote"sv || cmdline == "zygote32"sv || cmdline == "zygote64"sv) && context != "u:r:zygote:s0"sv){
        // this is pre-initialized app zygote
        if (strstr(context, "u:r:app_zygote:s0")){
            PTRACE_LOG("app zygote\n");
            goto check_and_hide;
        }
        PTRACE_LOG("app process\n");

        // wait until pre-initialized
        for (int i=0; cmdline != "<pre-initialized>"sv; i++) {
            if (i>=300000) return true; // we don't want it stuck forever
            // update cmdline
            if (auto f = open_file(path, "re")) {
                fgets(cmdline, sizeof(cmdline), f.get());
            } else {
                // Process died unexpectedly, ignore
                return true;
            }
            usleep(10);
        }
    }

check_and_hide:
    
    // UID hasn't changed
    if (uid == 0)
        return false;

    if (cmdline == "zygote"sv || cmdline == "zygote32"sv || cmdline == "zygote64"sv ||
        cmdline == "usap32"sv || cmdline == "usap64"sv)
        return false;

    // app process is being initialized
    // it should happen in short time
    for (int i=0;cmdline == "<pre-initialized>"sv; i++) {
        if (i>=300000) goto not_target; // we don't want it stuck forever
        if (auto f = open_file(path, "re")) {
            fgets(cmdline, sizeof(cmdline), f.get());
        } else {
            // Process died unexpectedly, ignore
            return true;
        }
        usleep(10);
    }

    // read process name again to make sure
    if (auto f = open_file(path, "re")) {
        fgets(cmdline, sizeof(cmdline), f.get());
    } else {
        // Process died unexpectedly, ignore
        return true;
    }

    // stop app process as soon as possible and do check if this process is target or not
    if (!sulist_enabled) kill(pid, SIGSTOP);

    if (!is_deny_target(uid, cmdline, 95)) {
        goto not_target;
    }

    // Ensure ns is separated
    struct stat ppid_st;
    ppid = parse_ppid(pid);
    read_ns(pid, &st);
    read_ns(ppid, &ppid_st);
    if (ino_equal(st, ppid_st)) {
        LOGW("proc_monitor: skip [%s] PID=[%d] PPID=[%d] UID=[%d]\n", cmdline, pid, ppid, uid);
        goto not_target;
    }

    // Finally this is our target
    // We stop target process and do all unmounts
    // The hide daemon will resume the process after hiding it
    LOGI("proc_monitor: [%s] PID=[%d] PPID=[%d] UID=[%d]\n", cmdline, pid, ppid, uid);

    if (sulist_enabled) {
        // mount magisk in sulist mode
        kill(pid, SIGSTOP);
        su_daemon(pid);
    } else {
        // hide magisk in normal mode
        revert_daemon(pid);
    }
    return true;

not_target:
    PTRACE_LOG("[%s] is not target\n", cmdline);
    if (!sulist_enabled) kill(pid, SIGCONT);
    return true;
}

static bool is_process(int pid) {
    char buf[128];
    char key[32];
    int tgid;
    sprintf(buf, "/proc/%d/status", pid);
    auto fp = open_file(buf, "re");
    // PID is dead
    if (!fp)
        return false;
    while (fgets(buf, sizeof(buf), fp.get())) {
        sscanf(buf, "%s", key);
        if (key == "Tgid:"sv) {
            sscanf(buf, "%*s %d", &tgid);
            return tgid == pid;
        }
    }
    return false;
}



static void new_zygote(int pid) {
    struct stat init_st;
    struct stat st;
    if (read_ns(1, &init_st) || read_ns(pid, &st))
        return;

    if (st.st_dev == init_st.st_dev &&
        st.st_ino == init_st.st_ino) {
        // skip if zygote ns is not seperated
        LOGD("proc_monitor: skip PID=[%d]\n", pid);
        return;
    }

    auto it = zygote_map.find(pid);
    if (it != zygote_map.end()) {
           if (it->second.st_dev != st.st_dev ||
               it->second.st_ino != st.st_ino) {
               goto add_zygote;
        }
        // Update namespace info
        //LOGD("proc_monitor: update zygote PID=[%d]\n", pid);
        it->second = st;
        return;
    }
    
    add_zygote:

    LOGI("proc_monitor: zygote PID=[%d]\n", pid);
    zygote_map[pid] = st;
    if (sulist_enabled) revert_daemon(pid,-2);

    ptrace(PTRACE_ATTACH, pid);

    waitpid(pid, nullptr, __WALL | __WNOTHREAD);
    ptrace(PTRACE_SETOPTIONS, pid, nullptr,
            PTRACE_O_TRACEFORK | PTRACE_O_TRACEVFORK | PTRACE_O_TRACEEXIT);
    ptrace(PTRACE_CONT, pid);
}

void do_check_fork() {
    int pid = fork_pid;
    fork_pid = 0;
    if (pid == 0)
        return;
    int i=0;
    PTRACE_LOG("do_check_fork start\n");
    // zygote child process need a mount of time to seperate mount namespace
    while (!check_pid(pid)){
        if (i>=300000) break;
        i++;
        usleep(10);
    }
    PTRACE_LOG("do_check_fork end\n");
}


void do_check_pid(int client){
    int pid = read_int(client);
    fork_pid = pid;
    new_daemon_thread(&do_check_fork);
}

#define DETACH_AND_CONT { detach_pid(pid); continue; }

void proc_monitor(){
    proc_monitor(true);
}

void proc_monitor(bool do_hide) {
    monitor_thread = pthread_self();

    // Backup original mask
    sigset_t orig_mask;
    pthread_sigmask(SIG_SETMASK, nullptr, &orig_mask);

    sigset_t unblock_set;
    sigemptyset(&unblock_set);
    sigaddset(&unblock_set, SIGTERMTHRD);
    sigaddset(&unblock_set, SIGIO);
    sigaddset(&unblock_set, SIGALRM);

    struct sigaction act{};
    sigfillset(&act.sa_mask);
    act.sa_handler = SIG_IGN;
    sigaction(SIGTERMTHRD, &act, nullptr);
    sigaction(SIGIO, &act, nullptr);
    sigaction(SIGALRM, &act, nullptr);

    // Temporary unblock to clear pending signals
    pthread_sigmask(SIG_UNBLOCK, &unblock_set, nullptr);
    pthread_sigmask(SIG_SETMASK, &orig_mask, nullptr);

    act.sa_handler = term_thread;
    sigaction(SIGTERMTHRD, &act, nullptr);
    act.sa_handler = inotify_event;
    sigaction(SIGIO, &act, nullptr);
    act.sa_handler = [](int){ check_zygote(); };
    sigaction(SIGALRM, &act, nullptr);

    setup_inotify();

    // First try find existing zygotes
    check_zygote();
    if (!is_zygote_done()) {
        // Periodic scan every 250ms
        timeval val { .tv_sec = 0, .tv_usec = 250000 };
        itimerval interval { .it_interval = val, .it_value = val };
        setitimer(ITIMER_REAL, &interval, nullptr);
    }

    // proc_monitor is blocked and i don't know why

    for (int status;;) {
        pthread_sigmask(SIG_UNBLOCK, &unblock_set, nullptr);

        const int pid = waitpid(-1, &status, __WALL | __WNOTHREAD);
        if (pid < 0) {
            if (errno == ECHILD) {
                // Nothing to wait yet, sleep and wait till signal interruption
                LOGD("proc_monitor: nothing to monitor, wait for signal\n");
                struct timespec ts = {
                    .tv_sec = INT_MAX,
                    .tv_nsec = 0
                };
                nanosleep(&ts, nullptr);
            }
            continue;
        }

        pthread_sigmask(SIG_SETMASK, &orig_mask, nullptr);

        if (!WIFSTOPPED(status) /* Ignore if not ptrace-stop */)
            DETACH_AND_CONT;

        int event = WEVENT(status);
        int signal = WSTOPSIG(status);

        if (signal == SIGTRAP && event) {
            unsigned long msg;
            ptrace(PTRACE_GETEVENTMSG, pid, nullptr, &msg);
            if (zygote_map.count(pid)) {
                // Zygote event
                switch (event) {
                    case PTRACE_EVENT_FORK:
                    case PTRACE_EVENT_VFORK:
                        PTRACE_LOG("zygote forked: [%lu]\n", msg);
                        attaches[msg] = false;
                        fork_pid = msg;
                        detach_pid(msg);
                        if (do_hide) new_daemon_thread(&do_check_fork);
                        break;
                    case PTRACE_EVENT_EXIT:
                        PTRACE_LOG("zygote exited with status: [%lu]\n", msg);
                        [[fallthrough]];
                    default:
                        zygote_map.erase(pid);
                        DETACH_AND_CONT;
                }
            } else {
                DETACH_AND_CONT;
            }
            ptrace(PTRACE_CONT, pid);
        } else if (signal == SIGSTOP) {
            if (!attaches[pid]) {
                // Double check if this is actually a process
                attaches[pid] = is_process(pid);
            }
            if (attaches[pid]) {
                // This is a process, continue monitoring
                PTRACE_LOG("SIGSTOP from child\n");
                ptrace(PTRACE_SETOPTIONS, pid, nullptr,
                        PTRACE_O_TRACECLONE | PTRACE_O_TRACEEXEC | PTRACE_O_TRACEEXIT);
                ptrace(PTRACE_CONT, pid);
            } else {
                // This is a thread, do NOT monitor
                PTRACE_LOG("SIGSTOP from thread\n");
                DETACH_AND_CONT;
            }
        } else {
            // Not caused by us, resend signal
            ptrace(PTRACE_CONT, pid, nullptr, signal);
            PTRACE_LOG("signal [%d]\n", signal);
        }
    }
}
