#include <sys/mount.h>
#include <libgen.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <base.hpp>
#include <magisk.hpp>
#include <daemon.hpp>
#include <selinux.hpp>
#include <flags.h>

#include "core.hpp"

using namespace std;

static void install_applet(const char *path){
    string s;
    for (int i = 0; applet_names[i]; ++i){
        s = string(path) + "/" + string(applet_names[i]);
        xsymlink("./magisk", s.data());
    }
    s = string(path) + "/supolicy";
    xsymlink("./magiskpolicy", s.data());
}

[[noreturn]] static void usage() {
    fprintf(stderr,
R"EOF(Magisk - Multi-purpose Utility

Usage: magisk [applet [arguments]...]
   or: magisk [options]...

Options:
   -c                        print current binary version
   -v                        print running daemon version
   -V                        print running daemon version code
   --list                    list all available applets
   --remove-modules          remove all modules and reboot
   --install-module ZIP      install a module zip file
   --install [PATH]          install applets into PATH

Advanced Options (Internal APIs):
   --daemon                  manually start magisk daemon
   --stop                    remove all magisk changes and stop daemon
   --[init trigger]          callback on init triggers. Valid triggers:
                             post-fs-data, service, boot-complete, zygote-restart
   --unlock-blocks           set BLKROSET flag to OFF for all block devices
   --restorecon              restore selinux context on Magisk files
   --clone-attr SRC DEST     clone permission, owner, and selinux context
   --clone SRC DEST          clone SRC to DEST
   --sqlite SQL              exec SQL commands to Magisk database
   --path                    print Magisk tmpfs mount path
   --hide ARGS               MagiskHide config CLI

Available applets:
)EOF");

    for (int i = 0; applet_names[i]; ++i)
        fprintf(stderr, i ? ", %s" : "    %s", applet_names[i]);
    fprintf(stderr, "\n\n");
    exit(1);
}

int magisk_main(int argc, char *argv[]) {
    if (argc < 2)
        usage();
    if (argv[1] == "-c"sv) {
#if MAGISK_DEBUG
        printf(MAGISK_VERSION ":MAGISK:D (" str(MAGISK_VER_CODE) ")\n");
#else
        printf(MAGISK_VERSION ":MAGISK:R (" str(MAGISK_VER_CODE) ")\n");
#endif
        return 0;
    } else if (argv[1] == "-v"sv) {
        int fd = connect_daemon(MainRequest::CHECK_VERSION);
        string v = read_string(fd);
        printf("%s\n", v.data());
        return 0;
    } else if (argv[1] == "-V"sv) {
        int fd = connect_daemon(MainRequest::CHECK_VERSION_CODE);
        printf("%d\n", read_int(fd));
        return 0;
    } else if (argv[1] == "--list"sv) {
        for (int i = 0; applet_names[i]; ++i)
            printf("%s\n", applet_names[i]);
        return 0;
    } else if (argv[1] == "--unlock-blocks"sv) {
        unlock_blocks();
        return 0;
    } else if (argv[1] == "--mount-sbin"sv) {
        int ret = mount_sbin();
        return ret;
    } else if (argv[1] == "--install"sv) {
        if (argc >= 3)
            install_applet(argv[2]);
        else
            install_applet("/sbin");
        return 0;
    } else if (argv[1] == "--restorecon"sv) {
        restorecon();
        return 0;
    } else if (argc >= 4 && argv[1] == "--clone-attr"sv) {
        clone_attr(argv[2], argv[3]);
        return 0;
    } else if (argc >= 4 && argv[1] == "--clone"sv) {
        cp_afc(argv[2], argv[3]);
        return 0;
    } else if (argv[1] == "--daemon"sv) {
        close(connect_daemon(MainRequest::START_DAEMON, true));
        return 0;
    } else if (argv[1] == "--stop"sv) {
        int fd = connect_daemon(MainRequest::STOP_DAEMON);
        return read_int(fd);
    } else if (argv[1] == "--post-fs-data"sv) {
        close(connect_daemon(MainRequest::POST_FS_DATA, true));
        return 0;
    } else if (argv[1] == "--service"sv) {
        close(connect_daemon(MainRequest::LATE_START, true));
        return 0;
    } else if (argv[1] == "--boot-complete"sv) {
        close(connect_daemon(MainRequest::BOOT_COMPLETE));
        return 0;
    } else if (argv[1] == "--zygote-restart"sv) {
        close(connect_daemon(MainRequest::ZYGOTE_RESTART));
        return 0;
    } else if (argv[1] == "--denylist"sv) {
        return 1;
    } else if (argv[1] == "--hide"sv) {
        return denylist_cli(argc - 1, argv + 1);
    } else if (argc >= 3 && argv[1] == "--sqlite"sv) {
        int fd = connect_daemon(MainRequest::SQLITE_CMD);
        write_string(fd, argv[2]);
        string res;
        for (;;) {
            read_string(fd, res);
            if (res.empty())
                return 0;
            printf("%s\n", res.data());
        }
    } else if (argv[1] == "--remove-modules"sv) {
        int fd = connect_daemon(MainRequest::REMOVE_MODULES);
        return read_int(fd);
    } else if (argv[1] == "--path"sv) {
        int fd = connect_daemon(MainRequest::GET_PATH);
        string path = read_string(fd);
        printf("%s\n", path.data());
        return 0;
    } else if (argc >= 3 && argv[1] == "--install-module"sv) {
        install_module(argv[2]);
    }
#if 0
    /* Entry point for testing stuffs */
    else if (argv[1] == "--test"sv) {
        rust_test_entry();
        return 0;
    }
#endif
    usage();
}


bool check_envpath(const char* path){
    char buf[4098];
    char envpath[4098];
    sprintf(envpath, "%s:", getenv("PATH"));
    int n=0;
    for (int i=0; envpath[i]; i++) {
        if (envpath[i] == ':'){
            buf[n]='\0';
            if (strcmp(buf,path) == 0) return true;
                n=0;
        } else {
            buf[n]=envpath[i];
            n++;
        }
    }
    return false;
}
