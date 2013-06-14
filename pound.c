/*
 * Pound - the reverse-proxy load-balancer
 * Copyright (C) 2002-2010 Apsis GmbH
 *
 * This file is part of Pound.
 *
 * Pound is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 * 
 * Pound is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 * Contact information:
 * Apsis GmbH
 * P.O.Box
 * 8707 Uetikon am See
 * Switzerland
 * EMail: roseg@apsis.ch
 */

#include    "pound.h"

/* while in shutdown, check number of running threads every 10 seconds */
#define     RUNNING_CHECK_PERIOD 10

/* common variables */
char        *user,              /* user to run as */
            *group,             /* group to run as */
            *root_jail,         /* directory to chroot to */
            *pid_name,          /* file to record pid in */
            *ctrl_name;         /* control socket name */

int         alive_to,           /* check interval for resurrection */
            anonymise,          /* anonymise client address */
            daemonize,          /* run as daemon */
            log_facility,       /* log facility to use */
            print_log,          /* print log messages to stdout/stderr */
            control_sock;       /* control socket */

SERVICE     *services;          /* global services (if any) */

LISTENER    *listeners;         /* all available listeners */
LISTENER    *prev_listeners;    /* saved listeners */

PID         *children;          /* pid of workers */

regex_t HEADER,             /* Allowed header */
        CHUNK_HEAD,         /* chunk header line */
        RESP_SKIP,          /* responses for which we skip response */
        RESP_IGN,           /* responses for which we ignore content */
        LOCATION,           /* the host we are redirected to */
        AUTHORIZATION;      /* the Authorisation header */

static int  shut_down = 0;

#ifndef  SOL_TCP
/* for systems without the definition */
int     SOL_TCP;
#endif

/* worker pid */
static  pid_t               son = 0;

/*
 * OpenSSL thread support stuff
 */
static pthread_mutex_t  *l_array;

static void
l_init(void)
{
    int i, n_locks;

    n_locks = CRYPTO_num_locks();
    if((l_array = (pthread_mutex_t *)calloc(n_locks, sizeof(pthread_mutex_t))) == NULL) {
        logmsg(LOG_ERR, "lock init: out of memory - aborted...");
        exit(1);
    }
    for(i = 0; i < n_locks; i++)
        /* pthread_mutex_init() always returns 0 */
        pthread_mutex_init(&l_array[i], NULL);
    return;
}

static void
l_lock(const int mode, const int n, /* unused */ const char *file, /* unused */ int line)
{
    int ret_val;

    if(mode & CRYPTO_LOCK) {
        if(ret_val = pthread_mutex_lock(&l_array[n]))
            logmsg(LOG_ERR, "l_lock lock(): %s", strerror(ret_val));
    } else {
        if(ret_val = pthread_mutex_unlock(&l_array[n]))
            logmsg(LOG_ERR, "l_lock unlock(): %s", strerror(ret_val));
    }
    return;
}

static unsigned long
l_id(void)
{
    return (unsigned long)pthread_self();
}

/*
 * work queue stuff
 */
static thr_arg          *first = NULL, *last = NULL;
static pthread_cond_t   arg_cond;
static pthread_mutex_t  arg_mut;
int                     numthreads;
static int              waiting = 0;

static void
init_thr_arg(void)
{
    pthread_cond_init(&arg_cond, NULL);
    pthread_mutex_init(&arg_mut, NULL);
    return;
}

/*
 * add a request to the queue
 */
int
put_thr_arg(thr_arg *arg)
{
    thr_arg *res;

    if((res = malloc(sizeof(thr_arg))) == NULL) {
        logmsg(LOG_WARNING, "thr_arg malloc");
        return -1;
    }
    memcpy(res, arg, sizeof(thr_arg));
    res->next = NULL;
    (void)pthread_mutex_lock(&arg_mut);
    if(last == NULL)
        first = last = res;
    else {
        last->next = res;
        last = last->next;
    }
    (void)pthread_mutex_unlock(&arg_mut);
    pthread_cond_signal(&arg_cond);
    return 0;
}

/*
 * get a request from the queue
 */
thr_arg *
get_thr_arg(void)
{
    thr_arg *res;

    (void)pthread_mutex_lock(&arg_mut);
    waiting++;
    while(first == NULL)
        (void)pthread_cond_wait(&arg_cond, &arg_mut);
    waiting--;
    if((res = first) != NULL)
        if((first = first->next) == NULL)
            last = NULL;
    (void)pthread_mutex_unlock(&arg_mut);
    if(first != NULL)
        pthread_cond_signal(&arg_cond);
    return res;
}

/*
 * get the current queue length
 */
get_thr_qlen(void)
{
    int     res;
    thr_arg *tap;

    (void)pthread_mutex_lock(&arg_mut);
    for(res = 0, tap = first; tap != NULL; tap = tap->next, res++)
        ;
    (void)pthread_mutex_unlock(&arg_mut);
    return res;
}

/*
 * handle SIGTERM/SIGQUIT - exit
 */
static RETSIGTYPE
h_term(const int sig)
{
    if(son > 0)
        signal_all(children, sig);
    else
        if(ctrl_name != NULL)
            (void)unlink(ctrl_name);
    exit(0);
}

/*
 * handle SIGHUP/SIGINT - shut down worker (and spawn new one, if possible)
 */
static RETSIGTYPE
h_shut(const int sig)
{
    if(son > 0) {
        kill(son, sig);
        son = 0;
    }
    shut_down = 1;
}

static RETSIGTYPE
h_child(const int sig)
{
    /* just wake-up from sigsuspend() */
}

/*
 * Pound: the reverse-proxy/load-balancer
 *
 * Arguments:
 *  -f config_file      configuration file - exclusive of other flags
 */

int
main(const int argc, char **argv)
{
    int                 n_listeners, i, clnt_length, clnt;
    struct pollfd       *polls;
    LISTENER            *lstn;
    LISTENER            *prev_lstn;
    pthread_t           thr;
    pthread_attr_t      attr;
    uid_t               user_id;
    gid_t               group_id;
    FILE                *fpid;
    struct sockaddr_storage clnt_addr;
    char                tmp[MAXBUF];
#ifndef SOL_TCP
    struct protoent     *pe;
#endif
    int                 daemon;

    polls = NULL;
    daemon = 0;
    (void)umask(077);
    logmsg(LOG_NOTICE, "starting...");

    signal(SIGHUP, h_shut);
    signal(SIGINT, h_shut);
    signal(SIGTERM, h_term);
    signal(SIGQUIT, h_term);
    signal(SIGPIPE, SIG_IGN);
    signal(SIGCHLD, h_child);

    srandom(getpid());

    /* SSL stuff */
    SSL_load_error_strings();
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    l_init();
    init_thr_arg();
    CRYPTO_set_id_callback(l_id);
    CRYPTO_set_locking_callback(l_lock);
    init_timer();

    /* Disable SSL Compression for OpenSSL pre-1.0.  1.0 is handled with an option in config.c */
#if OPENSSL_VERSION_NUMBER >= 0x00907000L
#ifndef SSL_OP_NO_COMPRESSION
    {
      int i,n;
      STACK_OF(SSL_COMP) *ssl_comp_methods;

      ssl_comp_methods = SSL_COMP_get_compression_methods();
      n = sk_SSL_COMP_num(ssl_comp_methods);

      for(i=n-1; i>=0; i--) {
        sk_SSL_COMP_delete(ssl_comp_methods, i);
      }
    }
#endif
#endif

    /* prepare regular expressions */
    if(regcomp(&HEADER, "^([a-z0-9!#$%&'*+.^_`|~-]+):[ \t]*(.*)[ \t]*$", REG_ICASE | REG_NEWLINE | REG_EXTENDED)
    || regcomp(&CHUNK_HEAD, "^([0-9a-f]+).*$", REG_ICASE | REG_NEWLINE | REG_EXTENDED)
    || regcomp(&RESP_SKIP, "^HTTP/1.1 100.*$", REG_ICASE | REG_NEWLINE | REG_EXTENDED)
    || regcomp(&RESP_IGN, "^HTTP/1.[01] (10[1-9]|1[1-9][0-9]|204|30[456]).*$", REG_ICASE | REG_NEWLINE | REG_EXTENDED)
    || regcomp(&LOCATION, "(http|https)://([^/]+)(.*)", REG_ICASE | REG_NEWLINE | REG_EXTENDED)
    || regcomp(&AUTHORIZATION, "Authorization:[ \t]*Basic[ \t]*\"?([^ \t]*)\"?[ \t]*", REG_ICASE | REG_NEWLINE | REG_EXTENDED)
    ) {
        logmsg(LOG_ERR, "bad essential Regex - aborted");
        exit(1);
    }

#ifndef SOL_TCP
    /* for systems without the definition */
    if((pe = getprotobyname("tcp")) == NULL) {
        logmsg(LOG_ERR, "missing TCP protocol");
        exit(1);
    }
    SOL_TCP = pe->p_proto;
#endif

    for(;;) {
        /* free previous values and re-initialize */
        free(user);
        free(group);
        free(root_jail);
        free(ctrl_name);

        print_log = 0;
        control_sock = -1;
        log_facility = -1;

        /* preserve listeners */
        prev_listeners = listeners;
        listeners = NULL;

        /* read config */
        config_parse(argc, argv);
        if(shut_down)
            print_log = 0;

        if(log_facility != -1)
            openlog("pound", LOG_CONS | LOG_NDELAY, LOG_DAEMON);
        else
            closelog();

        if(ctrl_name != NULL) {
            struct sockaddr_un  ctrl;

            if(control_sock >= 0)
                close(control_sock);

            memset(&ctrl, 0, sizeof(ctrl));
            ctrl.sun_family = AF_UNIX;
            strncpy(ctrl.sun_path, ctrl_name, sizeof(ctrl.sun_path) - 1);
            (void)unlink(ctrl.sun_path);
            if((control_sock = socket(PF_UNIX, SOCK_STREAM, 0)) < 0) {
                logmsg(LOG_ERR, "Control \"%s\" create: %s", ctrl.sun_path, strerror(errno));
                exit(1);
            }
            if(bind(control_sock, (struct sockaddr *)&ctrl, (socklen_t)sizeof(ctrl)) < 0) {
                logmsg(LOG_ERR, "Control \"%s\" bind: %s", ctrl.sun_path, strerror(errno));
                exit(1);
            }
            listen(control_sock, 512);
        }

        /* open listeners */
        for(lstn = listeners, n_listeners = 0; lstn; lstn = lstn->next, n_listeners++) {
            int opt;

            /* try to re-use listener socket */
            for(prev_lstn = prev_listeners; prev_lstn; prev_lstn = prev_lstn->next) {
                if(prev_lstn->sock >= 0 && !addrinfo_cmp(&prev_lstn->addr, &lstn->addr))
                    break;
            }
            if(prev_lstn && prev_lstn->sock >= 0) {
                char addr[MAXBUF];
                /* reuse listener socket */
                lstn->sock = prev_lstn->sock;
                prev_lstn->sock = -1;
                addr2str(addr, sizeof(addr), &prev_lstn->addr, 0);
                logmsg(LOG_INFO, "reusing listener socket for %s", addr);
            } else {
                /* prepare the socket */
                if((lstn->sock = socket(lstn->addr.ai_family == AF_INET? PF_INET: PF_INET6, SOCK_STREAM, 0)) < 0) {
                    addr2str(tmp, MAXBUF - 1, &lstn->addr, 0);
                    logmsg(LOG_ERR, "HTTP socket %s create: %s - aborted", tmp, strerror(errno));
                    exit(1);
                }
                opt = 1;
                setsockopt(lstn->sock, SOL_SOCKET, SO_REUSEADDR, (void *)&opt, sizeof(opt));
                if(bind(lstn->sock, lstn->addr.ai_addr, (socklen_t)lstn->addr.ai_addrlen) < 0) {
                    addr2str(tmp, MAXBUF - 1, &lstn->addr, 0);
                    logmsg(LOG_ERR, "HTTP socket bind %s: %s - aborted", tmp, strerror(errno));
                    exit(1);
                }
                listen(lstn->sock, 512);
            }
        }
        /* close remaining old listeners and free structures */
        while(prev_listeners) {
            LISTENER *lstn = prev_listeners;
            prev_listeners = prev_listeners->next;
            if(lstn->sock >= 0)
                close(lstn->sock);
            free_listener(lstn);
        }

        /* alloc the poll structures */
        free(polls);
        if((polls = (struct pollfd *)calloc(n_listeners, sizeof(struct pollfd))) == NULL) {
            logmsg(LOG_ERR, "Out of memory for poll - aborted");
            exit(1);
        }
        for(lstn = listeners, i = 0; lstn; lstn = lstn->next, i++)
            polls[i].fd = lstn->sock;

        /* set uid if necessary */
        if(user) {
            struct passwd   *pw;

            if((pw = getpwnam(user)) == NULL) {
                logmsg(LOG_ERR, "no such user %s - aborted", user);
                exit(1);
            }
            user_id = pw->pw_uid;
        }

        /* set gid if necessary */
        if(group) {
            struct group    *gr;

            if((gr = getgrnam(group)) == NULL) {
                logmsg(LOG_ERR, "no such group %s - aborted", group);
                exit(1);
            }
            group_id = gr->gr_gid;
        }

        /* Turn off verbose messages (if necessary) */
        print_log = 0;

        if(!daemon && daemonize) {
            /* daemonize - make ourselves a subprocess. */
            switch (fork()) {
                case 0:
                    if(log_facility != -1) {
                        close(0);
                        close(1);
                        close(2);
                    }
                    break;
                case -1:
                    logmsg(LOG_ERR, "fork: %s - aborted", strerror(errno));
                    exit(1);
                default:
                    exit(0);
            }
            daemon = 1;
#ifdef  HAVE_SETSID
            (void) setsid();
#endif
        }

        /* record pid in file */
        if(!fpid) {
            if((fpid = fopen(pid_name, "wt")) != NULL) {
                fprintf(fpid, "%d\n", getpid());
                fclose(fpid);
            } else
                logmsg(LOG_NOTICE, "Create \"%s\": %s", pid_name, strerror(errno));
        }

        shut_down = 0;

        /* split off into monitor and working process if necessary */
        while(!shut_down) {
#ifdef  UPER
            if((son = fork()) > 0) {
                sigset_t mask, oldmask;

                insert_pid(&children, son);

                sigemptyset(&mask);
                sigaddset(&mask, SIGHUP);
                sigaddset(&mask, SIGINT);
                sigaddset(&mask, SIGCHLD);

                sigprocmask(SIG_BLOCK, &mask, &oldmask);
                while(!shut_down) {
                    int status, pid;

                    while((pid = waitpid(-1, &status, WNOHANG)) > 0) {
                        /* we only oversee youngest son, older ones are ignored */
                        if(pid == son) {
                            if(WIFEXITED(status))
                                logmsg(LOG_ERR, "MONITOR: worker %d exited normally %d, restarting...", pid, WEXITSTATUS(status));
                            else if(WIFSIGNALED(status))
                                logmsg(LOG_ERR, "MONITOR: worker %d exited on signal %d, restarting...", pid, WTERMSIG(status));
                            else
                                logmsg(LOG_ERR, "MONITOR: worker %d exited (stopped?) %d, restarting...", pid, status);
                        } else {
                                logmsg(LOG_INFO, "worker %d exited", pid);
                        }
                        remove_pid(&children, pid);
                    }

                    /* wait for children or SIGHUP/INT */
                    sigsuspend(&oldmask);
                }
                /* SIGHUP/INT: reload configuration */
                sigprocmask(SIG_UNBLOCK, &mask, NULL);
                logmsg(LOG_NOTICE, "config reload...");
            } else if (son == 0) {
#endif
                /* chroot if necessary */
                if(root_jail) {
                    if(chroot(root_jail)) {
                        logmsg(LOG_ERR, "chroot: %s - aborted", strerror(errno));
                        exit(1);
                    }
                    if(chdir("/")) {
                        logmsg(LOG_ERR, "chroot/chdir: %s - aborted", strerror(errno));
                        exit(1);
                    }
                }

                if(group)
                    if(setgid(group_id) || setegid(group_id)) {
                        logmsg(LOG_ERR, "setgid: %s - aborted", strerror(errno));
                        exit(1);
                    }
                if(user)
                    if(setuid(user_id) || seteuid(user_id)) {
                        logmsg(LOG_ERR, "setuid: %s - aborted", strerror(errno));
                        exit(1);
                    }

                /* thread stuff */
                pthread_attr_init(&attr);
                pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);

#ifdef  NEED_STACK
                /* set new stack size - necessary for OpenBSD/FreeBSD and Linux NPTL */
                if(pthread_attr_setstacksize(&attr, 1 << 18)) {
                    logmsg(LOG_ERR, "can't set stack size - aborted");
                    exit(1);
                }
#endif
                /* start timer */
                if(pthread_create(&thr, &attr, thr_timer, NULL)) {
                    logmsg(LOG_ERR, "create thr_resurect: %s - aborted", strerror(errno));
                    exit(1);
                }

                /* start the controlling thread (if needed) */
                if(control_sock >= 0 && pthread_create(&thr, &attr, thr_control, NULL)) {
                    logmsg(LOG_ERR, "create thr_control: %s - aborted", strerror(errno));
                    exit(1);
                }

                /* pause to make sure the service threads were started */
                sleep(1);

                /* create the worker threads */
                for(i = 0; i < numthreads; i++)
                    if(pthread_create(&thr, &attr, thr_http, NULL)) {
                        logmsg(LOG_ERR, "create thr_http: %s - aborted", strerror(errno));
                        exit(1);
                    }

                /* pause to make sure at least some of the worker threads were started */
                sleep(1);

                /* and start working */
                for(;;) {
                    if(shut_down) {
                        int finished;

                        logmsg(LOG_NOTICE, "shutting down (%d)...", getpid());
                        for(lstn = listeners; lstn; lstn = lstn->next)
                            close(lstn->sock);
                        /* rename control file (append pid) */
                        if(ctrl_name != NULL) {
                            char *ctrl_tmp = malloc(strlen(ctrl_name)+11);
                            sprintf(ctrl_tmp, "%s.%d", ctrl_name, getpid());
                            rename(ctrl_name, ctrl_tmp);
                            free(ctrl_name);
                            ctrl_name = ctrl_tmp;
                        }
                        /* wait for all threads to be finished */
                        finished = 0;
                        while(!finished) {
                            int running;
                            (void)pthread_mutex_lock(&arg_mut);
                            running = numthreads-waiting;
                            finished = !first && !running;
                            (void)pthread_mutex_unlock(&arg_mut);
                            if(!finished) {
                                logmsg(LOG_INFO, "%d thread(s) still running...", running);
                                sleep(RUNNING_CHECK_PERIOD);
                            }
                        }
                        logmsg(LOG_NOTICE, "no threads running - exiting...");
                        if(ctrl_name != NULL)
                            (void)unlink(ctrl_name);
                        exit(0);
                    }
                    for(lstn = listeners, i = 0; i < n_listeners; lstn = lstn->next, i++) {
                        polls[i].events = POLLIN | POLLPRI;
                        polls[i].revents = 0;
                    }
                    if(poll(polls, n_listeners, -1) < 0) {
                        logmsg(LOG_WARNING, "poll: %s", strerror(errno));
                    } else {
                        for(lstn = listeners, i = 0; lstn; lstn = lstn->next, i++) {
                            if(polls[i].revents & (POLLIN | POLLPRI)) {
                                memset(&clnt_addr, 0, sizeof(clnt_addr));
                                clnt_length = sizeof(clnt_addr);
                                if((clnt = accept(lstn->sock, (struct sockaddr *)&clnt_addr,
                                    (socklen_t *)&clnt_length)) < 0) {
                                    logmsg(LOG_WARNING, "HTTP accept: %s", strerror(errno));
                                } else if(((struct sockaddr_in *)&clnt_addr)->sin_family == AF_INET
                                       || ((struct sockaddr_in *)&clnt_addr)->sin_family == AF_INET6) {
                                    thr_arg arg;

                                    if(lstn->disabled) {
                                        /*
                                        addr2str(tmp, MAXBUF - 1, &clnt_addr, 1);
                                        logmsg(LOG_WARNING, "HTTP disabled listener from %s", tmp);
                                        */
                                        close(clnt);
                                    }
                                    arg.sock = clnt;
                                    arg.lstn = lstn;
                                    if((arg.from_host.ai_addr = (struct sockaddr *)malloc(clnt_length)) == NULL) {
                                        logmsg(LOG_WARNING, "HTTP arg address: malloc");
                                        close(clnt);
                                        continue;
                                    }
                                    memcpy(arg.from_host.ai_addr, &clnt_addr, clnt_length);
                                    arg.from_host.ai_addrlen = clnt_length;
                                    if(((struct sockaddr_in *)&clnt_addr)->sin_family == AF_INET)
                                        arg.from_host.ai_family = AF_INET;
                                    else
                                        arg.from_host.ai_family = AF_INET6;
                                    if(put_thr_arg(&arg))
                                        close(clnt);
                                } else {
                                    /* may happen on FreeBSD, I am told */
                                    logmsg(LOG_WARNING, "HTTP connection prematurely closed by peer");
                                    close(clnt);
                                }
                            }
                        }
                    }
                }
#ifdef  UPER
            } else {
                /* failed to spawn son */
                logmsg(LOG_ERR, "Can't fork worker (%s) - aborted", strerror(errno));
                exit(1);
            }
#endif
        }
    }
}
