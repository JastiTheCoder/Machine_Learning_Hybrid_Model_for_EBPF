/*
 * fork_from_thread.c — deterministically calls fork(2) from a thread that is
 * NOT the process's thread-group leader.
 *
 * Exists to reproduce, without depending on Go runtime scheduling, the exact
 * scenario in the audited finding: "the fork handler filters a thread id
 * against a tgid-keyed map... for a multithreaded process forking from a
 * non-leader thread the lookup misses and the fork event ... is silently
 * dropped."
 *
 * Protocol on stdout, one line each, flushed immediately so a Go test can
 * read them as they appear:
 *   PARENT_PID=<pid>   this process's pid (== its tgid; this is what a
 *                      correct tracker keys "the tracked process" by)
 *   CHILD_PID=<pid>    the pid fork() returned, produced by a pthread whose
 *                      own tid is guaranteed to differ from PARENT_PID
 *
 * The forked child does nothing but exit immediately; only the fork event
 * itself is under test, not anything the child subsequently does.
 */
#define _GNU_SOURCE
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <unistd.h>

static pid_t g_child_pid = -1;

static void *forker(void *arg) {
    (void)arg;

    pid_t pid = fork();
    if (pid < 0) {
        perror("fork");
        _exit(1);
    }
    if (pid == 0) {
        /* Child: nothing to do, exit immediately. */
        _exit(0);
    }

    g_child_pid = pid;
    return NULL;
}

int main(void) {
    printf("PARENT_PID=%d\n", (int)getpid());
    fflush(stdout);

    pthread_t th;
    if (pthread_create(&th, NULL, forker, NULL) != 0) {
        fprintf(stderr, "pthread_create failed\n");
        return 1;
    }
    if (pthread_join(th, NULL) != 0) {
        fprintf(stderr, "pthread_join failed\n");
        return 1;
    }

    if (g_child_pid < 0) {
        fprintf(stderr, "fork failed in worker thread\n");
        return 1;
    }

    printf("CHILD_PID=%d\n", (int)g_child_pid);
    fflush(stdout);

    int status;
    waitpid(g_child_pid, &status, 0);
    return 0;
}
