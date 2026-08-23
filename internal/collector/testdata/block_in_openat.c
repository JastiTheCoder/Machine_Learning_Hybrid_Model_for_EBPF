// block_in_openat.c — used by TestFileCollectorClearsPendingOpensEntryWhenKilledMidOpenat
// (AUDIT.md H2).
//
// Reports its own pid, waits for one byte on stdin (the test's synchronisation
// point once it has finished marking this pid tracked), then calls open() on
// the path given in argv[1] with O_RDONLY. If that path is a FIFO with no
// writer, open() blocks in an interruptible sleep indefinitely -- this
// reproduces "a tracked process is SIGKILLed while blocked inside openat()"
// deterministically, rather than relying on timing luck to catch a real
// syscall mid-flight.
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "usage: %s <fifo-path>\n", argv[0]);
        return 1;
    }

    printf("PID=%d\n", getpid());
    fflush(stdout);

    char go;
    if (read(STDIN_FILENO, &go, 1) != 1)
        return 1;

    // Blocks here until a writer opens the other end of the FIFO -- which
    // the test never provides. The test kills this process instead, while
    // it is parked here.
    int fd = open(argv[1], O_RDONLY);
    if (fd >= 0)
        close(fd);
    return 0;
}
