/* Independently authored harmless app: write one exclusive private marker, then exit. */
#include <fcntl.h>
#include <unistd.h>

#ifndef PROBE_MARKER
#error Supply the new private kit's marker path at compilation.
#endif

int main(void) {
    const char result[] = "EXECUTED\n";
    int fd = open(PROBE_MARKER, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0600);
    if (fd < 0) return 2;
    if (write(fd, result, sizeof(result) - 1) != (ssize_t)(sizeof(result) - 1)) {
        close(fd);
        return 2;
    }
    return close(fd) == 0 ? 0 : 2;
}
