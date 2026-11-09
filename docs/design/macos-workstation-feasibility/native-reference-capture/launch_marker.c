/* Harmless control app: writes only the explicitly supplied new marker file. */
#include <stdio.h>
#include <unistd.h>

int main(int argc, char **argv) {
    if (argc != 2) {
        fputs("Supply one approved lab marker path.\n", stderr);
        return 2;
    }
    FILE *marker = fopen(argv[1], "wx");
    if (marker == NULL) {
        perror("marker");
        return 2;
    }
    if (fprintf(marker, "harmless control executed pid=%ld\n", (long)getpid()) < 0) {
        fclose(marker);
        return 2;
    }
    return fclose(marker) == 0 ? 0 : 2;
}
