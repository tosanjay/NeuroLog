/* Test sample: basic buffer overflow via tainted input */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

void process_data(char *input, int len) {
    char buf[64];
    memcpy(buf, input, len);   // vulnerable: no bounds check
    printf("Processed: %s\n", buf);
}

int read_input(int fd) {
    char *data = malloc(1024);
    if (!data) return -1;
    int n = read(fd, data, 1024);
    if (n > 0) {
        process_data(data, n);
    }
    free(data);
    return n;
}

void safe_copy(const char *src) {
    char dst[128];
    size_t slen = strlen(src);
    if (slen < sizeof(dst)) {
        memcpy(dst, src, slen + 1);  // safe: bounds checked
    }
}

int main(int argc, char **argv) {
    if (argc > 1) {
        process_data(argv[1], strlen(argv[1]));  // tainted
    }
    read_input(0);
    return 0;
}
