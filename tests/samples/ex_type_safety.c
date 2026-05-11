/**
 * ex_type_safety.c — Test cases for type confusion vulnerabilities.
 *
 * Patterns tested:
 *   1. Signed-to-unsigned truncation before malloc (attacker controls size)
 *   2. Integer overflow in narrow arithmetic before memcpy length
 *   3. Sign extension causing massive allocation
 *   4. Implicit truncation in comparison (signed < unsigned)
 *   5. Unguarded cast from user input
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

// BUG 1: Truncation of attacker-controlled size before malloc.
// Attacker sends size=0x100000010 as size_t (64-bit), truncated to
// uint32_t → 0x10. malloc(0x10) allocates 16 bytes, then memcpy
// copies the full attacker-controlled length → heap overflow.
void process_packet(const char *data, size_t total_len) {
    uint32_t payload_len = (uint32_t)total_len;     // TRUNCATION: 8→4 bytes
    char *buf = malloc(payload_len);                  // allocates truncated size
    if (buf) {
        memcpy(buf, data, total_len);                 // copies original size → OVERFLOW
        printf("Processed %u bytes\n", payload_len);
        free(buf);
    }
}

// BUG 2: Integer overflow in narrow arithmetic.
// Two uint16_t values added without widening → wraps around to small
// value, then used as allocation size.
void concat_messages(const char *msg1, uint16_t len1,
                     const char *msg2, uint16_t len2) {
    uint16_t total = len1 + len2;                     // OVERFLOW: 0xFFFF + 2 = 1
    char *combined = malloc(total);
    if (combined) {
        memcpy(combined, msg1, len1);                 // overflow if total wrapped
        memcpy(combined + len1, msg2, len2);
        combined[total - 1] = '\0';
        free(combined);
    }
}

// BUG 3: Sign extension causing massive allocation.
// User sends a negative int8 (e.g., -1 = 0xFF), sign-extended to
// int64 → 0xFFFFFFFFFFFFFFFF. Used as size → DoS or wrapping.
void allocate_from_header(int8_t header_size) {
    long alloc_size = (long)header_size;              // SIGN_EXTEND: 1→8 bytes
    if (alloc_size > 0) {
        // Guard only checks > 0, but -1 sign-extended is huge positive
        // when treated as unsigned by malloc
        char *buf = malloc(alloc_size);
        if (buf) {
            memset(buf, 0, alloc_size);
            free(buf);
        }
    }
}

// BUG 4: Implicit signed/unsigned comparison.
// Negative user input passes "< MAX_SIZE" check because signed int
// is implicitly converted to unsigned for comparison.
#define MAX_SIZE 1024
void read_with_check(int fd, int user_size) {
    if (user_size < MAX_SIZE) {                       // IMPLICIT: signed < unsigned
        // user_size = -1 passes this check!
        // When used as size_t in read(), becomes 0xFFFFFFFF...
        char buf[MAX_SIZE];
        read(fd, buf, user_size);                     // reads huge amount → OVERFLOW
    }
}

// BUG 5: Chained casts through function boundary.
// Attacker-controlled uint64 → uint32 → uint16 double truncation.
uint16_t narrow_size(uint32_t size) {
    return (uint16_t)size;                            // TRUNCATION: 4→2 bytes
}

void double_truncation(const char *data, uint64_t attacker_len) {
    uint32_t mid = (uint32_t)attacker_len;            // TRUNCATION: 8→4 bytes
    uint16_t final_len = narrow_size(mid);            // TRUNCATION: 4→2 bytes
    char *buf = malloc(final_len + 1);
    if (buf) {
        memcpy(buf, data, attacker_len);              // uses original size → OVERFLOW
        buf[final_len] = '\0';
        free(buf);
    }
}

// SAFE: proper bounds check before cast prevents the bug.
void safe_process(const char *data, size_t total_len) {
    if (total_len > UINT32_MAX) {                     // GUARD: range check
        return;
    }
    uint32_t payload_len = (uint32_t)total_len;       // safe after check
    char *buf = malloc(payload_len);
    if (buf) {
        memcpy(buf, data, payload_len);               // uses checked value
        free(buf);
    }
}

int main(int argc, char *argv[]) {
    // Simulate attacker-controlled input
    char data[256];
    size_t len = 0x100000010ULL;  // huge value that truncates to 0x10

    if (argc > 1) {
        len = atol(argv[1]);
    }

    process_packet(data, len);
    return 0;
}
