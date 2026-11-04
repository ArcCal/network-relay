#ifndef MASQUE_NF_BRIDGE_H
#define MASQUE_NF_BRIDGE_H
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
typedef struct NfHandle NfHandle;
typedef struct NfEvent {
    uint32_t kind;
    uint64_t id, token, flags;
    const uint8_t *data;
    size_t len;
} NfEvent;
NfHandle *nf_start(const char *configuration, uint32_t level);
NfEvent *nf_next_event(NfHandle *handle);
void nf_free_event(NfEvent *event);
// ERROR flags: 1 trust, 2 address in use, 3 timeout, 4 connection failure,
// 5 temporary native resource exhaustion (EMFILE/ENFILE).
bool nf_input(NfHandle *handle, uint32_t kind, uint64_t id, uint64_t token, uint64_t flags, const uint8_t *data, size_t len);
typedef enum NfDataInputResult {
    NF_DATA_ACCEPTED = 0,
    NF_DATA_CLOSED = 1,
    NF_DATA_FULL = 2,
    NF_DATA_INVALID = 3
} NfDataInputResult;
// Nonempty DATA only. The existing nf_input ABI, including EOF, is unchanged.
uint32_t nf_input_data(NfHandle *handle, uint64_t id, const uint8_t *data, size_t len);
uint64_t nf_accept(NfHandle *handle, uint64_t parent, uint64_t stream_id, const uint8_t *data, size_t len);
void nf_log_level(NfHandle *handle, uint32_t level);
void nf_stop(NfHandle *handle);
void nf_destroy(NfHandle *handle);
#endif
