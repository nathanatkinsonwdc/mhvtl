#ifndef SHIM_H
#define SHIM_H

#include <sys/socket.h>
#include <sys/un.h>
#include <fcntl.h>
#include <stddef.h>
#include "vtl_common.h"

#define SHM_NAME "/mhvtl_dbuf"
#define SHM_SZ 16 * 1024 * 1024
#define SHM_MODE 0660
#define SHM_OFLAGS O_RDWR | O_CREAT
#define SOCK_NAME "/tmp/mhvtl.sock"

struct socket_cmd {
    unsigned char *cdb; // scsi cdb
    unsigned int sz; // block size
};

struct socket_stat {
    uint8_t *sense;
    uint64_t current_position;
};

extern struct MAM mam;
extern int current_state;
extern int OK_to_write;
extern int sockfd;

int socket_init(const char *sockpath);
void shm_init(uint8_t *dbuf, size_t sz);
void shm_close(uint8_t *dbuf);
uint8_t ssc_write_6_shim(struct scsi_cmd *cmd);
void writeBlocksRequest(struct scsi_cmd *cmd, uint32_t src_sz);

#endif