#ifndef SHIM_H
#define SHIM_H

#include "vtl_common.h"
#include "vtllib.h"

#define SHM_NAME "/mhvtl_dbuf"
#define SHM_SZ 16 * 1024 * 1024
#define SHM_MODE 0666
#define SHM_OFLAGS O_RDWR | O_CREAT
#define MHVTL_SOCK_NAME "/tmp/mhvtl.sock"

typedef enum { 
    FREE, HOST_CMD_NEW, HOST_WR_CMD, 
    HOST_RD_CMD, STREAM_BUFFER_REQUEST, STREAM_SEGMENT_REQUEST, 
    CONTAINER, HOST_OBJECT, SUPERBLOCK, 
    WRITE_FLUSH, MAP_UPDATE, HOST_LOCATE_CMD
} shimTaskType;

struct mhvtl_socket_cmd {
    uint16_t id; // packet ID
    shimTaskType type; // backend task type
    uint32_t sz; // block size
    uint32_t count; // block count
    unsigned long long serialNo;
    uint8_t cdb[MAX_COMMAND_SIZE]; // scsi cdb
};

struct mhvtl_socket_stat {
    uint16_t id; // packet ID
    uint8_t sense_key;
    uint32_t sense_ascq; // sense additional field
    struct s_sd sense_sd;
};

extern struct MAM mam;
extern int current_state;
extern int OK_to_write;
extern int sockfd;
extern int is_connected;


int socket_init(const char *sockpath);
void shm_init(uint8_t **dbuf, size_t sz);
void shm_close(uint8_t *dbuf);
uint8_t ssc_write_6_shim(struct scsi_cmd *cmd);
uint8_t ssc_read_6_shim(struct scsi_cmd *cmd);
uint8_t ssc_locate_shim(struct scsi_cmd *cmd);

#endif