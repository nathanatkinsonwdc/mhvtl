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
    // State in task free pool
    FREE,

    // Data carriers
    CONTAINER, PARITY_CONTAINER, PAD_CONTAINER, SUPERBLOCK,
    PAD_SUPERBLOCK, HOST_OBJECT,

    // Host commands
    HOST_CMD_NEW, HOST_WR_CMD, HOST_WRFM_CMD, HOST_READ_POS,
    HOST_RD_CMD, HOST_REWIND_CMD, HOST_SPACE_CMD,
    HOST_LOAD_CMD, HOST_UNLOAD_CMD, HOST_LOCATE_CMD,

    // Internal commands
    WRITE_FLUSH, READ_CACHE_DISCARD,

    // Internal requests
    STREAM_BUFFER_REQUEST, STREAM_SEGMENT_REQUEST, MAP_UPDATE
    
} shimTaskType;

typedef enum {
    SUCCESS, CHECK
} shimStatus;

struct mhvtl_socket_cmd {
    uint16_t id;                    // packet ID
    shimTaskType type;              // derived from scsi opcode
    uint32_t sz;                    // block size
    uint32_t count;                 // block count
    uint32_t mediaBarcode;          // used for load command
    unsigned long long serialNo;
    uint8_t cdb[MAX_COMMAND_SIZE];  // scsi cdb
};

struct mhvtl_socket_stat {
    uint16_t id; // packet ID
    shimStatus completionStatus;
    uint8_t sense[SENSE_BUF_SIZE];
    uint64_t mediaBytesRemaining;
};

extern struct MAM mam;
extern int current_state;
extern int OK_to_write;
extern int sockfd;
extern int is_connected;


int socket_init(const char *sockpath);
void shm_init(uint8_t **dbuf, size_t sz);
void shm_close(uint8_t *dbuf);
uint8_t submit_to_shim(struct mhvtl_socket_cmd *sockcmd, struct mhvtl_socket_stat *sockstat, unsigned char *sam_stat, void *data);
uint8_t ssc_write_6_shim(struct scsi_cmd *cmd);
uint8_t ssc_read_6_shim(struct scsi_cmd *cmd);
uint8_t ssc_locate_shim(struct scsi_cmd *cmd);
uint8_t ssc_write_filemarks_shim(struct scsi_cmd *cmd);
uint8_t ssc_rewind_shim(struct scsi_cmd *cmd);
uint8_t ssc_read_position_shim(struct scsi_cmd *cmd);
uint8_t ssc_space_6_shim(struct scsi_cmd *cmd);
uint8_t ssc_space_16_shim(struct scsi_cmd *cmd);
uint8_t ssc_load_unload_shim(struct scsi_cmd *cmd);

#endif