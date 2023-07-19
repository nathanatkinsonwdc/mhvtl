#ifndef SHIM_H
#define SHIM_H

#include <stdbool.h>
#include "vtl_common.h"
#include "vtllib.h"

#define SHM_NAME        "/mhvtl_dbuf"
#define SHM_SZ          16 * 1024 * 1024
#define SHM_MODE        0777
#define SHM_OFLAGS      O_RDWR | O_CREAT
#define MHVTL_SOCK_NAME "/tmp/mhvtl.sock"
#define MAX_SERIAL_LEN  64

typedef enum { 
    // State in task free pool
    FREE,

    // Data carriers
    CONTAINER, PARITY_CONTAINER, PAD_CONTAINER, SUPERBLOCK, SUPERBLOCK_FLUSH,
    PAD_SUPERBLOCK, HOST_OBJECT,

    // Host commands
    HOST_CMD_NEW, HOST_WR_CMD, HOST_WRFM_CMD, HOST_READ_POS,
    HOST_RD_CMD, HOST_REWIND_CMD, HOST_SPACE_CMD,
    HOST_LOAD_CMD, HOST_UNLOAD_CMD, HOST_LOCATE_CMD,

    // Internal commands
    WRITE_FLUSH, READ_CACHE_DISCARD,

    // Internal requests
    STREAM_BUFFER_REQUEST, STREAM_SEGMENT_REQUEST, MAP_UPDATE, EXTEND_READ_STREAM
    
} shimTaskType;

enum hostCommandStatus  {SUCCESS, CHECK};

struct mhvtl_socket_cmd {
    uint16_t    id;                     // packet ID
    shimTaskType type;                   // derived from scsi opcode
    uint32_t    sz;                     // block size
    uint32_t    count;                  // block count
    bool        sew;                    // Synchronize at Early Warning
                                        /*
                                           A synchronize at early-warning (SEW) bit set to one specifies the logical unit shall cause any
                                           buffered logical objects to be transferred to the medium prior to returning status if positioned
                                           between early-warning and EOP. A SEW bit set to zero specifies the logical unit may retain
                                           unwritten buffered logical objects in the object buffer if positioned between early-warning and EOP
                                         */
    
    bool        rew;                    // A report early-warning (REW) bit set to zero specifies the device server shall not report
                                        // the early-warning condition for read operations and it shall report early-warning at or
                                        // before any medium-defined early-warning position during write operations. Application
                                        // clients should set the REW bit to zero.
                                        /*
                                          A REW bit set to one specifies the device server shall return CHECK CONDITION status with the additional
                                          sense code set to END-OF-PARTITION/MEDIUM DETECTED, and the EOM bit set to one in the sense data if
                                          early-warning position is encountered during read and write operations. If the REW bit is one and the
                                          SEW bit is zero, the device server shall return CHECK CONDITION status with the sense key set to
                                          VOLUME OVERFLOW if early-warning is encountered during write operations.
                                          NOTE 60 - A REW bit set to one is intended for compatibility with application clients using legacy formats
                                          that require an early-warning indication during read operations.
                                        */
    char        serial[MAX_SERIAL_LEN]; // serial number string
    uint8_t     cdb[MAX_COMMAND_SIZE];  // scsi cdb
};

struct mhvtl_socket_stat {
    uint16_t id; // packet ID
    enum hostCommandStatus completionStatus;
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