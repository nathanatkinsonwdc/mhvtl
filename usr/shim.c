#include <sys/socket.h>
#include <sys/un.h>
#include <sys/mman.h>
#include <errno.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stddef.h>
#include <string.h>
#include <dirent.h>
#include <syslog.h>
#include <ctype.h>
#include <inttypes.h>
#include <assert.h>
#include "be_byteshift.h"
#include "mhvtl_scsi.h"
#include "mhvtl_list.h"
#include "vtl_common.h"
#include "logging.h"
#include "vtllib.h"
#include "spc.h"
#include "q.h"
#include "ssc.h"
#include "vtltape.h"
#include "mhvtl_log.h"
#include "mode.h"
#include "shim.h"

unsigned int cmd_id = 0;
extern uint8_t sense[SENSE_BUF_SIZE];

// socket backend is responsible for listening server, including sockpath link/unlink
// uses UNIX domain stream sockets
int socket_init(const char *sockpath) {
	if (sockpath == NULL)
		sockpath = MHVTL_SOCK_NAME;

    struct sockaddr_un server;
	int fd;
    memset(&server, 0, sizeof(server));

    if ((fd = socket(AF_UNIX, SOCK_STREAM, 0)) < 0) {
		MHVTL_DBG(2, "failed to create socket: %s", strerror(errno))
        perror("failed to create socket");
		return -1;
    }

    server.sun_family = AF_UNIX;
    strcpy(server.sun_path, sockpath);

	if ((connect(fd, (const struct sockaddr *)&server, sizeof(server))) < 0) {
		close(fd);
		MHVTL_DBG(2, "failed to connect to socket: %s", strerror(errno))
		perror("failed to connect to socket");
		return -1;
	}

    return fd;
}

// don't forget to close and compile with -lrt
// shm_init() should be called to replace buffer in main() that gets passed to mhvtl_ds
void shm_init(uint8_t **dbuf, size_t sz) {
	int fd;

    if ((fd = shm_open(SHM_NAME, SHM_OFLAGS, SHM_MODE)) < 0)
        MHVTL_ERR("Could not initialize shared memory: %s", strerror(errno));
	if (ftruncate(fd, SHM_SZ) < 0)
        MHVTL_ERR("Failed to set shared memory size: %s", strerror(errno));
    if ((*dbuf = (uint8_t *)mmap(NULL, sz, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0)) == MAP_FAILED) 
        MHVTL_ERR("Failed to map shared memory: %s", strerror(errno));

    close(fd);
}

// socket backend is expected to unlink shm
void shm_close(uint8_t *dbuf) {
	munmap((void *)dbuf, SHM_SZ);
}

static uint8_t submit_to_shim(struct mhvtl_socket_cmd *sockcmd, struct mhvtl_socket_stat *sockstat, struct mhvtl_ds *dbuf_p) {
	// Request command completion over socket
	if (send(sockfd, sockcmd, sizeof(struct mhvtl_socket_cmd), 0) < 0) {
		MHVTL_DBG(1, "failed to send packet");
		sam_medium_error(E_UNKNOWN_FORMAT, &dbuf_p->sam_stat);
		is_connected = 0;
		return dbuf_p->sam_stat;
	}

	// Wait for status
	if (recv(sockfd, sockstat, sizeof(struct mhvtl_socket_stat), 0) < 0) {
		MHVTL_DBG(1, "failed to receive packet");
		sam_medium_error(E_UNKNOWN_FORMAT, &dbuf_p->sam_stat);
		is_connected = 0;
		return dbuf_p->sam_stat;
	}

	// Verify status matches requested packet
	if (sockcmd->id != sockstat->id) {
		MHVTL_DBG(1, "packet mismatch; expected ID %d but got %d", sockcmd->id, sockstat->id);
		sam_medium_error(E_IMCOMPATIBLE_FORMAT, &dbuf_p->sam_stat);
		is_connected = 0;
		return dbuf_p->sam_stat;
	}

	// uint8_t sense_key = sockstat->sense[2] & 0x0f;
	// uint16_t sense_asc_ascq = sockstat->sense[12] << 0x08 | sockstat->sense[13];
	// struct s_sd sense_sd = {sockstat->sense[15], sockstat->sense[16] << 0x08 | sockstat->sense[17]};
	// switch (sense_key) {
	// 	case UNIT_ATTENTION:
	// 		sam_unit_attention(sense_asc_ascq, &dbuf_p->sam_stat);
	// 		break;
	// 	case NOT_READY:
	// 		sam_not_ready(sense_asc_ascq, &dbuf_p->sam_stat);
	// 		break;
	// 	case ILLEGAL_REQUEST:
	// 		sam_illegal_request(sense_asc_ascq, &sense_sd, &dbuf_p->sam_stat);
	// 		break;
	// 	case MEDIUM_ERROR:
	// 		sam_medium_error(sense_asc_ascq, &dbuf_p->sam_stat);
	// 		break;
	// 	case BLANK_CHECK:
	// 		sam_blank_check(sense_asc_ascq, &dbuf_p->sam_stat);
	// 		break;
	// 	case DATA_PROTECT:
	// 		sam_data_protect(sense_asc_ascq, &dbuf_p->sam_stat);
	// 		break;
	// 	case HARDWARE_ERROR:
	// 		sam_hardware_error(sense_asc_ascq, &dbuf_p->sam_stat);
	// 		break;
	// 	case SD_ILI:
	// 	case SD_FILEMARK:
	// 	case (VOLUME_OVERFLOW | SD_EOM):
	// 	case SD_EOM:
	// 	case NO_SENSE:
	// 		if (sense_key || sense_asc_ascq) // if not both NO_SENSE and NO_ADDITIONAL_SENSE
	// 			sam_no_sense(sense_key, sense_asc_ascq, &dbuf_p->sam_stat);
	// 		break;
	// 	default:
	// 		break;
	// }

	// Set status
	dbuf_p->sam_stat = (sockstat->sense[0] & SD_VALID) ? SAM_STAT_CHECK_CONDITION : SAM_STAT_GOOD;
	memcpy(sense, sockstat->sense, sizeof(sense));

	return dbuf_p->sam_stat;
}

uint8_t ssc_write_6_shim(struct scsi_cmd *cmd) {
    struct mhvtl_ds *dbuf_p;
	struct priv_lu_ssc *lu_ssc;
	int count;
	int sz;

	struct mhvtl_socket_cmd sockcmd;
	struct mhvtl_socket_stat sockstat;

	lu_ssc = cmd->lu->lu_private;
	dbuf_p = cmd->dbuf_p;

	current_state = MHVTL_STATE_WRITING;

	opcode_6_params(cmd, &count, &sz);
	MHVTL_DBG(1, "%s(): %d block%s of %d bytes (%ld) **",
				__func__,
				count, count == 1 ? "" : "s",
				sz,
				(long)cmd->dbuf_p->serialNo);

	if ((sz * count) > lu_ssc->bufsize)
		MHVTL_DBG(1, "Fatal: bufsize %d, requested write of %d bytes", lu_ssc->bufsize, sz);

	dbuf_p->sz = sz * count;

	/* Retrieve data from kernel - unless media type is 'null' */
	if (likely(mam.MediumType != MEDIA_TYPE_NULL))
		retrieve_CDB_data(cmd->cdev, dbuf_p);

	if (!lu_ssc->pm->check_restrictions(cmd))
		return SAM_STAT_CHECK_CONDITION;

	memcpy(sockcmd.cdb, cmd->scb, sizeof(uint8_t) * cmd->scb_len); // possibly a way to avoid this copy?
	memset(&sockstat, 0, sizeof(struct mhvtl_socket_stat));
	sockcmd.type = HOST_WR_CMD;
	sockcmd.sz = sz;
	sockcmd.count = count;
	sockcmd.id = ++cmd_id;
	sockcmd.serialNo = cmd->dbuf_p->serialNo;

	MHVTL_DBG(1, "SHIM: %d block%s of %d bytes (%ld) **",
				sockcmd.count, sockcmd.count == 1 ? "" : "s",
				sockcmd.sz,
				(long)sockcmd.serialNo);

	if (OK_to_write) {
		/* TODO: handle edge cases that writeBlock() handles */
		return submit_to_shim(&sockcmd, &sockstat, cmd->dbuf_p);
	}

	return SAM_STAT_GOOD;
}

uint8_t ssc_read_6_shim(struct scsi_cmd *cmd) {
	uint8_t *cdb = cmd->scb;
	uint8_t *sam_stat = &cmd->dbuf_p->sam_stat;
	int count;
	int sz;
	struct s_sd sd;
	struct priv_lu_ssc *lu_ssc;

	struct mhvtl_socket_cmd sockcmd;
	struct mhvtl_socket_stat sockstat;

	current_state = MHVTL_STATE_READING;

	opcode_6_params(cmd, &count, &sz);
	MHVTL_DBG(1, "%s(): %d block%s of %d bytes (%ld) **",
				__func__,
				count, count == 1 ? "" : "s",
				sz,
				(long)cmd->dbuf_p->serialNo);

	/* If both FIXED & SILI bits set, invalid combo.. */
	if ((cdb[1] & (SILI | FIXED_BLOCK)) == (SILI | FIXED_BLOCK)) {
		MHVTL_DBG(1, "Suppress ILI and Fixed block "
					"read not allowed by SSC3");
		sd.byte0 = SKSV | CD;
		sd.field_pointer = 1;
		sam_illegal_request(E_INVALID_FIELD_IN_CDB, &sd, sam_stat);
		return SAM_STAT_CHECK_CONDITION;
	}

	lu_ssc = cmd->lu->lu_private;

	// check load status before attempting to read
	switch (lu_ssc->load_status) {
		case TAPE_LOADING:
			sam_not_ready(E_BECOMING_READY, sam_stat);
			return SAM_STAT_CHECK_CONDITION;
			break;
		case TAPE_LOADED:
			if (mam.MediumType == MEDIA_TYPE_CLEAN) {
				MHVTL_DBG(3, "Cleaning cart loaded");
				sam_not_ready(E_CLEANING_CART_INSTALLED,
									sam_stat);
				return SAM_STAT_CHECK_CONDITION;
			}
			break;
		case TAPE_UNLOADED:
			MHVTL_DBG(3, "No media loaded");
			sam_not_ready(E_MEDIUM_NOT_PRESENT, sam_stat);
			return SAM_STAT_CHECK_CONDITION;
			break;
		default:
			MHVTL_DBG(1, "Media format corrupt");
			sam_not_ready(E_MEDIUM_FMT_CORRUPT, sam_stat);
			return SAM_STAT_CHECK_CONDITION;
			break;
	}

	// populate packet data
	memcpy(sockcmd.cdb, cmd->scb, sizeof(uint8_t) * cmd->scb_len);
	memset(&sockstat, 0, sizeof(struct mhvtl_socket_stat));
	sockcmd.type = HOST_RD_CMD;
	sockcmd.sz = sz;
	sockcmd.count = count;
	sockcmd.id = ++cmd_id;
	sockcmd.serialNo = cmd->dbuf_p->serialNo;

	cmd->dbuf_p->sz = sz*count; // preemptively set size and overwrite if sam_stat == CHECK_CONDITION

	return submit_to_shim(&sockcmd, &sockstat, cmd->dbuf_p);
}

uint8_t ssc_locate_shim(struct scsi_cmd *cmd) {
	uint32_t blk_no;
	struct mhvtl_socket_cmd sockcmd;
	struct mhvtl_socket_stat sockstat;

	current_state = MHVTL_STATE_LOCATE;

	MHVTL_DBG(1, "LOCATE %d (%ld) **", (cmd->scb[0] == LOCATE_16) ? 16 : 10,
			(long)cmd->dbuf_p->serialNo);

	blk_no = (cmd->scb[0] == LOCATE_16) ?
		get_unaligned_be64(&cmd->scb[4]) : get_unaligned_be32(&cmd->scb[3]);

	// populate packet data
	memcpy(sockcmd.cdb, cmd->scb, sizeof(uint8_t) * cmd->scb_len);
	memset(&sockstat, 0, sizeof(struct mhvtl_socket_stat));
	sockcmd.type = HOST_LOCATE_CMD;
	sockcmd.count = blk_no;
	sockcmd.id = ++cmd_id;
	sockcmd.serialNo = cmd->dbuf_p->serialNo;

	/* If we want to seek closer to beginning of file than
	 * we currently are, rewind and seek from there
	 */
	MHVTL_DBG(2, "Current blk: %d, seek: %d",
					c_pos->blk_number, blk_no);

	return submit_to_shim(&sockcmd, &sockstat, cmd->dbuf_p);
}