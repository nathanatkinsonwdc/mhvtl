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
extern struct MAM mam;

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


uint8_t submit_to_shim(struct mhvtl_socket_cmd *sockcmd, struct mhvtl_socket_stat *sockstat, unsigned char *sam_stat, void *data) {
	// Request command completion over socket
	if (send(sockfd, sockcmd, sizeof(struct mhvtl_socket_cmd), 0) < 0) {
		MHVTL_DBG(1, "failed to send packet");
		sam_medium_error(E_UNKNOWN_FORMAT, sam_stat);
		is_connected = 0;
		return *sam_stat;
	}

	// Wait for status
	if (recv(sockfd, sockstat, sizeof(struct mhvtl_socket_stat), 0) < 0) {
		MHVTL_DBG(1, "failed to receive packet");
		sam_medium_error(E_UNKNOWN_FORMAT, sam_stat);
		is_connected = 0;
		return *sam_stat;
	}

	// Verify status matches requested packet
	if (sockcmd->id != sockstat->id) {
		MHVTL_DBG(1, "packet mismatch; expected ID %d but got %d", sockcmd->id, sockstat->id);
		sam_medium_error(E_IMCOMPATIBLE_FORMAT, sam_stat);
		is_connected = 0;
		return *sam_stat;
	}

	// Set status
	*sam_stat = (sockstat->completionStatus == SUCCESS) ? SAM_STAT_GOOD : SAM_STAT_CHECK_CONDITION;
	memcpy(sense, sockstat->sense, sizeof(sense));

	return *sam_stat;
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

	// char cdb[128] = "CMD->SCB: ";
	// char hex[4];
	// for(int i=0; i<6; ++i) {
	// 	sprintf(hex, " %02x", cmd->scb[i]);
	// 	strcat(cdb, hex);
	// }
	// MHVTL_DBG(3, "%s", cdb);

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

	MHVTL_DBG(2, "SHIM: %d block%s of %d bytes (%ld) **",
				sockcmd.count, sockcmd.count == 1 ? "" : "s",
				sockcmd.sz,
				(long)sockcmd.serialNo);

	if (OK_to_write) {
		submit_to_shim(&sockcmd, &sockstat, &cmd->dbuf_p->sam_stat, cmd->dbuf_p->data);

		uint8_t key = sense[2] & 0x0f;
		uint8_t data_format = sense[2] & 0xf0;
		if (key != NO_SENSE) {
			if (key == VOLUME_OVERFLOW) {
				mam.remaining_capacity = 0L;
				MHVTL_DBG(1, "End of Medium - VOLUME_OVERFLOW/EOM");
			} else {
				set_TapeAlert(cmd->lu, (uint64_t)(TA_HARD | TA_WRITE));
			}
		} else if ((lu_ssc->pm->drive_supports_early_warning) && (data_format == SD_EOM)) {
			MHVTL_DBG(1, "End of Medium - Early Warning");
		} else if ((lu_ssc->pm->drive_supports_prog_early_warning) && (data_format == SD_EOM)) {
			MHVTL_DBG(1, "End of Medium - Programmable Early Warning");
		}

		// TODO: pass current position in status so mam.remaining_capacity can be updated
		
		return cmd->dbuf_p->sam_stat;
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
	memcpy(sockcmd.cdb, cdb, sizeof(uint8_t) * cmd->scb_len);
	memset(&sockstat, 0, sizeof(struct mhvtl_socket_stat));
	sockcmd.type = HOST_RD_CMD;
	sockcmd.sz = sz;
	sockcmd.count = count;
	sockcmd.id = ++cmd_id;
	sockcmd.serialNo = cmd->dbuf_p->serialNo;

	submit_to_shim(&sockcmd, &sockstat, sam_stat, cmd->dbuf_p->data);
	
	cmd->dbuf_p->sz = (sockstat.completionStatus == SUCCESS) ? sz*count : sz*(count-get_unaligned_be32(&sense[3]));

	MHVTL_DBG(2, "sz: %d, count: %d, remaining: %d", sz, count, get_unaligned_be32(&sense[3]));

	return cmd->dbuf_p->sam_stat;
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

	return submit_to_shim(&sockcmd, &sockstat, &cmd->dbuf_p->sam_stat, cmd->dbuf_p->data);
}

uint8_t ssc_write_filemarks_shim(struct scsi_cmd *cmd) {
	struct priv_lu_ssc *lu_priv;
	uint8_t *sam_stat;
	int count;

	struct mhvtl_socket_cmd sockcmd;
	struct mhvtl_socket_stat sockstat;

	lu_priv = cmd->lu->lu_private;
	sam_stat = &cmd->dbuf_p->sam_stat;

	count = get_unaligned_be24(&cmd->scb[2]);

	MHVTL_DBG(1, "WRITE %d FILEMARKS (%ld) **", count,
						(long)cmd->dbuf_p->serialNo);
	if (!lu_priv->pm->check_restrictions(cmd)) {
		/* If restrictions & WORM media at block 0.. OK
		 * Otherwise return CHECK_CONDITION.
		 *	check_restrictions()
		 *	was nice enough to set correct sense status for us.
		 */
		if ((mam.MediumType == MEDIA_TYPE_WORM) &&
					(c_pos->blk_number == 0)) {
			MHVTL_DBG(1, "Erasing WORM media");
		} else
			return SAM_STAT_CHECK_CONDITION;
	}

	memcpy(sockcmd.cdb, cmd->scb, sizeof(uint8_t) * cmd->scb_len); 
	memset(&sockstat, 0, sizeof(struct mhvtl_socket_stat));
	sockcmd.type = HOST_WRFM_CMD;
	sockcmd.count = count;
	sockcmd.id = ++cmd_id;
	sockcmd.serialNo = cmd->dbuf_p->serialNo;

	submit_to_shim(&sockcmd, &sockstat, sam_stat, cmd->dbuf_p->data);

	uint8_t key = sense[2] & 0x0f;
	if (count) {
		if (key == SD_EOM) {
			mam.remaining_capacity = 0L;
			MHVTL_DBG(2, "Setting EOM flag");
		}
	}

	return *sam_stat;
}

uint8_t ssc_rewind_shim(struct scsi_cmd *cmd) {
	struct priv_lu_ssc *lu_priv;
	uint8_t *sam_stat;
	struct mhvtl_socket_cmd sockcmd;
	struct mhvtl_socket_stat sockstat;

	lu_priv = cmd->lu->lu_private;
	sam_stat = &cmd->dbuf_p->sam_stat;

	MHVTL_DBG(1, "REWINDING (%ld) **", (long)cmd->dbuf_p->serialNo);

	current_state = MHVTL_STATE_REWIND;

	switch (lu_priv->load_status) {
	case TAPE_UNLOADED:
		sam_not_ready(E_MEDIUM_NOT_PRESENT, sam_stat);
		return SAM_STAT_CHECK_CONDITION;
		break;
	case TAPE_LOADED:
		rewind_tape(sam_stat);

		memcpy(sockcmd.cdb, cmd->scb, sizeof(uint8_t) * cmd->scb_len); 
		memset(&sockstat, 0, sizeof(struct mhvtl_socket_stat));
		sockcmd.type = HOST_REWIND_CMD;
		sockcmd.id = ++cmd_id;
		sockcmd.serialNo = cmd->dbuf_p->serialNo;

		submit_to_shim(&sockcmd, &sockstat, sam_stat, cmd->dbuf_p->data);

		delay_opcode(DELAY_REWIND, lu_priv->delay_rewind);
		break;
	default:
		sam_not_ready(E_MEDIUM_FMT_CORRUPT, sam_stat);
		return SAM_STAT_CHECK_CONDITION;
		break;
	}

	return *sam_stat;
}

uint8_t ssc_read_position_shim(struct scsi_cmd *cmd) {
	struct priv_lu_ssc *lu_priv;
	uint8_t *sam_stat;
	int service_action;
	struct s_sd sd;
	struct mhvtl_socket_cmd sockcmd;
	struct mhvtl_socket_stat sockstat;

	lu_priv = cmd->lu->lu_private;
	sam_stat = &cmd->dbuf_p->sam_stat;

	MHVTL_DBG(1, "READ POSITION (%ld) **", (long)cmd->dbuf_p->serialNo);

	service_action = cmd->scb[1] & 0x1f;
	/* service_action == 0 or 1 -> Returns 20 bytes of data (short) */

	MHVTL_DBG(1, "service_action: %d", service_action);

	*sam_stat = SAM_STAT_GOOD;

	switch (lu_priv->load_status) {
	case TAPE_LOADED:
		switch (service_action) {
		case 0:
		case 1:
		case 6:
			memcpy(sockcmd.cdb, cmd->scb, sizeof(uint8_t) * cmd->scb_len); 
			memset(&sockstat, 0, sizeof(struct mhvtl_socket_stat));
			sockcmd.type = HOST_READ_POS;
			sockcmd.id = ++cmd_id;
			sockcmd.serialNo = cmd->dbuf_p->serialNo;

			submit_to_shim(&sockcmd, &sockstat, sam_stat, cmd->dbuf_p->data);
			break;
		default:
			MHVTL_DBG(1, "service_action not supported");
			sd.byte0 = SKSV | CD;
			sd.field_pointer = 1;
			sam_illegal_request(E_INVALID_FIELD_IN_CDB, &sd,
								sam_stat);
			return SAM_STAT_CHECK_CONDITION;
		}
		break;
	case TAPE_UNLOADED:
		sam_not_ready(E_MEDIUM_NOT_PRESENT, sam_stat);
		return SAM_STAT_CHECK_CONDITION;
		break;
	default:
		sam_not_ready(E_MEDIUM_FMT_CORRUPT, sam_stat);
		return SAM_STAT_CHECK_CONDITION;
		break;
	}
	return *sam_stat;
}

uint8_t ssc_space_6_shim(struct scsi_cmd *cmd) {
	uint8_t code;
	struct s_sd sd;
	struct mhvtl_socket_cmd sockcmd;
	struct mhvtl_socket_stat sockstat;

	current_state = MHVTL_STATE_POSITIONING;

	code = cmd->scb[1] & 0x07;
	if (code < 0 || code > 3) {
		MHVTL_DBG(1, "SPACE (%ld) ** - Unsupported option %d",
			(long)cmd->dbuf_p->serialNo,
			code);

		sd.byte0 = SKSV | CD | BPV | code;
		sd.field_pointer = 1;
		sam_illegal_request(E_INVALID_FIELD_IN_PARMS, &sd, &cmd->dbuf_p->sam_stat);
		return SAM_STAT_CHECK_CONDITION;
	}

	memcpy(sockcmd.cdb, cmd->scb, sizeof(uint8_t) * cmd->scb_len); 
	memset(&sockstat, 0, sizeof(struct mhvtl_socket_stat));
	sockcmd.type = HOST_SPACE_CMD;
	sockcmd.id = ++cmd_id;
	sockcmd.serialNo = cmd->dbuf_p->serialNo;

	submit_to_shim(&sockcmd, &sockstat, &cmd->dbuf_p->sam_stat, cmd->dbuf_p->data);

	return cmd->dbuf_p->sam_stat;
}

uint8_t ssc_space_16_shim(struct scsi_cmd *cmd) {
	uint8_t code;
	struct s_sd sd;
	struct mhvtl_socket_cmd sockcmd;
	struct mhvtl_socket_stat sockstat;

	current_state = MHVTL_STATE_POSITIONING;

	code = cmd->scb[1] & 0x0f;
	if (code < 0 || code > 3) {
		MHVTL_DBG(1, "SPACE (%ld) ** - Unsupported option %d",
			(long)cmd->dbuf_p->serialNo,
			code);

		sd.byte0 = SKSV | CD | BPV | code;
		sd.field_pointer = 1;
		sam_illegal_request(E_INVALID_FIELD_IN_PARMS, &sd, &cmd->dbuf_p->sam_stat);
		return SAM_STAT_CHECK_CONDITION;
	}

	memcpy(sockcmd.cdb, cmd->scb, sizeof(uint8_t) * cmd->scb_len); 
	memset(&sockstat, 0, sizeof(struct mhvtl_socket_stat));
	sockcmd.type = HOST_SPACE_CMD;
	sockcmd.id = ++cmd_id;
	sockcmd.serialNo = cmd->dbuf_p->serialNo;

	submit_to_shim(&sockcmd, &sockstat, &cmd->dbuf_p->sam_stat, cmd->dbuf_p->data);

	return cmd->dbuf_p->sam_stat;
}

uint8_t ssc_load_unload_shim(struct scsi_cmd *cmd) {
	struct priv_lu_ssc *lu_priv;
	uint8_t *sam_stat;
	struct s_sd sd;
	int load_request;
	int media_state;
	struct mhvtl_socket_cmd sockcmd;
	struct mhvtl_socket_stat sockstat;

	lu_priv = cmd->lu->lu_private;
	sam_stat = &cmd->dbuf_p->sam_stat;

	load_request = cmd->scb[4] & 0x01;

	current_state = (load_request) ? MHVTL_STATE_LOADING : MHVTL_STATE_UNLOADING;

	if (cmd->scb[4] & 0x04) { /* EOT bit */
		MHVTL_ERR("EOT bit set on load. Not supported");
		sd.byte0 = SKSV | CD | BPV | 4;
		sd.field_pointer = 4;
		sam_illegal_request(E_INVALID_FIELD_IN_CDB, &sd, sam_stat);
		return SAM_STAT_CHECK_CONDITION;
	}

	MHVTL_DBG(1, "%s TAPE (%ld) **", (load_request) ? "LOADING" : "UNLOADING",
						(long)cmd->dbuf_p->serialNo);

	media_state = rewind_tape(sam_stat);
	switch (lu_priv->load_status) {
	case TAPE_UNLOADED:
		if (load_request) {
			int load_state;
			switch(media_state) {
			case 0:
				/*
				 * lu_priv->barcode indicates there is a tape in mouth
				 * media not mounted, and receive a mount request - attempt
				 * to load media
				 */
				if (!lu_priv->barcode) {
					sam_not_ready(E_MEDIUM_NOT_PRESENT, sam_stat);
					return SAM_STAT_CHECK_CONDITION;
				}
				/*
				 * media_state = 0 - Load OK -> Nothing to do
				 * media_state = 1 - Already loaded -> Nothing to do
				 */
				load_state = loadTape(lu_priv->barcode, sam_stat);
				if (load_state == 2) {
					sam_not_ready(E_MEDIUM_FMT_CORRUPT, sam_stat);
					return SAM_STAT_CHECK_CONDITION;
				} else if (load_state == 3) {
					sam_not_ready(E_MEDIUM_NOT_PRESENT, sam_stat);
					return SAM_STAT_CHECK_CONDITION;
				}

				memcpy(sockcmd.cdb, cmd->scb, sizeof(uint8_t) * cmd->scb_len);
				memset(&sockstat, 0, sizeof(struct mhvtl_socket_stat));
				sockcmd.type = HOST_LOAD_CMD;
				sockcmd.id = ++cmd_id;
				sockcmd.serialNo = cmd->dbuf_p->serialNo;

				// make sure barcode ends in a unique value
				const char *lastDigits = &lu_priv->barcode[strlen(lu_priv->barcode)-1];
				sockcmd.mediaBarcode = (int)lastDigits & 0xff;

				submit_to_shim(&sockcmd, &sockstat, sam_stat, cmd->dbuf_p->data);

				break;
			case 1:
				break;
			default:
				sam_not_ready(E_MEDIUM_FMT_CORRUPT, sam_stat);
				return SAM_STAT_CHECK_CONDITION;
				break;
			}
		} else {
			sam_not_ready(E_MEDIUM_NOT_PRESENT, sam_stat);
			return SAM_STAT_CHECK_CONDITION;
		}
		break;

	case TAPE_LOADED:
		if (!load_request) {
			/* Send library an update status 'true' */
			unloadTape(TRUE, sam_stat);

			memcpy(sockcmd.cdb, cmd->scb, sizeof(uint8_t) * cmd->scb_len);
			memset(&sockstat, 0, sizeof(struct mhvtl_socket_stat));
			sockcmd.type = HOST_UNLOAD_CMD;
			sockcmd.id = ++cmd_id;
			sockcmd.serialNo = cmd->dbuf_p->serialNo;

			submit_to_shim(&sockcmd, &sockstat, sam_stat, cmd->dbuf_p->data);
		}
		break;

	default:
		sam_not_ready(E_MEDIUM_FMT_CORRUPT, sam_stat);
		return SAM_STAT_CHECK_CONDITION;
		break;
	}
	return *sam_stat;
}