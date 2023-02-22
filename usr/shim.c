#include <sys/mman.h>
#include <errno.h>
#include "vtllib.h"
#include "vtl_common.h"
#include "ssc.h"
#include "logging.h"
#include "mhvtl_scsi.h"
#include "mhvtl_log.h"
#include "shim.h"

unsigned int cmd_id = 0;

// socket backend is responsible for listening server, including sockpath link/unlink
// uses UNIX domain stream sockets
int socket_init(const char *sockpath) {
	if (sockpath == NULL)
		sockpath = MHVTL_SOCK_NAME;

    struct sockaddr_un server;
	int fd;
    memset(&server, 0, sizeof(server));

    if ((fd = socket(AF_UNIX, SOCK_STREAM, 0)) < 0) {
		MHVTL_ERR("failed to create socket: %s", strerror(errno))
        perror("failed to create socket");
        exit(1);
    }

    server.sun_family = AF_UNIX;
    strcpy(server.sun_path, sockpath);

	if ((connect(fd, (const struct sockaddr *)&server, sizeof(server))) < 0) {
		close(fd);
		MHVTL_ERR("failed to connect to socket: %s", strerror(errno))
		perror("failed to connect to socket");
		exit(1);
	}

    return fd;
}

// don't forget to close and compile with -lrt
// shm_init() should be called to replace buffer in main() that gets passed to mhvtl_ds
void shm_init(uint8_t *dbuf, size_t sz) {
	int fd;

    if (fd = shm_open(SHM_NAME, SHM_OFLAGS, SHM_MODE) < 0)
        MHVTL_ERR("Could not initialize shared memory");
    if ((dbuf = (uint8_t *)mmap(NULL, sz, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0)) == MAP_FAILED) 
        MHVTL_ERR("Failed to map shared memory");

    close(fd);
}

// socket backend is expected to unlink shm
void shm_close(uint8_t *dbuf) {
	munmap((void *)dbuf, SHM_SZ);
}

// same as ssc_write_6, but sends write cmd over socket for completion elsewhere 
uint8_t ssc_write_6_shim(struct scsi_cmd *cmd) {
    struct mhvtl_ds *dbuf_p;
	struct priv_lu_ssc *lu_ssc;
	uint64_t current_position;
	int count;
	int sz;
	int k;
	int retval = 0;

	lu_ssc = cmd->lu->lu_private;
	dbuf_p = cmd->dbuf_p;

	current_state = MHVTL_STATE_WRITING;

	opcode_6_params(cmd, &count, &sz);
	MHVTL_DBG(3, "%s(): %d block%s of %d bytes (%ld) **",
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

	if (OK_to_write) {
		writeBlocksRequest(cmd, sz);

		// TODO: remove filesystem write by fully implementing write flow in backend
		for (k = 0; k < count; k++) {
			retval = writeBlock(cmd, sz);
			dbuf_p->data += retval;

			/* If sam_stat != SAM_STAT_GOOD, return */
			if (cmd->dbuf_p->sam_stat)
				return cmd->dbuf_p->sam_stat;
		}
	}
	return SAM_STAT_GOOD;
}

// LBP and compression are ignored
void writeBlocksRequest(struct scsi_cmd *cmd, uint32_t src_sz) {
	struct priv_lu_ssc *lu_ssc;
	int src_len;
	uint64_t current_position;
	int64_t remaining_capacity;
	uint8_t *sam_stat = &cmd->dbuf_p->sam_stat;
	struct mhvtl_socket_cmd sockcmd;
	struct mhvtl_socket_stat sockstat;

	lu_ssc = cmd->lu->lu_private;
	src_len = 0;
	
	sockcmd.opcode = sockcmd.cdb[0];
	sockcmd.sz = src_sz;
	sockcmd.id = ++cmd_id;
	sockcmd.serialNo = cmd->dbuf_p->serialNo;
	memcpy(sockcmd.cdb, *cmd->scb, sizeof(uint8_t) * cmd->scb_len); // possibly a way to avoid this copy?
	memset(&sockstat, 0, sizeof(struct mhvtl_socket_stat));

	/* Check if we hit EOT and fail before attempting to write */
	current_position = current_tape_offset();
	if (current_position >= lu_ssc->max_capacity) {
		mam.remaining_capacity = 0L;
		MHVTL_DBG(1, "End of Medium - VOLUME_OVERFLOW/EOM");
		sam_no_sense(VOLUME_OVERFLOW | SD_EOM, E_EOM, cmd->dbuf_p->sam_stat);
	}

	/* Attempt write by requesting over socket */
	if (send(sockfd, &sockcmd, sizeof(sockcmd), 0) < 0) {
		MHVTL_ERR("failed to send packet");
		return 0;
	}

	if (recv(sockfd, &sockstat, sizeof(sockstat), 0) < 0) {
		MHVTL_ERR("failed to receive packet");
		return 0;
	}

	/* TODO: verify proper sense codes returned (see mhvtl_scsi.h) */
	// switch(sockstat.sense[0]) {
	// 	case ... -> sam_no_sense(KEY, NO_SENSE, cmd->dbuf_p->sam_stat)
	// 	default ... 
	// }

	lu_ssc->bytesWritten_M += src_sz;
	lu_ssc->bytesWritten_I += src_sz;
	src_len = (cmd->dbuf_p->sam_stat == SAM_STAT_GOOD) ? src_sz : 0; 

	if (!src_len) {
		/* Set 'Read/Write error' TapeAlert flag */
		uint64_t fg = TA_HARD | TA_WRITE;
		set_TapeAlert(cmd->lu, fg);
		return 0;
	}

	current_position = sockstat.current_position;
	if ((lu_ssc->pm->drive_supports_early_warning) &&
			(current_position >= (uint64_t)lu_ssc->early_warning_position)) {
		MHVTL_DBG(1, "End of Medium - Early Warning");
		sam_no_sense(SD_EOM, NO_ADDITIONAL_SENSE, sam_stat);
	} else if ((lu_ssc->pm->drive_supports_prog_early_warning) &&
			(current_position >= (uint64_t)lu_ssc->prog_early_warning_position)) {
		/* FIXME: Need to implement REW bit in Device Configuration Mode Page
		 *	  REW == Report Early Warning
		 */
		MHVTL_DBG(1, "End of Medium - Programmable Early Warning");
		sam_no_sense(SD_EOM, E_PROGRAMMABLE_EARLY_WARNING, sam_stat);
	}
	
	remaining_capacity = lu_ssc->max_capacity - current_position;
	if (remaining_capacity < 0)
		remaining_capacity = 0L;

	put_unaligned_be64(remaining_capacity, &mam.remaining_capacity);

	return src_len;
}