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

// same as ssc_write_6, but sends write cmd over socket for completion elsewhere 
uint8_t ssc_write_6_shim(struct scsi_cmd *cmd) {
    struct mhvtl_ds *dbuf_p;
	struct priv_lu_ssc *lu_ssc;
	int count;
	int sz;

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
		/* TODO: handle edge cases that writeBlock() handles */
		writeBlocksRequest(cmd, sz);

		/* If sam_stat != SAM_STAT_GOOD, return */
		if (cmd->dbuf_p->sam_stat)
			return cmd->dbuf_p->sam_stat;
	}

	return SAM_STAT_GOOD;
}

// LBP and compression are ignored
void writeBlocksRequest(struct scsi_cmd *cmd, uint32_t src_sz) {
	struct mhvtl_socket_cmd sockcmd;
	struct mhvtl_socket_stat sockstat;

	memcpy(sockcmd.cdb, cmd->scb, sizeof(uint8_t) * cmd->scb_len); // possibly a way to avoid this copy?
	memset(&sockstat, 0, sizeof(struct mhvtl_socket_stat));
	sockcmd.type = HOST_WR_CMD;
	sockcmd.sz = src_sz;
	sockcmd.count = cmd->dbuf_p->sz / src_sz;
	sockcmd.id = ++cmd_id;
	sockcmd.serialNo = cmd->dbuf_p->serialNo;

	/* Attempt write by requesting over socket */
	if (send(sockfd, &sockcmd, sizeof(sockcmd), 0) < 0) {
		MHVTL_DBG(1, "failed to send packet");
		sam_medium_error(E_WRITE_ERROR, &cmd->dbuf_p->sam_stat);
		is_connected = 0;
		return;
	}

	/* Wait for status */
	if (recv(sockfd, &sockstat, sizeof(sockstat), 0) < 0) {
		MHVTL_DBG(1, "failed to receive packet");
		sam_medium_error(E_WRITE_ERROR, &cmd->dbuf_p->sam_stat);
		is_connected = 0;
		return;
	}

	/* Check status */
	switch (sockstat.sense_key) {
		case UNIT_ATTENTION:
			sam_unit_attention(sockstat.sense_ascq, &cmd->dbuf_p->sam_stat);
			break;
		case NOT_READY:
			sam_not_ready(sockstat.sense_ascq, &cmd->dbuf_p->sam_stat);
			break;
		case ILLEGAL_REQUEST:
			sam_illegal_request(sockstat.sense_ascq, &sockstat.sense_sd, &cmd->dbuf_p->sam_stat);
			break;
		case MEDIUM_ERROR:
			sam_medium_error(sockstat.sense_ascq, &cmd->dbuf_p->sam_stat);
			break;
		case BLANK_CHECK:
			sam_blank_check(sockstat.sense_ascq, &cmd->dbuf_p->sam_stat);
			break;
		case DATA_PROTECT:
			sam_data_protect(sockstat.sense_ascq, &cmd->dbuf_p->sam_stat);
			break;
		case HARDWARE_ERROR:
			sam_hardware_error(sockstat.sense_ascq, &cmd->dbuf_p->sam_stat);
			break;
		case SD_ILI:
		case SD_FILEMARK:
		case (VOLUME_OVERFLOW | SD_EOM):
		case SD_EOM:
		case NO_SENSE:
			if (sockstat.sense_key || sockstat.sense_ascq) // if not both NO_SENSE and NO_ADDITIONAL_SENSE
				sam_no_sense(sockstat.sense_key, sockstat.sense_ascq, &cmd->dbuf_p->sam_stat);
			break;
		default:
			break;
	}
}