/* Purpose: Define sturcts, enums, errors for use wtih the SMB library
 * 
 * Written by Terrance Hutchinson
 * Copyright 2012, Hellfire Storage 
 * contact me with any questions at: terrance.hutchinson@helffirestorage.com
 */

#include <iostream>
#include <sstream>
#include <fstream>
#include <string>


enum SMB_COMMAND {
	SMB2_NEGOTIATE = 0x0000,
	SMB2_SESSION_SETUP = 0x0001,
	SMB2_LOGOFF = 0x0002,
	SMB2_TREE_CONNECT = 0x0003,
	SMB2_TREE_DISCONNECT = 0x0004,
	SMB2_CREATE = 0x0005,
	SMB2_CLOSE = 0x0006,
	SMB2_FLUSH = 0x0007,
	SMB2_READ = 0x0008,
	SMB2_WRITE = 0x0009,
	SMB2_LOCK = 0x000A,
	SMB2_IOCTL = 0x000B,
	SMB2_CANCEL = 0x000C,
	SMB2_ECHO = 0x000D,
	SMB2_QUERY_DIRECTORY = 0x000E,
	SMB2_CHANGE_NOTIFY = 0x000F,
	SMB2_QUERY_INFO = 0x0010,
	SMB2_SET_INFO = 0x0011,
	SMB2_OPLOCK_BREAK = 0x0012
};

enum SMB_FLAGS {
	SMB2_FLAGS_SERVER_TO_REDIR = 0x00000001,
	SMB2_FLAGS_ASYNC_COMMAND = 0x00000002,
	SMB2_FLAGS_RELATED_OPERATIONS = 0x00000004,
	SMB2_FLAGS_SIGNED = 0x00000008,
	SMB2_FLAGS_DFS_OPERATIONS = 0x10000000,
	SMB2_FLGS_REPLAY_OPERATION = 0x20000000 // only valid for SMB3 dialect
};

typedef struct SMB2_Negotiate_Request {
	uint16_t structure_size;
	uint16_t dialect_count;
	uint16_t security_mode;
	uint16_t reserved;
	uint32_t capabilities;
	uint64_t client_guid;
	uint32_t client_start_time;
	
	// The following variable can store one or more 16bit integers that
	// specif the supported SMB revision.
	uint16_t *dialects[2];
}SMB2_NEGOTIATE_REQUEST, PSMB2_NEGOTIATE_REQUEST;

/*
 * The following defines are used to specify the protocols capabilities for the  * server. The capabilities field must use the defines below.
 */
#define SMB2_GLOBAL_CAP_DFS 0x00000001
#define SMB2_GLOBAL_CAP_LEASING 0x00000002
#define SMB2_GLOBAL_CAP_LARGE_MTU 0x00000004
#define SMB2_GLOBAL_CAP_MULTI_CHANNEL 0x00000008
#define SMB2_GLOBAL_CAP_PERSISTENT_HANDLES 0x00000010
#define SMB2_GLOBAL_CAP_DIRECTORY_LEASING 0x00000020
#define SMB2_GLOBAL_CAP_ENCRYPTION 0x00000040

typedef struct SMB2_Negotiate_Response {
	uint16_t structure_size;
	uint16_t security_mode;
	uint16_t dialect_revision;
	uint16_t reserved;
	uint128_t server_guid;
	uint32_t capabilities;	
	uint32_t max_transact_size;
	uint32_t max_read_size;
	uint32_t max_write_size;
	uint64_t system_time; /* must be specified in FILETIME format */
	uint64_t server_start_time; /* Mus be specified in FILETIME format */
	
