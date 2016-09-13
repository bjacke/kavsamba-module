/*  
 * $Id: kavsamba_helpers.h,v 1.4 2004/06/25 12:46:45 automake Exp $
 *
 * This source file is a part of a Kaspersky Antivirus For Samba Servers.
 * Copyright (C) Kaspersky Lab 1998-2004
 * See License.txt for details
 *
 */

#ifndef __KAV_SAMBA_HELPERS__
#define __KAV_SAMBA_HELPERS__

#define SAMBA_INTERFACE_VERSION		2

#define smb_default_sock "/tmp/KavSmb"

enum samba_request_type {
	SAMBA_CONNECT,
	SAMBA_CHECK_FILE,
	SAMBA_CHECKED_FILE
};

enum samba_fileop_type {
	SAMBA_FILE_OPEN,
	SAMBA_FILE_CLOSE,
	SAMBA_FILE_UNLINK
};

enum samba_filestat_type {
	SAMBA_ACCESS_ACCEPT,
	SAMBA_ACCESS_DENY
};


#pragma pack(1)
typedef struct {
	u_short			request;
	u_short			version;
	u_int			data_size;	
} samba_header;

typedef struct {
	samba_header		header;
	char			data[0];
} samba_data;

typedef struct {
	u_int			uid;
	u_int			pid;
	int			flags;
	int			file_op;
	char			name[0];
} samba_check_file;

typedef struct {
	samba_header		header;
	samba_check_file	file;
} samba_check_file_data;


typedef struct {
	int status;
} samba_checked_file;

typedef struct {
	samba_header		header;
	samba_checked_file	file;
} samba_checked_file_data;


typedef struct {
	char name[0];
} samba_connect;


typedef struct {
	samba_header		header;
	samba_connect		config;
} samba_connect_data;

#pragma pack()

typedef void smb_file_check_request_callback(int sock,uid_t, pid_t,const char *,
						enum samba_fileop_type,int);

typedef void smb_file_checked_request_callback(enum  samba_filestat_type);

typedef void smb_connect_callback(int sock,const char * user, 
				  const char * ip, const char * host);

typedef struct {
	smb_connect_callback			* smb_connect;
	smb_file_check_request_callback		* smb_file_check;
	smb_file_checked_request_callback	* smb_file_checked;
} samba_callbacks;

#ifdef __cplusplus
extern "C" {
#endif

void Samba_callbacks_init(samba_callbacks * s_callbacks);
int Samba_connect(int fd, const char * user, const char * ip, const char * host);
int Samba_check_file(int fd,uid_t uid, pid_t pid, const char * filename, 
			enum samba_fileop_type file_op, int flags);

int Samba_checked_file(int fd,enum samba_filestat_type check_result);

int Samba_request_ready(int read_fd, int write_fd, void * data);

#ifdef __cplusplus
}
#endif


#endif
