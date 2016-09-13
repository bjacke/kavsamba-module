/*  
 * $Id: kavsamba_common.h,v 1.5 2004/05/12 09:17:20 isv Exp $
 *
 * This source file is a part of a Kaspersky Antivirus For Samba Servers.
 * Copyright (C) Kaspersky Lab, 1997-2004
 * See License.txt for details
 *
 */


#ifndef __KAV_SAMBA_COMMON__
#define __KAV_SAMBA_COMMON__

typedef struct {
	int				  sock;
	enum  samba_filestat_type	  check_result;
	int				  flags;
	int				  written;
	char				* filename;
	enum samba_filestat_type	  file_result;
	time_t				  last_open;
} samba_conn;


void     samba_file_checked(enum  samba_filestat_type status);
enum     samba_filestat_type kav_check_file(const char * filename, 
	 				   enum samba_fileop_type file_op, int flags);
enum     samba_filestat_type	kav_unlink_file(const char * filename);
int      kav_connect();
int      kav_disconnect(void);
void free_daemon( samba_conn * conn);
void samba_file_checked(enum  samba_filestat_type status);
int kav_connected();

extern samba_conn 		  daemon_connect;
extern connection_struct	* smbd_connect;



#endif

