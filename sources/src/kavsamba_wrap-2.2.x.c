/*  
 * $Id: kavsamba_wrap-2.2.x.c,v 1.10 2004/05/12 09:17:20 isv Exp $
 *
 * This source file is a part of a Kaspersky Antivirus For Samba Servers.
 * Copyright (C) Kaspersky Lab, 1997-2004
 * See License.txt for details
 *
 */


#include <includes.h>
#include "kavsamba_helpers.h"
#include "kavsamba_common.h"


extern struct   vfs_ops default_vfs_ops;
static int	kav_smb_connect(struct connection_struct *conn, const char *svc, const char *user);
static void 	kav_smb_disconnect(struct connection_struct *conn);
static int	kav_smb_open(struct connection_struct *conn,const char *fname, int flags, mode_t mode);
static int	kav_smb_close(struct files_struct *fsp, int fd);
static int 	kav_smb_unlink(struct connection_struct *conn, const char *path);
static int	kav_smb_rename(struct connection_struct *conn, const char *old, const char *new);
static ssize_t	kav_smb_write(struct files_struct *fsp, int fd, const void *data, size_t n);
static DIR  *   kav_smb_opendir(struct connection_struct *conn, const char *fname);
static int	kav_smb_stat(struct connection_struct *conn, const char *fname, SMB_STRUCT_STAT *sbuf);
static int	kav_smb_fstat(struct files_struct *fsp, int fd, SMB_STRUCT_STAT *sbuf);
static int	kav_smb_lstat(struct connection_struct *conn, const char *path, SMB_STRUCT_STAT *sbuf);

struct 				  vfs_ops kav_smb_ops;

static samba_callbacks  remote_callbacks = {
		smb_connect:		NULL,
		smb_file_check:		NULL,
		smb_file_checked:	samba_file_checked
};

#if SMB_VFS_INTERFACE_VERSION>=3
struct vfs_ops *vfs_init(int *vfs_version, struct vfs_ops *def_vfs_ops)
{
	
    *vfs_version = SMB_VFS_INTERFACE_VERSION;
    memcpy(&kav_smb_ops,def_vfs_ops,sizeof(kav_smb_ops));
    kav_smb_ops.connect=kav_smb_connect;
    kav_smb_ops.disconnect=kav_smb_disconnect;
    kav_smb_ops.open=kav_smb_open;
    kav_smb_ops.close=kav_smb_close;
    kav_smb_ops.unlink=kav_smb_unlink;
    kav_smb_ops.rename=kav_smb_rename;
    kav_smb_ops.write=kav_smb_write;
    kav_smb_ops.opendir=kav_smb_opendir;
    kav_smb_ops.stat=kav_smb_stat;
    kav_smb_ops.fstat=kav_smb_fstat;
    kav_smb_ops.lstat=kav_smb_lstat;

    smbd_connect = NULL;

    return &kav_smb_ops;
}
#endif


int  kav_smb_connect(struct connection_struct *conn, const char *svc, const char *user)
{
	smbd_connect = conn;
	free_daemon(&daemon_connect);
			
	Samba_callbacks_init(&remote_callbacks);

	if (!kav_connect()) {
		errno = EACCES;
		return -1;
	}

	return default_vfs_ops.connect(conn, svc, user);
}

void kav_smb_disconnect(struct connection_struct *conn)
{
	kav_disconnect();
	
	default_vfs_ops.disconnect(conn);
	smbd_connect = NULL;
}

int kav_smb_open(struct connection_struct *conn, const char *fname, int flags, mode_t mode)
{
	enum  samba_filestat_type	  file_result;
	char 				* result_path;
	int			 	  len;
	struct stat	 		  stat_buf;

	smbd_connect = conn;

	len = strlen(fname)+strlen(smbd_connect->connectpath)+2;
	result_path = malloc(len+1);
	
	snprintf(result_path,len,"%s/%s",smbd_connect->connectpath,fname);

	if (daemon_connect.filename && time(NULL) - daemon_connect.last_open < 2 ){
		if (!strcmp(daemon_connect.filename,result_path) && 
				daemon_connect.file_result == SAMBA_ACCESS_DENY) {
			errno = EACCES;
			return -1;
		}
		
	}

	daemon_connect.written		= 0;
	daemon_connect.flags		= flags;
	if (daemon_connect.filename) {
		free (daemon_connect.filename);
	}
	
	daemon_connect.filename		= result_path;
		
	if (lstat(result_path,&stat_buf) || !stat_buf.st_size) {
		if (!kav_connected()&& !kav_connect()) {
			errno = EACCES;
			return -1;
		}
		
		goto Done;		
	}
	
	file_result = kav_check_file(result_path,SAMBA_FILE_OPEN,flags);
	
	daemon_connect.file_result = file_result;
	daemon_connect.last_open = time(NULL);

	if (file_result !=  SAMBA_ACCESS_ACCEPT) {
		errno = EACCES;
		return -1;
	}
	
Done:	
	return default_vfs_ops.open(conn, fname, flags, mode);
}

int kav_smb_close(struct files_struct *fsp, int fd)
{
	int				res;
	struct stat	 		stat_buf;
	enum  samba_filestat_type	file_result;
	
	res = default_vfs_ops.close(fsp, fd);

	if (!daemon_connect.filename) return res;

	if (!smbd_connect || !daemon_connect.written) {
		goto Done;

	}

	if (lstat(daemon_connect.filename,&stat_buf) || !stat_buf.st_size) {
		return res;
	}

	file_result = kav_check_file(daemon_connect.filename,SAMBA_FILE_CLOSE,
					daemon_connect.flags);

	if (file_result !=  SAMBA_ACCESS_ACCEPT) {
		errno = EACCES;
		return -1;
	}

Done:
	free(daemon_connect.filename);
	daemon_connect.filename = NULL;

	return res;
}

int kav_smb_unlink(struct connection_struct *conn, const char *path)
{
	int			  len;
	char			* result_path;
	struct stat		  stat_buf;

	smbd_connect = conn;

	if (daemon_connect.filename) {
		free(daemon_connect.filename);
		daemon_connect.filename = NULL;
	}

	len = strlen(path)+strlen(smbd_connect->connectpath)+2;
	result_path = malloc(len+1);
	
	snprintf(result_path,len,"%s/%s",smbd_connect->connectpath,path);

	if (lstat(result_path,&stat_buf)) {
		goto Done;
	}

	
	if (kav_unlink_file(result_path) != SAMBA_ACCESS_ACCEPT) {
		free(result_path);
		errno = EACCES;
		return -1;
	
	}
Done:	
	free(result_path);
	return default_vfs_ops.unlink(conn,path);
}

int kav_smb_rename(struct connection_struct *conn, const char *old, const char *new)
{
	int			  len;
	char			* result_path;
	struct stat		  stat_buf;

	smbd_connect = conn;

	if (daemon_connect.filename) {
		free(daemon_connect.filename);
		daemon_connect.filename = NULL;
	}

	len = strlen(old)+strlen(smbd_connect->connectpath)+2;
	result_path = malloc(len+1);
	
	snprintf(result_path,len,"%s/%s",smbd_connect->connectpath,old);

	if (lstat(result_path,&stat_buf)) {
		goto Done;
	}
	
	if (kav_unlink_file(result_path) != SAMBA_ACCESS_ACCEPT) {
		free(result_path);
		errno = EACCES;
		return -1;
	
	}

Done:
	free(result_path);
	return default_vfs_ops.rename(conn,old,new);
}


ssize_t	kav_smb_write(struct files_struct *fsp, int fd, const void *data, size_t n)
{
	daemon_connect.written = 1;

	return default_vfs_ops.write(fsp,fd,data,n);
}


DIR * kav_smb_opendir(struct connection_struct *conn, const char *fname)
{
	smbd_connect = conn;
	
	if (!kav_connected()&& !kav_connect()) {
		errno = EACCES;
		return NULL;
	}

	
	return  default_vfs_ops.opendir(conn,fname);
}

int kav_smb_stat(struct connection_struct *conn, const char *fname, SMB_STRUCT_STAT *sbuf)
{
	smbd_connect = conn;
	
	if (!kav_connected()&& !kav_connect()) {
		errno = EACCES;
		return -1;
	}

	return  default_vfs_ops.stat(conn,fname,sbuf);
}

int kav_smb_fstat(struct files_struct *fsp, int fd, SMB_STRUCT_STAT *sbuf)
{
	if (!smbd_connect) goto Done;
	
	if (!kav_connected()&& !kav_connect()) {
		errno = EACCES;
		return -1;
	}

Done:
	return  default_vfs_ops.fstat(fsp,fd,sbuf);
}

int kav_smb_lstat(struct connection_struct *conn, const char *path, SMB_STRUCT_STAT *sbuf)
{
	smbd_connect = conn;

	if (!kav_connected()&& !kav_connect()) {
		errno = EACCES;
		return -1;
	}

	return  default_vfs_ops.lstat(conn,path,sbuf);
}




