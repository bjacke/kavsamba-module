/*  
 * $Id: kavsamba_wrap-3.x.c,v 1.11 2005/09/19 13:00:20 automake Exp $
 *
 * This source file is a part of a Kaspersky Antivirus For Samba Servers.
 * Copyright (C) Kaspersky Lab, 1997-2004
 * See License.txt for details
 *
 */


#include <includes.h>
#include "kavsamba_helpers.h"
#include "kavsamba_common.h"


static int kav_smb_connect(vfs_handle_struct *handle, connection_struct *conn, const char *service, const char *user);
static void kav_smb_disconnect(vfs_handle_struct *handle, connection_struct *conn);
static int kav_smb_open(vfs_handle_struct *handle, connection_struct *conn, const char *fname, int flags, mode_t mode);
static int kav_smb_close(vfs_handle_struct *handle, files_struct *fsp, int fd);
static ssize_t kav_smb_write(vfs_handle_struct *handle, files_struct *fsp, int fd, const void *data, size_t n);
#if defined SMB_VFS_INTERFACE_VERSION && SMB_VFS_INTERFACE_VERSION >=10
static ssize_t kav_smb_pwrite(vfs_handle_struct *handle, files_struct *fsp, int fd, const void *data, size_t n, SMB_OFF_T offset);
#endif

static int kav_smb_rename(vfs_handle_struct *handle, connection_struct *conn, const char *old, const char *new_);
static int kav_smb_unlink(vfs_handle_struct *handle, connection_struct *conn, const char *path);
static int kav_smb_stat(struct vfs_handle_struct *handle, struct connection_struct *conn, const char *fname, SMB_STRUCT_STAT *sbuf);
static int kav_smb_fstat(struct vfs_handle_struct *handle, struct files_struct *fsp, int fd, SMB_STRUCT_STAT *sbuf);
static int kav_smb_lstat(struct vfs_handle_struct *handle, struct connection_struct *conn, const char *path, SMB_STRUCT_STAT *sbuf);
#if SMB_VFS_INTERFACE_VERSION >=12
static DIR * kav_smb_opendir(struct vfs_handle_struct *handle, struct connection_struct *conn, const char *fname,
				const char *mask, uint32 attributes);
#else
static DIR * kav_smb_opendir(struct vfs_handle_struct *handle, struct connection_struct *conn, const char *fname);
#endif



static vfs_op_tuple kav_smb_ops[] = {
	{SMB_VFS_OP(kav_smb_connect),			SMB_VFS_OP_CONNECT, 		SMB_VFS_LAYER_TRANSPARENT},
	{SMB_VFS_OP(kav_smb_disconnect),		SMB_VFS_OP_DISCONNECT,		SMB_VFS_LAYER_TRANSPARENT},
	{SMB_VFS_OP(kav_smb_open),			SMB_VFS_OP_OPEN,		SMB_VFS_LAYER_TRANSPARENT},
	{SMB_VFS_OP(kav_smb_close),			SMB_VFS_OP_CLOSE,		SMB_VFS_LAYER_TRANSPARENT},
	{SMB_VFS_OP(kav_smb_write),			SMB_VFS_OP_WRITE,		SMB_VFS_LAYER_TRANSPARENT},
#if defined SMB_VFS_INTERFACE_VERSION && SMB_VFS_INTERFACE_VERSION >=10
	{SMB_VFS_OP(kav_smb_pwrite),			SMB_VFS_OP_PWRITE,		SMB_VFS_LAYER_TRANSPARENT},
#endif	
	{SMB_VFS_OP(kav_smb_rename),			SMB_VFS_OP_RENAME,		SMB_VFS_LAYER_TRANSPARENT},
	{SMB_VFS_OP(kav_smb_unlink),			SMB_VFS_OP_UNLINK,		SMB_VFS_LAYER_TRANSPARENT},
	{SMB_VFS_OP(kav_smb_stat),			SMB_VFS_OP_STAT,		SMB_VFS_LAYER_TRANSPARENT},
	{SMB_VFS_OP(kav_smb_fstat),			SMB_VFS_OP_FSTAT,		SMB_VFS_LAYER_TRANSPARENT},
	{SMB_VFS_OP(kav_smb_lstat),			SMB_VFS_OP_LSTAT,		SMB_VFS_LAYER_TRANSPARENT},
	{SMB_VFS_OP(kav_smb_opendir),			SMB_VFS_OP_OPENDIR,		SMB_VFS_LAYER_TRANSPARENT},
	{NULL,						SMB_VFS_OP_NOOP,		SMB_VFS_LAYER_NOOP}
	};


static samba_callbacks  remote_callbacks = {
		smb_connect:		NULL,
		smb_file_check:		NULL,
		smb_file_checked:	samba_file_checked
};

NTSTATUS init_module(void)
{
	return smb_register_vfs(SMB_VFS_INTERFACE_VERSION,KAVSAMBA_3X_MODULE_NAME, kav_smb_ops);
}

int kav_smb_connect(vfs_handle_struct *handle, connection_struct *conn, const char *service, const char *user)    
{
	smbd_connect = conn;
	free_daemon(&daemon_connect);
			
	Samba_callbacks_init(&remote_callbacks);

	if (!kav_connect()) {
		errno = EACCES;
		return -1;
	}

	return 0;
}


void kav_smb_disconnect(vfs_handle_struct *handle, connection_struct *conn)
{
	kav_disconnect();

	smbd_connect = NULL;
	return;
}

int kav_smb_open(vfs_handle_struct *handle, connection_struct *conn, const char *fname, int flags, mode_t mode)
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
	
	daemon_connect.written          = 0;
	daemon_connect.flags            = flags;

	if (daemon_connect.filename) {
	        free (daemon_connect.filename);
	    }
						
	daemon_connect.filename = result_path;
		
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
	return vfswrap_open(handle, conn, fname, flags, mode);
}

int kav_smb_close(vfs_handle_struct *handle, files_struct *fsp, int fd)
{
	int				res;
	struct stat	 		stat_buf;
	enum  samba_filestat_type	file_result;
	
	res = vfswrap_close(handle, fsp, fd);

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

ssize_t kav_smb_write(vfs_handle_struct *handle, files_struct *fsp, int fd, const void *data, size_t n)
{
	daemon_connect.written = 1;
	
	return vfswrap_write(handle, fsp, fd, data, n);
}

#if defined SMB_VFS_INTERFACE_VERSION && SMB_VFS_INTERFACE_VERSION >=10
ssize_t kav_smb_pwrite(vfs_handle_struct *handle, files_struct *fsp, int fd, const void *data, size_t n, SMB_OFF_T offset)
{
	daemon_connect.written = 1;
	
	return vfswrap_pwrite(handle, fsp, fd, data, n, offset);
}
#endif

int kav_smb_rename(vfs_handle_struct *handle, connection_struct *conn, const char *old, const char *new_)
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

	return vfswrap_rename(handle, conn, old, new_);
}

static int kav_smb_unlink(vfs_handle_struct *handle, connection_struct *conn, const char *path)
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
	
	return vfswrap_unlink(handle, conn, path);
}


int kav_smb_stat(struct vfs_handle_struct *handle, struct connection_struct *conn, const char *fname, SMB_STRUCT_STAT *sbuf)
{
	smbd_connect = conn;

	if (!kav_connected()&& !kav_connect()) {
		errno = EACCES;
		return -1;
	}

	return vfswrap_stat(handle, conn,fname, sbuf);
}

int kav_smb_fstat(struct vfs_handle_struct *handle, struct files_struct *fsp, int fd, SMB_STRUCT_STAT *sbuf)
{
	if (!smbd_connect) goto Done;

	if (!kav_connected()&& !kav_connect()) {
		errno = EACCES;
		return -1;
	}

Done:
	return vfswrap_fstat(handle, fsp,fd,sbuf);
}

int kav_smb_lstat(struct vfs_handle_struct *handle, struct connection_struct *conn, const char *path, SMB_STRUCT_STAT *sbuf)
{
	smbd_connect = conn;

	if (!kav_connected()&& !kav_connect()) {
		errno = EACCES;
		return -1;
	}

	return vfswrap_lstat(handle, conn,path,sbuf);
}
#if SMB_VFS_INTERFACE_VERSION >=12
DIR * kav_smb_opendir(struct vfs_handle_struct *handle, struct connection_struct *conn, const char *fname,
			const char *mask, uint32 attributes)
#else
DIR * kav_smb_opendir(struct vfs_handle_struct *handle, struct connection_struct *conn, const char *fname)
#endif

{
	smbd_connect = conn;

	if (!kav_connected()&& !kav_connect()) {
		errno = EACCES;
		return NULL;
	}
#if SMB_VFS_INTERFACE_VERSION >=12
	return vfswrap_opendir(handle,conn,fname, mask,attributes);
#else
	return vfswrap_opendir(handle,conn,fname);
#endif
}


