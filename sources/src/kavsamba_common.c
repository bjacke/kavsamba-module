/*  
 * $Id: kavsamba_common.c,v 1.9 2004/07/20 11:56:35 automake Exp $
 *
 * This source file is a part of a Kaspersky Antivirus For Samba Servers.
 * Copyright (C) Kaspersky Lab, 1997-2004
 * See License.txt for details
 *
 */

#include "includes.h"
#include "kavsamba_helpers.h"
#include "kavsamba_common.h"


static int      kav_read_data(int sock, char * buff, int size);

samba_conn			  daemon_connect = {filename: NULL};
struct connection_struct 	* smbd_connect;


#if defined SMB_VFS_INTERFACE_VERSION && SMB_VFS_INTERFACE_VERSION < 9
extern fstring remote_machine;

static const char * get_remote_machine_name(void)
{


	return remote_machine;
}
#endif


enum  samba_filestat_type kav_check_file(const char * filename, enum samba_fileop_type file_op, 
					int flags)
{
	samba_checked_file_data	file_data;
	int			reconnect;

	reconnect = 0;
	
	if (!smbd_connect) return SAMBA_ACCESS_DENY;

again:
	if (daemon_connect.sock == -1) {
		if (!kav_connect()) return SAMBA_ACCESS_DENY;
	    }
	

	daemon_connect.check_result = SAMBA_ACCESS_DENY;

	while (1) {
		if (!Samba_check_file(daemon_connect.sock,smbd_connect->uid,
				getpid(),filename,file_op,flags)) {
			kav_disconnect();
			reconnect++;
			if (reconnect<2) goto again;
			DEBUG(0,("Error checking %s\n",filename));
			syslog(LOG_CRIT,"Error checking %s",filename);
			return SAMBA_ACCESS_DENY;
		}
		
		if (!kav_read_data(daemon_connect.sock,(char *) &file_data,sizeof(file_data))){
			kav_disconnect();
			reconnect++;
			if (reconnect<2) goto again;
			DEBUG(0,("Error checking %s\n",filename));
			syslog(LOG_CRIT,"Error checking %s",filename);
			return SAMBA_ACCESS_DENY;
			
		} else break;
	}

	Samba_request_ready(daemon_connect.sock,daemon_connect.sock,&file_data);	

	return daemon_connect.check_result;
}



enum samba_filestat_type kav_unlink_file(const char * filename)
{
	int			reconnect;

	if (!smbd_connect) return SAMBA_ACCESS_DENY;
	
	reconnect = 0;

again:
	if (daemon_connect.sock == -1) {
		if (!kav_connect()) return SAMBA_ACCESS_DENY;
	    }

	while(1) {
		if (!Samba_check_file(daemon_connect.sock,smbd_connect->uid,
				getpid(),filename,SAMBA_FILE_UNLINK,0)){
			kav_disconnect();
			reconnect++;
			if (reconnect<2) goto again;
			
			DEBUG(0,("Read/write error on unlink operation, filename=%s\n",filename));
			syslog(LOG_CRIT,"Read/write error on unlink operation, filename=%s",filename);
			return SAMBA_ACCESS_DENY;

		} else break;
	}
	
	
    return SAMBA_ACCESS_ACCEPT;	
}

int kav_connect(void)
{
	struct  sockaddr_un     smb_addr;
	int			err;

	if (!smbd_connect) return 0;

	daemon_connect.sock = socket(AF_UNIX,SOCK_STREAM,0);
	memset((char *)&smb_addr, 0, sizeof(smb_addr));

	smb_addr.sun_family=AF_UNIX;
	strncpy(smb_addr.sun_path,smb_default_sock,sizeof(smb_addr.sun_path));
	err = connect(daemon_connect.sock,(struct sockaddr *)&smb_addr,sizeof(smb_addr));

	if (err){
		DEBUG(0,("Can't connect to the kavsamba daemon(err=%s)\n",strerror(errno)));
		syslog(LOG_CRIT,"Can't connect to the kavsamba daemon(err=%s)",strerror(errno));
		close(daemon_connect.sock);
		daemon_connect.sock = -1;
		return 0;
	}

	Samba_connect(daemon_connect.sock,smbd_connect->user,
			      smbd_connect->client_address,get_remote_machine_name());

	return 1;
}


int kav_disconnect(void)
{
	close(daemon_connect.sock);
	free_daemon(&daemon_connect);

	return 1;
}


void free_daemon( samba_conn * conn)
{
	conn->sock = -1;
	conn->check_result = SAMBA_ACCESS_DENY;
	conn->file_result = SAMBA_ACCESS_DENY;
	conn->flags = 0;
	conn->written = 0;
	conn->last_open = 0;
}


int kav_connected()
{
	if (daemon_connect.sock == -1) return 0;

	return 1;
}


int kav_read_data(int sock, char * buff, int size)
{
	int      count;
	fd_set   rmask;
	int      i,n;
	int	 bytes;

	for (count=0,bytes=size;count<size;) {
		FD_ZERO(&rmask);
		FD_SET(sock, &rmask);
		i = select(sock+1, &rmask, (fd_set *)NULL, (fd_set *)NULL, NULL);
		if (i < 0 || i==0) {
			DEBUG(0,("Data reading error from kavsamba daemon(err=%s)\n",strerror(errno)));
			syslog(LOG_WARNING,"Data reading error from kavsamba daemon(err=%s)",strerror(errno));
			return 0;
		}
		
		n = recv(sock, buff+count, bytes,0);
		if (n <= 0) {
			DEBUG(0,("Data reading error from kavsamba daemon(err=%s)\n",strerror(errno)));
			syslog(LOG_WARNING,"Data reading error from kavsamba daemon(err=%s)",strerror(errno));
			return 0;
		}
		count+=n;
		if (bytes > size-count) bytes=size-count;
	}

	return 1;
   }

void samba_file_checked(enum  samba_filestat_type status)
{
	daemon_connect.check_result = status;	
}



