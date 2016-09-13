/*  
 * $Id: kavsamba_helpers.c,v 1.7 2004/05/12 09:14:50 isv Exp $
 *
 * This source file is a part of a Kaspersky Antivirus For Samba Servers.
 * Copyright (C) Kaspersky Lab, 1997-2004
 * See License.txt for details
 *
 */

#include <sys/types.h>
#include <sys/time.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <time.h>
#include "kavsamba_helpers.h"

int samba_send_data(int fd, samba_data *packet);
void samba_make_header(samba_header * header,u_short data_size, u_short request);

static samba_callbacks callbacks;

void Samba_callbacks_init(samba_callbacks * s_callbacks)
{
	callbacks.smb_file_check	= s_callbacks->smb_file_check;
	callbacks.smb_file_checked	= s_callbacks->smb_file_checked;
	callbacks.smb_connect		= s_callbacks->smb_connect;
}


int Samba_connect(int fd, const char * user, const char * ip, const char * host)
{
	samba_connect_data * connect_data;
	int res;

	connect_data = (samba_connect_data *) 
		malloc(sizeof(*connect_data)+ strlen(user) +strlen(ip) +strlen(host)+10);

	samba_make_header(&connect_data->header,sizeof(connect_data->config)
			+ strlen(user)+strlen(ip)+strlen(host)+3, SAMBA_CONNECT);

	memcpy(connect_data->config.name,user,strlen(user)+1);
	memcpy(connect_data->config.name+strlen(user)+1,ip,strlen(ip)+1);
	memcpy(connect_data->config.name+strlen(user)+strlen(ip)+2,host,strlen(host)+1);

	res = samba_send_data(fd,(samba_data *) connect_data);
	free(connect_data);

	return res;
}


int Samba_check_file(int fd,uid_t uid, pid_t pid, const char * filename, 
			enum samba_fileop_type file_op, int flags)
{
	samba_check_file_data * file_data;
	int res;

	file_data = (samba_check_file_data *)malloc(sizeof(*file_data) + strlen(filename)+2);
	samba_make_header(&file_data->header,sizeof(file_data->file) + strlen(filename)+1,
			SAMBA_CHECK_FILE);

	file_data->file.uid = uid;
	file_data->file.pid = pid;
	file_data->file.flags = flags;
	file_data->file.file_op = file_op;
	memcpy(file_data->file.name,filename,strlen(filename)+1);
	res = samba_send_data(fd,(samba_data *) file_data);
	free(file_data);

	return res;
}


int Samba_checked_file(int fd,enum samba_filestat_type check_result)
{
	samba_checked_file_data file_data;

	samba_make_header(&file_data.header,sizeof(file_data.file),SAMBA_CHECKED_FILE);
	file_data.file.status = check_result;
	
	return samba_send_data(fd,(samba_data *) &file_data);
}

int samba_send_data(int fd, samba_data *packet)
{
	int		packet_len, num_fd;
	int		i,count,bytes;
	fd_set		write_set;
	struct timeval	tv;

	packet_len = packet->header.data_size + sizeof(packet->header);

	for(count=0,bytes=packet_len;count<packet_len;){

		FD_ZERO(&write_set);
		FD_SET(fd,&write_set);
		
		tv.tv_sec	= 0;
		tv.tv_usec	= 100;

		num_fd = select(fd+1,NULL,&write_set,NULL,&tv);
		if (num_fd<=0) return 0;

		i = write(fd,packet+count,bytes);
		if (i<=0) return 0;
		
		count +=i;
		if (bytes > packet_len-count) bytes=packet_len-count;
	}
	
	return 1;
}

void samba_make_header(samba_header * header,u_short data_size, u_short request)
{
	memset(header,0,sizeof(*header));
	header->request    = request;
	header->version   = SAMBA_INTERFACE_VERSION;
	header->data_size = data_size;
}


int Samba_request_ready(int read_fd, int write_fd, void * data)
{
	samba_data * request;

	request = (samba_data *) data;

	switch (request->header.request) {
		case SAMBA_CHECK_FILE:
		{
			samba_check_file_data * file_data;
			file_data = (samba_check_file_data *) data;

			if (callbacks.smb_file_check) {
				callbacks.smb_file_check( 
							  write_fd,
							  file_data->file.uid,
							  file_data->file.pid,
							  file_data->file.name,
							  file_data->file.file_op,
							  file_data->file.flags);
			}
		}
		break;
		
		case SAMBA_CHECKED_FILE:
		{
			samba_checked_file_data * file_data;

			file_data = (samba_checked_file_data *) data;
						
			if (callbacks.smb_file_checked) {
				switch (file_data->file.status) {
					case SAMBA_ACCESS_ACCEPT:
						callbacks.smb_file_checked(SAMBA_ACCESS_ACCEPT);
						break;
					case SAMBA_ACCESS_DENY:
						callbacks.smb_file_checked(SAMBA_ACCESS_DENY);
						break;
				}
			}
			
		}
		break;
		
		case SAMBA_CONNECT:
		{
			samba_connect_data * connect_data;
			connect_data = (samba_connect_data *) data;

			if (callbacks.smb_connect) {
				char * user;
				char * ip;
				char * host;
				
				user	= connect_data->config.name;
				ip	= user+strlen(user)+1;
				host	= ip + strlen(ip)+1;		
				
				callbacks.smb_connect(write_fd,user,ip,host);
			}

		}
		break;
	}

	return 1;
}
