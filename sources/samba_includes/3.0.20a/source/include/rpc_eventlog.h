/* 
 *  Unix SMB/CIFS implementation.
 *  RPC Pipe client / server routines
 *  Copyright (C) Marcin Krzysztof Porwit    2005.
 *  
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *  
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *  
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */
 
#ifndef _RPC_EVENTLOG_H		/* _RPC_EVENTLOG_H */
#define _RPC_EVENTLOG_H

/* opcodes */

#define EVENTLOG_CLEAREVENTLOG		0x00
#define EVENTLOG_CLOSEEVENTLOG		0x02
#define EVENTLOG_GETNUMRECORDS		0x04
#define EVENTLOG_GETOLDESTENTRY		0x05
#define EVENTLOG_OPENEVENTLOG		0x07
#define EVENTLOG_READEVENTLOG		0x0a

/* Eventlog read flags */

#define EVENTLOG_SEQUENTIAL_READ      0x0001
#define EVENTLOG_SEEK_READ            0x0002
#define EVENTLOG_FORWARDS_READ        0x0004
#define EVENTLOG_BACKWARDS_READ       0x0008

/* Event types */

#define EVENTLOG_SUCCESS              0x0000
#define EVENTLOG_ERROR_TYPE           0x0001
#define EVENTLOG_WARNING_TYPE         0x0002
#define EVENTLOG_INFORMATION_TYPE     0x0004
#define EVENTLOG_AUDIT_SUCCESS        0x0008
#define EVENTLOG_AUDIT_FAILURE        0x0010


typedef struct eventlog_q_open_eventlog
{
	uint32 unknown1;
	uint16 unknown2;
	uint16 unknown3;
	uint16 sourcename_length;
	uint16 sourcename_size;
	uint32 sourcename_ptr;
	UNISTR2 sourcename;
	uint32 servername_ptr;
	UNISTR2 servername;
}
EVENTLOG_Q_OPEN_EVENTLOG;

typedef struct eventlog_r_open_eventlog
{
	POLICY_HND handle;
	WERROR status;
}
EVENTLOG_R_OPEN_EVENTLOG;

typedef struct eventlog_q_close_eventlog
{
	POLICY_HND handle;
}
EVENTLOG_Q_CLOSE_EVENTLOG;

typedef struct eventlog_r_close_eventlog
{
	POLICY_HND handle;
	WERROR status;
} 
EVENTLOG_R_CLOSE_EVENTLOG;

typedef struct eventlog_q_get_num_records
{
	POLICY_HND handle;
} 
EVENTLOG_Q_GET_NUM_RECORDS;

typedef struct eventlog_r_get_num_records
{
	uint32 num_records;
	WERROR status;
}
EVENTLOG_R_GET_NUM_RECORDS;

typedef struct eventlog_q_get_oldest_entry
{
	POLICY_HND handle;
}
EVENTLOG_Q_GET_OLDEST_ENTRY;

typedef struct eventlog_r_get_oldest_entry
{
	uint32 oldest_entry;
	WERROR status;
}
EVENTLOG_R_GET_OLDEST_ENTRY;

typedef struct eventlog_q_read_eventlog
{
	POLICY_HND handle;
	uint32 flags;
	uint32 offset;
	uint32 max_read_size;
}
EVENTLOG_Q_READ_EVENTLOG;

typedef struct eventlog_record
{
	uint32 length;
	uint32 reserved1;
	uint32 record_number;
	uint32 time_generated;
	uint32 time_written;
	uint32 event_id;
	uint16 event_type;
	uint16 num_strings;
	uint16 event_category;
	uint16 reserved2;
	uint32 closing_record_number;
	uint32 string_offset;
	uint32 user_sid_length;
	uint32 user_sid_offset;
	uint32 data_length;
	uint32 data_offset;
} Eventlog_record;

typedef struct eventlog_data_record
{
	uint32 source_name_len;
	wpstring source_name;
	uint32 computer_name_len;
	wpstring computer_name;
	uint32 sid_padding;
	wpstring sid;
	uint32 strings_len;
	wpstring strings;
	uint32 user_data_len;
	pstring user_data;
	uint32 data_padding;
} Eventlog_data_record;

typedef struct eventlog_entry
{
	Eventlog_record record;
	Eventlog_data_record data_record;
	uint8 *data;
	uint8 *end_of_data_padding;
	struct eventlog_entry *next;
} Eventlog_entry;
 
typedef struct eventlog_r_read_eventlog
{
	uint32 num_bytes_in_resp;
	uint32 bytes_in_next_record;
	uint32 num_records;
	Eventlog_entry *entry;
	uint8 *end_of_entries_padding;
	uint32 sent_size;
	uint32 real_size;
	WERROR status;
}
EVENTLOG_R_READ_EVENTLOG;

typedef struct eventlog_q_clear_eventlog
{
	POLICY_HND handle;
	uint32 unknown1;
	uint16 backup_file_length;
	uint16 backup_file_size;
	uint32 backup_file_ptr;
	UNISTR2 backup_file;
}
EVENTLOG_Q_CLEAR_EVENTLOG;

typedef struct eventlog_r_clear_eventlog
{
	WERROR status;
}
EVENTLOG_R_CLEAR_EVENTLOG;

#endif /* _RPC_EVENTLOG_H */
