CREATE TABLE IF NOT EXISTS tbl_netstat (
	victim		      text,
	collection_time text,
  proto		        text,
	local_address 	text,
	foreign_address	text,
	foreign_port	  text,
	state		        text,
	pid		          integer
);

CREATE TABLE IF NOT EXISTS tbl_imagepaths (
	victim		      text,
	collection_time text,
	pid		          integer,
	hostname	      text,
	imagepath	      text
);

CREATE TABLE IF NOT EXISTS tbl_tasklist_verbose (
	victim		      text,
  collection_time text,
	image_name	    text,
	pid		          integer,
	session_name	  text,
	session_num	    integer,
	mem_usage	      text,
	status		      text,
	user_name	      text,
	cpu_time	      text,
	window_title	  text
);

CREATE TABLE IF NOT EXISTS tbl_tasklist_service (
	victim		      text,
  collection_time text,
	image_name	    text,
	pid		          integer,
	services	      text
);

CREATE TABLE IF NOT EXISTS tbl_tasklist_modules (
	victim		      text,
  collection_time text,
	pid		          integer,
	image_name	    text,
	modules		      text
);

-- Create tables for merged data

-- TCP only
CREATE TABLE IF NOT EXISTS tbl_tcp_connections (
	victim		      text,
  collection_time text,
	pid		          integer,
	image_name	    text,
	imagepath	      text,
	user_name	      text,
	window_title	  text,
	local_address	  text,
	local_port	    text,
	foreign_address	text,
	foreign_port	  text,
	state		        text
);

