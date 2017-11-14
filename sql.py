import sqlite3

def create_db(source_file):
    conn = sqlite3.connect(source_file)
    c = conn.cursor()

    c.execute('CREATE TABLE IF NOT EXISTS tbl_netstat (victim text,	collection_time text, proto	text, '
              'local_address text, foreign_address text, foreign_port text,	state text,	pid	integer)')

    c.execute('CREATE TABLE IF NOT EXISTS tbl_imagepaths (victim text, collection_time text, pid integer, '
              'hostname text, imagepath text)')

    c.execute('CREATE TABLE IF NOT EXISTS tbl_tasklist_verbose (victim text, collection_time text, image_name text,'
              'pid integer,	session_name text, session_num integer,	mem_usage text,	status text, user_name text,'
              'cpu_time	text, window_title text)')

    c.execute('CREATE TABLE IF NOT EXISTS tbl_tasklist_service (victim text, collection_time text, image_name text,'
              'pid integer,	services text)')

    c.execute('CREATE TABLE IF NOT EXISTS tbl_tasklist_modules (victim text, collection_time text, pid integer,'
              'image_name text, modules text)')

    c.execute('CREATE TABLE IF NOT EXISTS tbl_tcp_connections (victim text, collection_time text, pid integer,'
              'image_name text,	imagepath text,	user_name text,	window_title text, local_address text, local_port text,'
              'foreign_address text, foreign_port text,	state text)')

    conn.commit()
    conn.close()

def run_independent():
    test_db = 'testdb.sqlite'
    create_db(test_db)



if __name__ == "__main__":
    run_independent()