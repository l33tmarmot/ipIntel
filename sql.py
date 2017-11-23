import sqlite3
from collections import namedtuple

def create_db(source_file):
    conn = sqlite3.connect(source_file)
    c = conn.cursor()

    c.execute('CREATE TABLE IF NOT EXISTS tbl_netstat (victim text,	investigation_id text, collection_time text, proto	text, '
              'local_address text, local_port text, foreign_address text, foreign_port text,'
              'state text, pid integer)')

    c.execute('CREATE TABLE IF NOT EXISTS tbl_imagepaths (victim text, investigation_id text, collection_time text, pid integer, '
              'executable_path text)')

    c.execute('CREATE TABLE IF NOT EXISTS tbl_tasklist_verbose (victim text, investigation_id text, collection_time text, image_name text,'
              'pid integer,	session_name text, session_num integer,	mem_usage text,	status text, user_name text,'
              'cpu_time	text, window_title text)')

    c.execute('CREATE TABLE IF NOT EXISTS tbl_tasklist_service (victim text, investigation_id text, collection_time text, image_name text,'
              'pid integer,	services text)')

    c.execute('CREATE TABLE IF NOT EXISTS tbl_tasklist_modules (victim text, investigation_id text, collection_time text, pid integer,'
              'image_name text, modules text)')

    c.execute('CREATE TABLE IF NOT EXISTS tbl_tcp_connections (victim text, investigation_id text, collection_time text, pid integer,'
              'image_name text,	imagepath text,	user_name text,	window_title text, local_address text, local_port text,'
              'foreign_address text, foreign_port text,	state text)')

    conn.commit()
    conn.close()
    print(f'New SQLite database file created for use --> {source_file}')


def insert_into_table(destination_db, dest_table, rows_to_insert):
    db = sqlite3.connect(destination_db)
    cursor = db.cursor()
    if dest_table == 'tbl_netstat':
        tbl_netstat_fields = 'victim, investigation_id, collection_time, proto, local_address, local_port, foreign_address, foreign_port, ' \
                             'state, pid'
        tbl_netstat_tuple = namedtuple('tbl_netstat_tuple', tbl_netstat_fields)
        for row in rows_to_insert:
            insertable_row = tbl_netstat_tuple(**row)
            cursor.execute("INSERT INTO tbl_netstat VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", insertable_row)
    elif dest_table == 'tbl_imagepaths':
        tbl_imagepaths_fields = 'victim, investigation_id, collection_time, pid, executable_path'
        tbl_imagepaths_tuple = namedtuple('tbl_imagepaths_tuple', tbl_imagepaths_fields)
        for row in rows_to_insert:
            insertable_row = tbl_imagepaths_tuple(**row)
            cursor.execute("INSERT INTO tbl_imagepaths VALUES (?, ?, ?, ?, ?)", insertable_row)
    elif dest_table == 'tbl_tasklist_verbose':
        tbl_tasklist_verbose_fields = 'victim, investigation_id, collection_time, image_name, pid, session_name, session_num, mem_usage,' \
                                      'status, user_name, cpu_time, window_title'
        tbl_tasklist_verbose_tuple = namedtuple('tbl_tasklist_verbose_tuple', tbl_tasklist_verbose_fields)
        for row in rows_to_insert:
            insertable_row = tbl_tasklist_verbose_tuple(**row)
            cursor.execute("INSERT INTO tbl_tasklist_verbose VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", insertable_row)
    elif dest_table == 'tbl_tasklist_service':
        tbl_tasklist_service_fields = 'victim, investigation_id, collection_time, image_name, pid, services'
        tbl_tasklist_service_tuple = namedtuple('tbl_tasklist_service_tuple', tbl_tasklist_service_fields)
        for row in rows_to_insert:
            insertable_row = tbl_tasklist_service_tuple(**row)
            cursor.execute("INSERT INTO tbl_tasklist_service VALUES (?, ?, ?, ?, ?, ?)", insertable_row)
    elif dest_table == 'tbl_tasklist_modules':
        tbl_tasklist_modules_fields = 'victim, investigation_id, collection_time, pid, image_name, modules'
        tbl_tasklist_modules_tuple = namedtuple('tbl_tasklist_modules_tuple', tbl_tasklist_modules_fields)
        for row in rows_to_insert:
            insertable_row = tbl_tasklist_modules_tuple(**row)
            cursor.execute("INSERT INTO tbl_tasklist_modules VALUES (?, ?, ?, ?, ?, ?)", insertable_row)
            # todo: Handle the list of module names properly as they come in list form
    elif dest_table == 'tbl_tcp_connections':
        tbl_tcp_connections_fields = 'victim, investigation_id, collection_time, pid, image_name, imagepath, user_name, window_title,' \
                                     'local_address, local_port, foreign_address, foreign_port, state'
        tbl_tcp_connections_tuple = namedtuple('tbl_tcp_connections_tuple', tbl_tcp_connections_fields)
    else:
        print(f'{dest_table} was not found in the {destination_db} database. Aborting.')
        return False
    db.commit()






def run_independent():
    test_db = 'testdb.sqlite'
    create_db(test_db)



if __name__ == "__main__":
    run_independent()