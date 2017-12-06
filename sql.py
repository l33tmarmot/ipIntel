import sqlite3
from collections import namedtuple

def create_db(source_file):
    conn = sqlite3.connect(source_file)
    c = conn.cursor()

    c.execute('CREATE TABLE IF NOT EXISTS tbl_investigation (victim text, investigation_id text, ingest_time text, '
              'foreign_address text, foreign_address_asn text, foreign_address_entity text, '
              'foreign_address_contact_name text, foreign_address_contact_kind text, '
              'foreign_address_contact_address text, foreign_address_country_code text)')

    c.execute('CREATE TABLE IF NOT EXISTS tbl_netstat (victim text,	investigation_id text, ingest_time text, '
              'victim_time_at_capture text, proto	text, local_address text, local_port text, foreign_address text, '
              'foreign_port text, state text, pid integer)')

    c.execute('CREATE TABLE IF NOT EXISTS tbl_imagepaths (victim text, investigation_id text, ingest_time text, '
              'victim_time_at_capture text, pid integer, executable_path text, creation_date text,'
              'UNIQUE (victim, investigation_id, pid))')

    c.execute('CREATE TABLE IF NOT EXISTS tbl_tasklist_verbose (victim text, investigation_id text, ingest_time text, '
              'victim_time_at_capture text, image_name text,  pid integer,	session_name text, session_num integer,	'
              'mem_usage text,	status text, user_name text, cpu_time	text, window_title text, '
              'UNIQUE (victim, investigation_id, pid))')

    c.execute('CREATE TABLE IF NOT EXISTS tbl_tasklist_service (victim text, investigation_id text, ingest_time text, '
              'victim_time_at_capture text, image_name text, pid integer, services text,'
              'UNIQUE (victim, investigation_id, pid))')

    c.execute('CREATE TABLE IF NOT EXISTS tbl_tasklist_modules (victim text, investigation_id text, ingest_time text, '
              'victim_time_at_capture text, pid integer, image_name text, modules text,'
              'UNIQUE (victim, investigation_id, pid))')

    c.execute('CREATE TABLE IF NOT EXISTS tbl_net_config (victim text, investigation_id text, ingest_time text, '
              'victim_time_at_capture text, caption text, defaultipgateway text, description text, dhcpenabled boolean, '
              'dhcpleaseexpires text, dhcpleaseobtained text, dhcpserver text, dnsdomain text, dnshostname text, '
              'dnsserversearchorder text, ipaddress text, ipsubnet text, macaddress text,'
              'UNIQUE (victim, investigation_id, macaddress))')
    conn.commit()
    conn.close()
    print(f'New SQLite database file created for use --> {source_file}')


def insert_into_table(destination_db, dest_table, rows_to_insert):
    db = sqlite3.connect(destination_db)
    cursor = db.cursor()
    cursor.execute('BEGIN TRANSACTION')
    try:

        if dest_table == 'tbl_netstat':
            tbl_netstat_fields = 'victim, investigation_id, ingest_time, victim_time_at_capture, proto, local_address, ' \
                                 'local_port, foreign_address, foreign_port, state, pid'
            tbl_netstat_tuple = namedtuple('tbl_netstat_tuple', tbl_netstat_fields)
            for row in rows_to_insert:
                insertable_row = tbl_netstat_tuple(**row)
                cursor.execute("INSERT INTO tbl_netstat VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", insertable_row)
        elif dest_table == 'tbl_imagepaths':
            tbl_imagepaths_fields = 'victim, investigation_id, ingest_time, victim_time_at_capture, pid, executable_path, ' \
                                    'creation_date'
            tbl_imagepaths_tuple = namedtuple('tbl_imagepaths_tuple', tbl_imagepaths_fields)
            for row in rows_to_insert:
                insertable_row = tbl_imagepaths_tuple(**row)
                cursor.execute("INSERT INTO tbl_imagepaths VALUES (?, ?, ?, ?, ?, ?, ?)", insertable_row)
        elif dest_table == 'tbl_tasklist_verbose':
            tbl_tasklist_verbose_fields = 'victim, investigation_id, ingest_time, victim_time_at_capture, image_name, pid, ' \
                                          'session_name, session_num, mem_usage, status, user_name, cpu_time, window_title'
            tbl_tasklist_verbose_tuple = namedtuple('tbl_tasklist_verbose_tuple', tbl_tasklist_verbose_fields)
            for row in rows_to_insert:
                insertable_row = tbl_tasklist_verbose_tuple(**row)
                cursor.execute("INSERT INTO tbl_tasklist_verbose VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", insertable_row)
        elif dest_table == 'tbl_tasklist_service':
            tbl_tasklist_service_fields = 'victim, investigation_id, ingest_time, victim_time_at_capture, image_name, pid, ' \
                                          'services'
            tbl_tasklist_service_tuple = namedtuple('tbl_tasklist_service_tuple', tbl_tasklist_service_fields)
            for row in rows_to_insert:
                insertable_row = tbl_tasklist_service_tuple(**row)
                cursor.execute("INSERT INTO tbl_tasklist_service VALUES (?, ?, ?, ?, ?, ?, ?)", insertable_row)
        elif dest_table == 'tbl_tasklist_modules':
            tbl_tasklist_modules_fields = 'victim, investigation_id, ingest_time, victim_time_at_capture, pid, image_name, ' \
                                          'modules'
            tbl_tasklist_modules_tuple = namedtuple('tbl_tasklist_modules_tuple', tbl_tasklist_modules_fields)
            for row in rows_to_insert:
                insertable_row = tbl_tasklist_modules_tuple(**row)
                cursor.execute("INSERT INTO tbl_tasklist_modules VALUES (?, ?, ?, ?, ?, ?, ?)", insertable_row)
        elif dest_table == 'tbl_net_config':
            tbl_net_config_fields = 'victim, investigation_id, ingest_time, victim_time_at_capture, caption, ' \
                                    'defaultipgateway, description, dhcpenabled, dhcpleaseexpires, dhcpleaseobtained, ' \
                                    'dhcpserver, dnsdomain, dnshostname, dnsserversearchorder, ipaddress, ipsubnet, ' \
                                    'macaddress'
            tbl_net_config_tuple = namedtuple('tbl_net_config_tuple', tbl_net_config_fields)
            for row in rows_to_insert:
                insertable_row = tbl_net_config_tuple(**row)
                cursor.execute("INSERT INTO tbl_net_config VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", insertable_row)
        elif dest_table == 'tbl_investigation':
            tbl_investigation_fields = 'victim, investigation_id, ingest_time, foreign_address, foreign_address_asn,' \
                                       'foreign_address_entity, foreign_address_contact_name, ' \
                                       'foreign_address_contact_kind, foreign_address_contact_address,' \
                                       'foreign_address_country_code'
            tbl_investigation_tuple = namedtuple('tbl_investigation_tuple', tbl_investigation_fields)
            for row in rows_to_insert:
                insertable_row = tbl_investigation_tuple(**row)
                cursor.execute("INSERT INTO tbl_investigation VALUES(?,?,?,?,?,?,?,?,?,?)", insertable_row)
        else:
            print(f'{dest_table} was not found in the {destination_db} database. Aborting.')
            return False
        db.commit()
    except KeyboardInterrupt:
        pass # todo: Write a log that indicates there were ignored duplicate entries or constraint violations, it's ignored silently now.


def create_network_process_view(source_db):
    db = sqlite3.connect(source_db)
    cursor = db.cursor()
    cursor.execute('CREATE VIEW IF NOT EXISTS v_outside_net_processes as '
                   'SELECT tbl_netstat.victim, user_name, tbl_netstat.pid, image_name, tbl_imagepaths.executable_path, status, '
                   'tbl_netstat.state, tbl_netstat.foreign_address, tbl_netstat.foreign_port, '
                   'tbl_netstat.local_address, tbl_netstat.local_port '
                   'FROM tbl_tasklist_verbose '
                   'INNER JOIN tbl_imagepaths on tbl_imagepaths.pid = tbl_tasklist_verbose.pid '
                   'INNER JOIN tbl_netstat on tbl_netstat.pid = tbl_tasklist_verbose.pid '
                   'WHERE tbl_netstat.state != "LISTENING" '
                   'and tbl_netstat.state != "N/A" '
                   'and tbl_netstat.foreign_address != "127.0.0.1" '
                   'ORDER BY tbl_netstat.foreign_address ASC, tbl_netstat.state, tbl_netstat.pid ASC;')

    db.commit()


def qry_victim_network_processes(victim_id, source_db):
    db = sqlite3.connect(source_db)
    cursor = db.cursor()
    rows = []
    for row in cursor.execute('SELECT * from v_outside_net_processes WHERE victim = ?', (victim_id,)):
        rows.append(row)
    return rows
