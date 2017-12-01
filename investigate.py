from IntelCache import Global_IP_Cache
from IntelRecord import AddressRecord
from collect import ingest, choose_files, scrape_ips_from_file
from sql import create_db, insert_into_table
from pprint import pprint


def populate_cache(data_directory):
    unique_ip_addr = set()
    cache = Global_IP_Cache()

    for f in choose_files(data_directory):
        collected_ip_info = scrape_ips_from_file(f)
        unique_ip_addr |= collected_ip_info['global']

    for ip_obj in unique_ip_addr:
        address_obj = AddressRecord(ip_obj)
        network_returned = address_obj.query(cache)
        if network_returned:
            print(f'{ip_obj} is in {network_returned}')
        else:
            cache.add(ip_obj)

    cache.save()


def insert_evidence_data(evidence_file_name, list_of_rows):
    '''Select the proper table based on the filename, then insert the data into that table'''
    if 'tasklist' in evidence_file_name:
        if 'verbose' in evidence_file_name:
            insert_into_table(test_database, 'tbl_tasklist_verbose', list_of_rows)
        elif 'service' in evidence_file_name:
            insert_into_table(test_database, 'tbl_tasklist_service', list_of_rows)
        elif 'modules' in evidence_file_name:
            insert_into_table(test_database, 'tbl_tasklist_modules', list_of_rows)
        else:
            print(f'The correct tasklist table to insert data cannot be found for {evidence_file_name}')
    elif 'netstat' in evidence_file_name:
        insert_into_table(test_database, 'tbl_netstat', list_of_rows)
    elif 'imagepaths' in evidence_file_name:
        insert_into_table(test_database, 'tbl_imagepaths', list_of_rows)
    elif 'netconfig' in evidence_file_name:
        insert_into_table(test_database, 'tbl_net_config', list_of_rows)
    else:
        print(f'Not sure what table to insert data from {evidence_file_name} into.')


if __name__ == '__main__':
    test_directory = r'C:\MoTemp\v2'
    test_investigation_id = 'INC00077777'
    test_database = r'C:\MoTemp\evidence.sqlite'

    create_db(test_database)

    cache = populate_cache(test_directory)

    raw_evidence = ingest(test_directory, test_investigation_id)
    for key in raw_evidence:
        victim, victim_file = key.name.split('__')
        insert_evidence_data(victim_file, raw_evidence[key])
        #print(f'{victim_file} --> {raw_evidence[key]}')

