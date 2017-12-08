from IntelCache import Global_IP_Cache
from IntelRecord import AddressRecord
from collect import ingest, choose_files, scrape_ips_from_file
from sql import create_db, insert_into_table, create_network_process_view, qry_victim_network_processes
from pprint import pprint
from ipaddress import ip_address


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
    return cache


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
        tbl_investigation_rows = []

        for row in list_of_rows:
            try:
                ip_obj = ip_address(row['foreign_address'])
            except ValueError:
                continue # Quick way to work around invalid data that there wouldn't be a cache record for anyway.
            if ip_obj.is_global:
                tbl_investigation_row = {}
                tbl_investigation_row['victim'] = row['victim']
                tbl_investigation_row['investigation_id'] = row['investigation_id']
                tbl_investigation_row['ingest_time'] = row['ingest_time']
                tbl_investigation_row['foreign_address'] = row['foreign_address']
                cache_data = cache.search(ip_obj)
                if cache_data:
                    tbl_investigation_row['foreign_address_asn'] = cache_data.data_dict['asn']
                    first_entity = cache_data.data_dict['entities'][0]
                    tbl_investigation_row['foreign_address_entity'] = cache_data.data_dict['asn_description']
                    tbl_investigation_row['foreign_address_contact_name'] = cache_data.data_dict['objects'][first_entity]['contact']['name']
                    tbl_investigation_row['foreign_address_contact_kind'] = cache_data.data_dict['objects'][first_entity]['contact']['kind']
                    tbl_investigation_row['foreign_address_contact_address'] = cache_data.data_dict['objects'][first_entity]['contact']['address'][0]['value']
                    tbl_investigation_row['foreign_address_country_code'] = cache_data.data_dict['asn_country_code']
                else:
                    tbl_investigation_row['foreign_address_asn'] = 'Unavailable'
                    tbl_investigation_row['foreign_address_entity'] = 'Unavailable'
                    tbl_investigation_row['foreign_address_contact_name'] = 'Unavailable'
                    tbl_investigation_row['foreign_address_contact_kind'] = 'Unavailable'
                    tbl_investigation_row['foreign_address_contact_address'] = 'Unavailable'
                    tbl_investigation_row['foreign_address_country_code'] = 'Unavailable'
                tbl_investigation_rows.append(tbl_investigation_row)
            else:
                continue
        print(f'Number of rows = {len(tbl_investigation_rows)}')
        insert_into_table(test_database, 'tbl_investigation', tbl_investigation_rows)

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
    victims = set()

    create_db(test_database)
    cache = populate_cache(test_directory)
    raw_evidence = ingest(test_directory, test_investigation_id)

    for key in raw_evidence:
        victim, victim_file = key.name.split('__')
        victims.add(victim)
        insert_evidence_data(victim_file, raw_evidence[key])

    create_network_process_view(test_database)

    # todo: List all network processes starting with connected ones, and their associated ARIN (or other) registry data
    # todo: Write a parser for startup data to be used for analysis and to compare against baseline image
    # todo: Capture baseline data from fresh image (Zach / Alex)
