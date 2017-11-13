from pathlib import Path
from ipaddress import ip_address, AddressValueError
from ipwhois.utils import unique_addresses
from IntelCache import Global_IP_Cache
from IntelRecord import AddressRecord


def merge(dict_a, dict_b):
    return {**dict_a, **dict_b}


def choose_files(file_path):
    """Generator function yielding each file from the path specified."""
    p = Path(file_path)
    files = p.glob('**/*.*')   # This is going to grab everything
    for f in files:
        if f.is_dir():
            choose_files(f)  # Handle nested directories if they exist
            continue  # Ignore directories
        yield f


def open_log(source):
    with open(source, 'r') as fh:
        for row in fh:
            yield row


def count_rows(source_file):
    '''Utility function to help decide whether or not it makes sense to parse out the unique lines of a file rather
    than every individual line.'''
    unique_rows = set()
    all_rows = 0
    for line in open_log(source_file):
        all_rows += 1
        unique_rows.add(line)
    return {'total_rows': all_rows, 'unique_rows': len(unique_rows)}


def scrape_ips_from_file(source_file, max_failures_to_return=1000, unique_rows_only=True):
    '''Tries to parse the file line by line and use secynic's method to find ip addresses.
    It returns a dictionary with a set of global ip addresses, a set of other ip addresses,
    unique lines which failed parsing for the file, and also any object that matched an ip
    address returned by unique_addresses, but could not be parsed as an IP address.'''
    results = {'success': {}, 'failed': set()}
    failed_records = 0
    if unique_rows_only:  # If the source file has a lot of duplicate data, set this flag
        unique_rows = set()
        for line in open_log(source_file):
            unique_rows.add(line)
        for unique_line in unique_rows:
            try:
                source_file_results = unique_addresses(data=unique_line)
                results['success'] = merge(results['success'], source_file_results)
            except:
                failed_records += 1
                results['failed'].add(unique_line)  # Adds failed line to set for the file
                if failed_records >= max_failures_to_return:
                    print("Failed line threshold exceeded, skipping the rest of file {}".format(source_file.name))
                    break
                else:
                    continue
    else:
        for line in open_log(source_file):
            try:
                source_file_results = unique_addresses(data=line)
                results['success'] = merge(results['success'], source_file_results)
            except:  # If the line can't be processed simply, then collect it for other handling
                failed_records += 1
                results['failed'].add(line)  # Adds failed line to set for the file
                if failed_records >= max_failures_to_return:
                    print("Failed line threshold exceeded, skipping the rest of file {}".format(source_file.name))
                    break
                else:
                    continue

    # Don't allow the function to return anything that can't be a valid IP address
    global_ip_addresses = set()
    failed_ip_conversions = set()
    other_ip_addresses = set()
    for unvalidated_ip in results['success'].keys():
        try:
            unvalidated_ip_obj = ip_address(unvalidated_ip)
        except AddressValueError:
            failed_ip_conversions.add(unvalidated_ip_obj)
            continue
        if unvalidated_ip_obj.is_global and unvalidated_ip_obj.version == 4:
            global_ip_addresses.add(unvalidated_ip_obj)
        else:
            other_ip_addresses.add(unvalidated_ip_obj)

    return {'global': global_ip_addresses,
            'other': other_ip_addresses,
            'failed': results['failed'],
            'invalid_ip_addrs': failed_ip_conversions}


# Test data follows
# ----------------------------------------------------
from pprint import pprint

unique_ip_addr = set()
cache = Global_IP_Cache()

for f in choose_files(r'C:\MoTemp\v2'):
    collected_ip_info = scrape_ips_from_file(f)
    unique_ip_addr |= collected_ip_info['global']

for ip_obj in unique_ip_addr:
    address_obj = AddressRecord(ip_obj)
    network_returned = address_obj.query(cache)
    if network_returned:
        print(network_returned)
    else:
        cache.add(ip_obj)

cache.save()
#cache.dump()




