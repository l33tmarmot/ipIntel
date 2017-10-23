from pathlib import Path
from os import stat
from ipaddress import ip_address, ip_network, IPv4Network, IPv4Address, AddressValueError
from csv import DictReader
from ipwhois import IPWhois
from collections import defaultdict
from io import BytesIO, TextIOWrapper
import mmap
import pickle


# ----------- FUNCTIONS-----------


def choose_files(file_path):
    """Generator function yielding each file from the path specified."""
    p = Path(file_path)
    files = p.glob('**/*.*')   # This is going to grab everything
    for f in files:
        if f.is_dir():
            continue  # Ignore directories
        yield f

# ----------- CLASS DEFINITIONS -----------


class NetRecord:
    def __init__(self, network, country, name, events):
        self.cidr = IPv4Network(network)
        self.net = network
        self.country_code = country
        self.name = name
        self.events = events
        self.asn_dict = {}

    def add_asn(self, asn_net, asn_dict):
        if asn_net not in self.asn_dict.keys():
            self.asn_dict[asn_net] = asn_dict

    def find_asn_data(self, ip_query):
        ip = ip_address(ip_query)
        for net in self.asn_dict.keys():
            asn_network = IPv4Network(net)
            if ip in asn_network:
                return self.asn_dict[net]
        return False

    def print(self):
        print("Parent Network {0}:  Name={1}, Country Code={2}".format(self.net, self.name, self.country_code))
        if self.asn_dict:
            for asn_net in sorted(self.asn_dict.keys()):
                print(" Network==>{0}".format(asn_net))
                for k, v in sorted(self.asn_dict[asn_net].items()):
                    print("\t----> {0}==>{1}".format(k, v))


class IP_Cache:
    def __init__(self):
        self.cache_data = defaultdict()
        self.output_data = defaultdict()
        self.lookup_count = 0
        self.cache_hits = 0
        self.ip_addresses_to_add = None
        self.ip_objs = None
        self.cached_networks = set()
        self.info_dict = None
        self.new_nets = None
        self.new_net_country = None
        self.new_net_name = None
        self.new_net_events = None
        self.new_net_asn = None
        self.new_net_obj = None
        self.new_asn_dict = None
        self.test_for_cidr = None
        self.ip_addresses_with_lookup_errors = set()

    @classmethod
    def return_ip_type(cls, ip_obj):
        try:
            if ip_obj.is_global:
                return 'Global'
            if ip_obj.is_private:
                return 'RFC1918 Private'
            if ip_obj.is_loopback:
                return 'RFC3330 Loopback'
            if ip_obj.is_multicast:
                return 'RFC3171 Multicast'
            if ip_obj.is_link_local:
                return 'RFC3927 Link Local'
            if ip_obj.is_reserved:
                return 'IETF Reserved'
            if ip_obj.is_unspecified:
                return 'RFC5735 Unspecified'
            else:
                return 'ERROR'
        except:
            return 'EXCEPTION_CAUGHT'

    @classmethod
    def return_ip_object(cls, ip_string):
        try:
            ip = IPv4Address(ip_string)
        except AddressValueError:
            return "'{0}' is not an IP address.".format(ip_string)
        return ip

    @classmethod
    def lookup_single_ip(cls, ip_str):
        ip_record = IPWhois(ip_str, allow_permutations=False)
        results = ip_record.lookup_rdap(depth=0)
        return results

    def add_to_cache(self, ip_list):
        self.cache_hits = 0
        self.lookup_count = 0
        self.cached_networks = {IPv4Network(major_net.strip()) for major_net in self.cache_data.keys()}
        if self.cached_networks:
            self.ip_objs = {IPv4Address(ip_add) for ip_add in ip_list}
            self.ip_addresses_to_add = set()
            for ip in self.ip_objs:
                for cached_net in self.cached_networks:
                    if ip in cached_net:
                        self.cache_hits += 1
                        break
                else:
                    self.ip_addresses_to_add.add(str(ip))
        else:
            self.ip_addresses_to_add = ip_list

        for address in self.ip_addresses_to_add:
            try:
                self.lookup_count += 1
                self.info_dict = self.lookup_single_ip(address)
            except:
                print("Unhandled lookup error occurred on {0}, adding to error list.".format(address))
                self.ip_addresses_with_lookup_errors.add(address)
                continue

            self.new_nets = self.info_dict['network']['cidr'].split(',')
            self.new_net_country = self.info_dict['network']['country']
            self.new_net_name = self.info_dict['network']['name']
            self.new_net_events = self.info_dict['network']['events']
            self.new_net_asn = self.info_dict['asn_cidr']
            for new_net in self.new_nets:
                self.new_net_obj = NetRecord(new_net.strip(),
                                             self.new_net_country,
                                             self.new_net_name,
                                             self.new_net_events)
                self.new_asn_dict = {'asn': self.info_dict['asn'],
                                     'asn_country_code': self.info_dict['asn_country_code'],
                                     'asn_date': self.info_dict['asn_date'],
                                     'asn_description': self.info_dict['asn_description'],
                                     'asn_registry': self.info_dict['asn_registry']}
                try:
                    self.test_for_cidr = ip_network(self.new_net_asn)  # Sometimes ARIN returns 'NA'
                    self.new_net_obj.add_asn(self.new_net_asn, self.new_asn_dict)
                except ValueError:
                    print("Record {0} did not return a valid asn_cidr value, "
                          "thus that value ({1}) will not be included.".format(new_net.strip(), self.new_net_asn))
                    pass
                self.cache_data[new_net] = self.new_net_obj
                pass

    def print_cache(self):
        for network in self.cache_data.keys():
            self.cache_data[network].print() # Each value should be a NetRecord object


class IntelLog:
    log_types = ('timestamped', 'non_timestamped')
    valid_states = ('unparsed', 'parsed', 'error')

    def __init__(self, log_type):
        assert log_type in self.log_types
        self.state = 'unparsed'
        assert self.state in self.valid_states
        self.record_count = 0
        self.columns = []
        self.reader_obj = None
        self.fh = None
        self.file_name = ''
        self.encoding = ''
        self.delimiter = ''
        self.lines_to_skip = 0
        self.skip_initial_space = False
        self.log_file_buffer = []  # Used when loading a log completely into memory first for performance
        self.mm = None
        self.b_obj = None
        self.t_obj = None

    def get_state(self):
        return self.state

    def set_state(self, state):
        assert state in self.valid_states
        self.state = state

    def open_log(self, file_name, file_encoding, file_delimiter, file_columns, skip_lines=0, skip_space=False):
        self.lines_to_skip = int(skip_lines)
        self.skip_initial_space = skip_space
        self.columns = file_columns
        self.file_name = str(file_name)
        self.encoding = file_encoding
        self.delimiter = file_delimiter
        with open(self.file_name, 'r', encoding=self.encoding) as self.fh:
            for i in range(self.lines_to_skip):
                self.fh.readline()  # This is used to skip over any header garbage by moving the file pointer ahead
            self.reader_obj = DictReader(self.fh,
                                         delimiter=self.delimiter,
                                         fieldnames=self.columns,
                                         skipinitialspace=self.skip_initial_space)
            for self.row in self.reader_obj:
                yield self.row

    def open_log_in_mem(self, file_name, file_encoding, file_delimiter, file_columns, skip_lines=0, skip_space=False):
        self.lines_to_skip = int(skip_lines)
        self.skip_initial_space = skip_space
        self.columns = file_columns
        self.file_name = str(file_name)
        self.encoding = file_encoding
        self.delimiter = file_delimiter
        with open(self.file_name, 'r+', encoding=self.encoding) as self.fh:
            print("Reading {0} into memory...".format(self.file_name))
            self.mm = mmap.mmap(self.fh.fileno(), 0)
            self.b_obj = BytesIO(self.mm)
            self.t_obj = TextIOWrapper(self.b_obj)

        for i in range(self.lines_to_skip):
            self.t_obj.readline()  # This is used to skip over any header garbage by moving the file pointer ahead
        self.reader_obj = DictReader(self.t_obj,
                                     delimiter=self.delimiter,
                                     fieldnames=self.columns,
                                     skipinitialspace=self.skip_initial_space)
        for self.row in self.reader_obj:
            self.log_file_buffer.append(self.row)  # Puts every row in the file into the list in memory


class IISLog(IntelLog):

    iis_fields = ('date', 'time', 's-ip', 'cs-method', 'cs-uri-stem', 'cs-uri-query', 's-port', 'cs-username', 'c-ip',
                  'cs-user-agent', 'sc-status-code', 'sc-sub-status', 'sc-win32-status', 'time-taken')

    status_codes = {'100': 'Continue', '101': 'Switching Protocols',
                    '200': 'OK', '201': 'Created', '202': 'Accepted', '203': 'Nonauthoritative information',
                    '204': 'No Content', '205': 'Reset content', '206': 'Partial Content',
                    '301': 'Moved permanently', '302': 'Object moved', '304': 'Not Modified', '307': 'Temp Redirect',
                    '400': 'Bad Request', '401': 'Access Denied', '403': 'Forbidden', '404': 'Not Found',
                    '405': 'Method not allowed',
                    '406': 'Client browser does not accept the MIME type of the requested page',
                    '408': 'Request timed out', '412': 'Precondition failed',
                    '500': 'Internal Server Error',
                    '501': 'Header values specify a configuration that is not implemented',
                    '503': 'Service Unavailable'}
    substatus_403 = {'1': 'Execute Access Forbidden',
                     '2': 'Read Access Forbidden',
                     '3': 'Write Access Forbidden',
                     '4': 'SSL Required',
                     '5': 'SSL 128 Required',
                     '6': 'IP Address rejected',
                     '7': 'Client certificate required',
                     '8': 'Site access denied',
                     '9': 'Too many users',
                     '10': 'Invalid configuration',
                     '11': 'Password change',
                     '12': 'Mapper denied access',
                     '13': 'Client certificate revoked',
                     '14': 'Directory listing denied',
                     '15': 'Client Access Licenses exceeded',
                     '16': 'Client certificate is untrusted or invalid',
                     '17': 'Client certificate has expired or is not yet valid',
                     '18': 'Cannot execute requested URL in the current application pool.',
                     '19': 'Cannot execute CGIs for the client in this application pool.',
                     '20': 'Passport logon failed'}
    substatus_404 = {'1': 'Site Not Found',
                     '2': 'ISAPI or CGI restriction',
                     '3': 'MIME type restriction',
                     '4': 'No handler configured',
                     '5': 'Denied by request filtering configuration',
                     '6': 'Verb denied',
                     '7': 'File extension denied',
                     '8': 'Hidden namespace',
                     '9': 'File attribute hidden',
                     '10': 'Request header too long',
                     '11': 'Request contains double escape sequence',
                     '12': 'Request contains high-bit characters',
                     '13': 'Content length too large',
                     '14': 'Request URL too long',
                     '15': 'Query string too long',
                     '16': 'DAV request sent to the static file handler',
                     '17': 'Dynamic content mapped to the static file handler via a wildcard MIME mapping',
                     '18': 'Querystring sequence denied',
                     '19': 'Denied by filtering rule',
                     '20': 'Too Many URL Segments'}
    substatus_500 = {'0': 'Module or ISAPI error occurred',
                     '11': 'Application is shutting down on the web server',
                     '12': 'Application is busy restarting on the web server',
                     '13': 'Web server is too busy',
                     '15': 'Direct requests for Global.asax are not allowed',
                     '19': 'Configuration data is invalid',
                     '21': 'Module not recognized',
                     '22': 'An ASP.NET httpModules configuration does not apply in Managed Pipeline mode',
                     '23': 'An ASP.NET httpHandlers configuration does not apply in Managed Pipeline mode',
                     '24': 'An ASP.NET impersonation configuration does not apply in Managed Pipeline mode',
                     '50': 'A rewrite error occurred during RQ_BEGIN_REQUEST notification handling. A configuration or '
                           'inbound rule execution error occurred',
                     '51': 'A rewrite error occurred during GL_PRE_BEGIN_REQUEST notification handling. A global '
                           'configuration or global rule execution error occurred',
                     '52': 'A rewrite error occurred during RQ_SEND_RESPONSE notification handling. An outbound rule '
                           'execution occurred',
                     '53': 'A rewrite error occurred during RQ_RELEASE_REQUEST_STATE notification handling. An outbound'
                           ' rule execution error occurred. The rule is configured to be executed before the output '
                           'user cache gets updated',
                     '100': 'Internal ASP error'}
    substatus_502 = {'1': 'CGI application timeout',
                     '2': 'Bad gateway: Premature Exit',
                     '3': 'Bad Gateway: Forwarder Connection Error (ARR)',
                     '4': 'Bad Gateway: No Server (ARR)'}
    substatus_503 = {'0': 'Application pool unavailable',
                     '2': 'Concurrent request limit exceeded',
                     '3': 'ASP.NET queue full'}
    substatus_codes = {'403': substatus_403, '404': substatus_404, '500': substatus_500, '502': substatus_502,
                       '503': substatus_503}

    @classmethod
    def set_win32_url(cls, win32_status):
        win32_int_code = int(win32_status)
        if win32_int_code in range(0, 499):
            return r'https://msdn.microsoft.com/en-us/library/ms681382(v=vs.85).aspx'
        elif win32_int_code in range(500, 999):
            return r'https://msdn.microsoft.com/en-us/library/ms681388(v=vs.85).aspx'
        elif win32_int_code in range(1000, 1299):
            return r'https://msdn.microsoft.com/en-us/library/ms681383(v=vs.85).aspx'
        elif win32_int_code in range(1300, 1699):
            return r'https://msdn.microsoft.com/en-us/library/ms681385(v=vs.85).aspx'
        elif win32_int_code in range(1700, 3999):
            return r'https://msdn.microsoft.com/en-us/library/ms681386(v=vs.85).aspx'
        elif win32_int_code in range(4000, 5999):
            return r'https://msdn.microsoft.com/en-us/library/ms681387(v=vs.85).aspx'
        elif win32_int_code in range(6000, 8199):
            return r'https://msdn.microsoft.com/en-us/library/ms681389(v=vs.85).aspx'
        elif win32_int_code in range(8200, 8999):
            return r'https://msdn.microsoft.com/en-us/library/ms681390(v=vs.85).aspx'
        elif win32_int_code in range(9000, 11999):
            return r'https://msdn.microsoft.com/en-us/library/ms681391(v=vs.85).aspx'
        elif win32_int_code in range(12000, 15999):
            return r'https://msdn.microsoft.com/en-us/library/ms681384(v=vs.85).aspx'
        else:
            return r'https://msdn.microsoft.com/en-us/library/ms681381(v=vs.85).aspx'

    @classmethod
    def set_extended_defs(cls, row):
        if row['sc-status-code'] in cls.status_codes.keys():
            extended_defs = [cls.status_codes[row['sc-status-code']]]
            if row['sc-status-code'] in cls.substatus_codes.keys():
                extended_defs.append(cls.substatus_codes['sc-sub-status'])
            else:
                extended_defs.append("Undefined")
        else:
            extended_defs = "Undefined", "Undefined"
        return extended_defs

    def __init__(self, log_file, ip_cache, time_offset=None):
        super().__init__('timestamped')
        self.log_file = str(log_file)
        self.log_path = Path(log_file)
        assert self.log_path.is_file()
        self.log_size = stat(self.log_file)[6]
        self.log_kbytes = self.log_size / 1024
        self.start_from_index = 3
        self.time_offset = time_offset
        self.local_cache = ip_cache
        self.encoding = 'utf-8'
        self.delimiter = ' '
        self.dr = None
        self.fh = None
        self.username_dict = defaultdict(list)
        self.line_number = 0
        self.unique_ip_addresses = set()
        self.unique_ip_objects = set()
        self.log_ip_types = defaultdict(set)
        self.log_ip_type = None

    def parse_ip(self):
        for self.file_row in self.open_log(self.log_file, self.encoding, self.delimiter, self.iis_fields):
            self.record_count += 1
            self.unique_ip_addresses.add(self.file_row['s-ip'])
            self.unique_ip_addresses.add(self.file_row['c-ip'])
        print('{0} rows read in {1}.'.format(self.record_count, self.log_file))
        self.unique_ip_objects = {self.local_cache.return_ip_object(ip_string) for ip_string
                                  in self.unique_ip_addresses}
        try:
            for ip_obj in self.unique_ip_objects:
                self.log_ip_type = self.local_cache.return_ip_type(ip_obj)
                self.log_ip_types[self.log_ip_type].add(str(ip_obj))
        except:
            self.set_state('error')
            return self.state

        print('\t{0} global IP addresses found.'.format(len(self.log_ip_types['Global'])))
        self.set_state('parsed')  # This indicates that the log file instance has been parsed
        return self.state

    def parse_ip_in_mem(self):
        self.open_log_in_mem(self.log_file, self.encoding, self.delimiter, self.iis_fields)
        for self.row in self.log_file_buffer:
            self.record_count += 1
            self.unique_ip_addresses.add(self.row['s-ip'])
            self.unique_ip_addresses.add(self.row['c-ip'])
        print('{0} rows read in {1}.'.format(self.record_count, self.log_file))
        self.unique_ip_objects = {self.local_cache.return_ip_object(ip_string) for ip_string
                                  in self.unique_ip_addresses}
        try:
            for ip_obj in self.unique_ip_objects:
                self.log_ip_type = self.local_cache.return_ip_type(ip_obj)
                self.log_ip_types[self.log_ip_type].add(str(ip_obj))
        except:
            self.set_state('error')
            return self.state

        print('\t{0} global IP addresses found.'.format(len(self.log_ip_types['Global'])))
        self.set_state('parsed')  # This indicates that the log file instance has been parsed
        return self.state

    def parse_usernames(self, username_value):
        for self.file_row in self.open_log(self.log_file, self.encoding, self.delimiter, self.iis_fields):
            self.line_number += 1
            if self.file_row['cs-username'] and not self.file_row['cs-username'] == '-':
                if self.file_row['cs-username'] == username_value:
                    self.username_dict[self.file_name].append(self.file_row)
                else:
                    continue
        self.set_state('parsed')
        return self.state


class NetstatLog(IntelLog):
    netstat_fields = ('Proto', 'Local Address', 'Foreign Address', 'State', 'PID')

    def __init__(self, log_file, ip_cache):
        super().__init__('non_timestamped')
        self.log_file = log_file
        self.log_path = Path(log_file)
        assert self.log_path.is_file()
        self.local_cache = ip_cache
        self.start_from_index = 4
        self.parsed_netstat_log = {}
        self.dr = None
        self.nsfo = None
        self.encoding = 'utf-8'
        self.delimiter = ' '
        self.skip_initial_space = True
        self.unique_ip_addresses = set()
        self.unique_ip_objects = set()
        self.log_ip_types = defaultdict(set)
        self.log_ip_type = None

    def parse_ip(self):
        for self.file_row in self.open_log(self.log_file,
                                           self.encoding,
                                           self.delimiter,
                                           self.netstat_fields,
                                           self.start_from_index,
                                           self.skip_initial_space):
            self.record_count += 1
            try:
                self.parsed_netstat_log['Local Address'], self.parsed_netstat_log['Local Port'] \
                    = self.file_row['Local Address'].split(':')
                self.parsed_netstat_log['Remote Address'], self.parsed_netstat_log['Remote Port'] \
                    = self.file_row['Foreign Address'].split(':')
            except ValueError:
                continue # Throws out this line and moves on.  Opted not to create extensive error-handling logic.

            self.unique_ip_addresses.add(self.parsed_netstat_log['Local Address'])
            self.unique_ip_addresses.add(self.parsed_netstat_log['Remote Address'])

        self.unique_ip_objects = {self.local_cache.return_ip_object(ip_string) for ip_string
                                  in self.unique_ip_addresses}
        print('{0} rows read in {1}.'.format(self.record_count, self.log_file))
        try:
            for ip_obj in self.unique_ip_objects:
                self.log_ip_type = self.local_cache.return_ip_type(ip_obj)
                self.log_ip_types[self.log_ip_type].add(str(ip_obj))
        except:
            self.set_state('error')
            return self.state

        print('\t{0} global IP addresses found.'.format(len(self.log_ip_types['Global'])))
        self.set_state('parsed')
        return self.state

    def parse_ip_in_mem(self):
        self.open_log_in_mem(self.log_file,
                             self.encoding,
                             self.delimiter,
                             self.netstat_fields,
                             self.start_from_index,
                             self.skip_initial_space)
        for self.row in self.log_file_buffer:
            self.record_count += 1
            try:
                self.parsed_netstat_log['Local Address'], self.parsed_netstat_log['Local Port'] \
                    = self.row['Local Address'].split(':')
                self.parsed_netstat_log['Remote Address'], self.parsed_netstat_log['Remote Port'] \
                    = self.row['Foreign Address'].split(':')
            except ValueError:
                continue  # Throws out this line and moves on.  Opted not to create extensive error-handling logic.

            self.unique_ip_addresses.add(self.parsed_netstat_log['Local Address'])
            self.unique_ip_addresses.add(self.parsed_netstat_log['Remote Address'])
        self.unique_ip_objects = {self.local_cache.return_ip_object(ip_string) for ip_string
                                  in self.unique_ip_addresses}
        print('{0} rows read in {1}.'.format(self.record_count, self.log_file))
        try:
            for ip_obj in self.unique_ip_objects:
                self.log_ip_type = self.local_cache.return_ip_type(ip_obj)
                self.log_ip_types[self.log_ip_type].add(str(ip_obj))
        except:
            self.set_state('error')
            return self.state

        print('\t{0} global IP addresses found.'.format(len(self.log_ip_types['Global'])))
        self.set_state('parsed')
        return self.state

# -------------- Main Flow ----------------


base_path = r'C:/MoTemp/'
iis_path = r'C:/MoTemp/iis/'
netstat_path = r'C:/MoTemp/netstat/'
ip_cache_filename = base_path + 'ip_cache.dat'
unique_global_ip_addresses = set()

try:
    with open(ip_cache_filename, 'rb') as p_ip_cache:
        cache_data = pickle.load(p_ip_cache)
        print("Loaded cache file into memory.")
except FileNotFoundError:
    print("{0} was not found, assuming an empty cache!".format(ip_cache_filename))
    cache_data = IP_Cache()

for netstat_file in choose_files(netstat_path):
    netstat_log = NetstatLog(netstat_file, cache_data)
    netstat_log.parse_ip_in_mem()
    if netstat_log.state == 'parsed':
        unique_global_ip_addresses |= netstat_log.log_ip_types['Global']
    else:
        print("{0} had some kind of parsing error, skipping that file's data for now.".format(netstat_log.file_name))

    print('{0} status = {1}'.format(netstat_log.file_name, netstat_log.state))

for iis_file in choose_files(iis_path):
    iis_log = IISLog(iis_file, cache_data)
    iis_log.parse_ip()
    if iis_log.state == 'parsed':
        unique_global_ip_addresses |= iis_log.log_ip_types['Global']
    else:
        print("{0} had some kind of parsing error, skipping that file's data for now.".format(iis_log.file_name))

    print('{0} status = {1}'.format(iis_log.file_name, iis_log.state))

# -------- Populate IP Cache ----------

cache_data.add_to_cache(unique_global_ip_addresses)
print('Cache Hits={0}'.format(cache_data.cache_hits))
print('Lookups Performed={0}'.format(cache_data.lookup_count))

if cache_data.ip_addresses_with_lookup_errors:
    print('--------- Lookups that failed for which no data was collected are listed below ---------')
    for error_ip in cache_data.ip_addresses_with_lookup_errors:
        print(error_ip)

with open(ip_cache_filename, 'wb') as p_ip_cache:
    pickle.dump(cache_data, p_ip_cache, pickle.HIGHEST_PROTOCOL)






