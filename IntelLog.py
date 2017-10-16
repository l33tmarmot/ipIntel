from pathlib import Path
from os import stat
from ipaddress import ip_address, ip_network, IPv4Network, IPv4Address, AddressValueError
from csv import DictReader
from ipwhois import IPWhois
from collections import defaultdict

# ----------- FUNCTIONS-----------


def choose_files(file_path):
    """Generator function yielding each file from the path specified."""
    p = Path(file_path)
    files = p.glob('**/*.*')   # This is going to grab everything
    for f in files:
        if f.is_dir():
            continue
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
        ip_record = IPWhois(ip_str)
        results = ip_record.lookup_rdap(depth=0)
        return results

    def add_to_cache(self, ip_list):
        cached_networks = [ip_network(major_net.strip()) for major_net in self.cache_data.keys()]
        ip_addresses_to_add = [ip for ip in ip_list if ip_address(ip) not in cached_networks]
        for address in ip_addresses_to_add:
            info_dict = self.lookup_single_ip(address)
            new_nets = info_dict['network']['cidr'].split(',')
            new_net_country = info_dict['network']['country']
            new_net_name = info_dict['network']['name']
            new_net_events = info_dict['network']['events']
            new_net_asn = info_dict['asn_cidr']
            for new_net in new_nets:
                new_net_obj = NetRecord(new_net.strip(), new_net_country, new_net_name, new_net_events)
                new_asn_dict = {'asn': info_dict['asn'],
                                'asn_country_code': info_dict['asn_country_code'],
                                'asn_date': info_dict['asn_date'],
                                'asn_description': info_dict['asn_description'],
                                'asn_registry': info_dict['asn_registry']}
                try:
                    test_for_cidr = ip_network(new_net_asn)  # Sometimes ARIN returns 'NA'
                    new_net_obj.add_asn(new_net_asn, new_asn_dict)
                except ValueError:
                    print("Record {0} did not return a valid asn_cidr value, "
                          "thus that value ({1}) will not be included.".format(new_net.strip(), new_net_asn))
                    pass
                self.cache_data[new_net] = new_net_obj

    def print_cache(self):
        for network in self.cache_data.keys():
            self.cache_data[network].print() # Each value should be a NetRecord object


class IntelLog:
    log_types = ('timestamped', 'non_timestamped')
    valid_states = ('unparsed', 'parsed', 'error')

    def __init__(self, log_type, log_directory):
        assert log_type in self.log_types
        self.state = 'unparsed'
        assert self.state in self.valid_states
        self.log_dir = Path(log_directory)
        assert self.log_dir.is_dir()
        self.record_count = 0
        self.columns = []
        self.reader_obj = None
        self.fh = None
        self.file_name = ''
        self.encoding = ''
        self.delimiter = ''
        self.lines_to_skip = 0
        self.skip_initial_space=False

    def get_state(self):
        return self.state

    def set_state(self, state):
        assert state in self.valid_states
        self.state = state

    def open_log(self, file_name, file_encoding, file_delimiter, file_columns, skip_lines=0, skip_space=False):
        self.lines_to_skip = int(skip_lines)
        self.skip_initial_space = skip_space
        self.columns = file_columns
        self.file_name = file_name
        self.encoding = file_encoding
        self.delimiter = file_delimiter
        with open(self.file_name, 'r', encoding=self.encoding) as self.fh:
            for i in range(self.lines_to_skip):
                self.fh.readline() # This is used to skip over any header garbage by moving the file pointer ahead
            self.reader_obj = DictReader(self.fh,
                                         delimiter=self.delimiter,
                                         fieldnames=self.columns,
                                         skipinitialspace=self.skip_initial_space)
            for self.row in self.reader_obj:
                yield self.row

    @classmethod
    def remove_duplicates(cls, in_list):
        return list(set(in_list))


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

    def __init__(self, log_file, ip_cache, time_offset=None):
        super().__init__('timestamped')
        self.log_file = log_file
        self.log_path = Path(log_file)
        assert self.log_path.is_file()
        self.log_size = stat(log_file)[6]
        self.log_kbytes = self.log_size / 1024
        self.start_from_index = 3
        self.time_offset = time_offset
        self.local_cache = ip_cache
        self.server_ip = None
        self.server_ip_type = ''
        self.client_ip = None
        self.client_ip_type = ''
        self.encoding = 'utf-8'
        self.delimiter = ' '
        self.dr = None
        self.fh = None
        self.ip_dict = defaultdict(list)
        self.parsed_ip_dict = defaultdict(list)

    def parse_ip(self):
        for self.file_row in self.open_log(self.log_file, self.encoding, self.delimiter, self.iis_fields):
            self.record_count += 1
            self.server_ip = self.local_cache.return_ip_object(self.file_row['s-ip'])
            self.server_ip_type = self.local_cache.return_ip_type(self.server_ip)
            self.ip_dict[self.server_ip_type].append(self.file_row['s-ip'])
            self.client_ip = self.local_cache.return_ip_object(self.file_row['c-ip'])
            self.client_ip_type = self.local_cache.return_ip_type(self.client_ip)
            self.ip_dict[self.client_ip_type].append(self.file_row['c-ip'])
        print('{0} rows read in {1}.'.format(self.record_count, self.log_file))
        try:
            for address_type in self.ip_dict.keys():
                self.parsed_ip_dict[address_type] = self.remove_duplicates(self.ip_dict[address_type])
        except:
            self.set_state('error')  # This indicates the log file instance here is in an error state.
            return self.state

        self.set_state('parsed')  # This indicates that the log file instance has been parsed
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
        self.private_ip_list = []
        self.public_ip_list = []
        self.local_ip = None
        self.local_ip_type = ''
        self.remote_ip = None
        self.remote_ip_type = ''
        self.dr = None
        self.nsfo = None
        self.encoding = 'utf-8'
        self.delimiter = ' '
        self.skip_initial_space = True
        self.ip_dict = defaultdict(list)
        self.parsed_ip_dict = defaultdict(list)

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
                continue # Throws out this line and moves on

            self.local_ip = self.local_cache.return_ip_object(self.parsed_netstat_log['Local Address'])
            self.remote_ip = self.local_cache.return_ip_object(self.parsed_netstat_log['Remote Address'])

            self.local_ip_type = self.local_cache.return_ip_type(self.local_ip)
            self.ip_dict[self.local_ip_type].append(self.parsed_netstat_log['Local Address'])

            self.remote_ip_type = self.local_cache.return_ip_type(self.remote_ip)
            self.ip_dict[self.remote_ip_type].append(self.parsed_netstat_log['Remote Address'])
        print('{0} rows read in {1}.'.format(self.record_count, self.log_file))
        try:
            for address_type in self.ip_dict.keys():
                self.parsed_ip_dict[address_type] = self.remove_duplicates(self.ip_dict[address_type])
        except:
            self.set_state('error')
            return self.state

        self.set_state('parsed')
        return self.state


base_path = r'C:/MoTemp'
iis_path = r'C:/MoTemp/iis/'
netstat_path = r'C:/MoTemp/netstat/'

cache_data = IP_Cache()

for iis_file in choose_files(iis_path):
    iis_log = IISLog(iis_file, cache_data)

for netstat_file in choose_files(netstat_path):
    netstat_log = NetstatLog(netstat_file, cache_data)

cache_data.print_cache()





