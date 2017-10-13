from ipwhois import IPWhois
from ipaddress import ip_address, ip_network, IPv4Network, IPv4Address, AddressValueError
from csv import DictReader
from pathlib import Path


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


def returnIP_object(ip_string):
    try:
        ip = IPv4Address(ip_string)
    except AddressValueError:
        print("'{0}' is not a valid IPv4 Address.".format(ip_string))
        return ip_string
    return ip


def returnIP_type(ip_obj):
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


def parse_netstat_logs(netstat_file_obj):
    with open(netstat_file_obj, "r") as nsfo:
        columns = ('Proto', 'Local Address', 'Foreign Address', 'State', 'PID')
        for i in range(4):
            nsfo.readline()  # Skip the obnoxious header
        dr = DictReader(nsfo, fieldnames=columns, delimiter=' ', skipinitialspace=True)
        parsed_netstat_log = {}
        private_ip_list = []
        public_ip_list = []
        for row in dr:
            try:
                parsed_netstat_log['Local Address'], parsed_netstat_log['Local Port'] = row['Local Address'].split(':')
                parsed_netstat_log['Remote Address'], parsed_netstat_log['Remote Port'] = row['Foreign Address'].split(':')
            except ValueError:
                continue

            local_ip = returnIP_object(parsed_netstat_log['Local Address'])
            remote_ip = returnIP_object(parsed_netstat_log['Remote Address'])

            if returnIP_type(local_ip) == 'RFC1918 Private':
                private_ip_list.append(str(local_ip))
            else:
                public_ip_list.append(str(local_ip))

            if returnIP_type(remote_ip) == 'Global':
                public_ip_list.append(str(remote_ip))
            else:
                private_ip_list.append(str(remote_ip))

        ip_dict = {'Public': list(set(public_ip_list)), 'Private': list(set(private_ip_list))}
        return ip_dict


def lookup_single_ip(ip_str):
    ip_record = IPWhois(ip_str)
    results = ip_record.lookup_rdap(depth=0)
    return results



netstat_file_path = 'C:/MoTemp/netstat_ano.txt'
netstat_ip_dict = parse_netstat_logs(netstat_file_path)

ip_list = ['34.19.104.249', '67.105.200.10', '4.2.2.2', '8.8.8.8', '67.105.200.1']

cachedata = {}
output_data = {}

for ip in netstat_ip_dict['Public']:   # ip_list:
    ip_obj = ip_address(ip)
    for major_net in cachedata.keys():
        cached_net = ip_network(major_net.strip())
        if ip_obj in cached_net:
            print("Cache Hit: {0} is in network {1}".format(ip, major_net))
            output_data[ip] = cachedata[major_net]
            break  # Cache hit, move to the next IP.
    else:
        info_dict = lookup_single_ip(ip)
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
                test_for_cidr = ip_network(new_net_asn)  # Sometimes ARIN returns 'NA' if there aren't net records
                new_net_obj.add_asn(new_net_asn, new_asn_dict)
            except ValueError:
                print("Record {0} did not return a valid asn_cidr value, "
                      "thus that value ({1}) will not be included.".format(new_net.strip(), new_net_asn))
                pass
            cachedata[new_net] = new_net_obj
            output_data[ip] = new_net_obj
            print("New Record:{0}".format(ip))


print("List complete, printing output...")
for ip, net_record in output_data.items():
    net_record.print()
