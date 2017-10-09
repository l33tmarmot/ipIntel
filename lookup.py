from ipwhois import IPWhois
from ipaddress import ip_address, ip_network, IPv4Network
from pprint import pprint


class NetRecord:
    def __init__(self, network, country, name, events):
        self.cidr = IPv4Network(network)  # todo: Handle multiple networks returned by RDAP that are comma-separated.
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


def lookup_single_ip(ip_str):
    ip_record = IPWhois(ip_str)
    results = ip_record.lookup_rdap(depth=1)
    return results


ip_list = ['34.19.104.249', '67.105.200.10', '4.2.2.2', '8.8.8.8', '67.105.200.1']

cachedata = {}
output_data = {}

for ip in ip_list:
    ip_obj = ip_address(ip)
    for major_net in cachedata.keys():
        cached_net = ip_network(major_net)
        if ip_obj in cached_net:
            print("Cache Hit: {0} is in network {1}".format(ip, major_net))
            output_data[ip] = cachedata[major_net]
            break  # Cache hit, move to the next IP.
    else:
        info_dict = lookup_single_ip(ip)

        new_net = info_dict['network']['cidr']
        new_net_country = info_dict['network']['country']
        new_net_name = info_dict['network']['name']
        new_net_events = info_dict['network']['events']
        new_net_asn = info_dict['asn_cidr']

        new_net_obj = NetRecord(new_net, new_net_country, new_net_name, new_net_events)
        new_asn_dict = {'asn': info_dict['asn'],
                        'asn_country_code': info_dict['asn_country_code'],
                        'asn_date': info_dict['asn_date'],
                        'asn_description': info_dict['asn_description'],
                        'asn_registry': info_dict['asn_registry']}
        new_net_obj.add_asn(new_net_asn, new_asn_dict)

        cachedata[new_net] = new_net_obj
        output_data[ip] = new_net_obj
        print("New Record:{0}".format(ip))


print("List complete, printing output...")
for ip, info in output_data.items():
    print("{0} Network >> {1}".format(ip, str(info.cidr)))
    print("\t{0}".format(info.find_asn_data(ip)))
