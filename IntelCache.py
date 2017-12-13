import pickle
from ipwhois import IPWhois
from IntelRecord import NetworkRecord
from pprint import pprint
from datetime import date

class IntelCache:
    def __init__(self, cache_type, cache_file='global_ip_cache.dat'):
        self.cache_type = cache_type
        self.file = cache_file

    def __repr__(self):
        return self.cache_type

    def __str__(self):
        return f'{self.cache_type}'


class Global_IP_Cache(IntelCache):
    def __init__(self, cache_file):  # Expects a Path object, not a string
        super().__init__('IP', cache_file)
        self.loaded_from_file = False
        self.query_depth = 1
        try:
            self.read()
            self.loaded_from_file = True
        except FileNotFoundError:
            print(f'{self.file} not found, assuming empty cache.')
            self.networks = set()  # The only objects stored here should be NetworkRecord objects

    def __repr__(self):
        return self.file

    def __str__(self):
        return f'Global IP address cache stored at {self.file}'

    def add(self, ip_obj):
        whois_obj = IPWhois(str(ip_obj), allow_permutations=True)
        results_dict = whois_obj.lookup_rdap(depth=self.query_depth)

        new_network_list = results_dict['network']['cidr'].split(',')
        for new_net in new_network_list:
            new_network = NetworkRecord(new_net.strip())
            new_network.data_dict = results_dict
            new_network.last_refreshed = date.today()
            self.networks.add(new_network)  # Don't add any other objects other than NetworkRecord objects here.


    def save(self):
        with open(self.file, 'wb') as fh:
            pickle.dump(self.networks, fh, pickle.HIGHEST_PROTOCOL)

    def read(self):
        with open(self.file, 'rb') as fh:
            self.networks = pickle.load(fh)

    def search(self, ip_obj):
        network_record_obj = None
        for network_record_obj in self.networks:  # network_record_obj needs to be a NetworkRecord object
            if ip_obj in network_record_obj.net_obj:
                return network_record_obj
        else:
            return False

    def dump(self):
        for net_record in self.networks:
            pprint(net_record.data_dict)












