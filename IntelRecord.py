from ipaddress import ip_network


class NetworkRecord:
    def __init__(self, network_string):
        self.net = network_string
        self.net_obj = ip_network(self.net)  # Using factory function to handle both IPv4 and IPv6 cases
        self.data_dict = {}
        self.last_refreshed = False
        self.ip_objects = set()
        self.referenced = False  # Flag to indicate the are IPAddress objects associated with this object

    def __str__(self):
        return f'{self.net} | Last Refresh Date: {self.last_refreshed}'

    def __repr__(self):
        return self.net_obj

    def associate(self, ip_address_obj):
        self.ip_objects.add(ip_address_obj)  # Naively assumes that this will always be the correct object type
        self.referenced = True


class AddressRecord:
    def __init__(self, address):
        self.addr = address # Should always be an IPAddress object of either IPv4 or IPv6 type
        self.network_record = False  # This should refer to a NetworkRecord object when populated
        self.last_refreshed = False
        self.associated = False  # Flag to indicate the object is successfully tied to a NetworkRecord object.

    def __str__(self):
        return f'{self.addr}, in network: {self.network_record}'

    def __repr__(self):
        return self.addr # Objective here is to simplify comparisons with NetworkRecord

    def associate(self, network_record_obj):
        self.network_record = network_record_obj  # Naively assumes that this will always be the correct object type
        self.network_record.associate(self.addr)
        self.associated = True

    def query(self, global_ip_cache_obj, search_depth=1):
        self.cache = global_ip_cache_obj  # This should only refer to an object of Global_IP_Cache type
        assert self.cache.cache_type == 'IP'
        self.network_record = self.cache.search(self.addr)
        if self.network_record:
            self.network_record.associate(self.addr)
            self.associated = True
        return self.network_record  # If this returns False, you know you need to do an RDAP lookup for that IP.





    def refresh(self):
        assert self.network_record
        # todo: Update data dictionary in associated NetworkRecord object if last_refreshed > MAXAGE
