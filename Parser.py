from csv import DictReader, QUOTE_ALL
from datetime import timedelta, timezone
from dateutil.parser import parse as dateparse

class Parser:
    def __init__(self, source_file, victim, investigation_id,
                 file_encoding='iso-8859-1', file_delimiter=',', skip_lines=0,
                 skip_space=False, quote_char='"', quoting=QUOTE_ALL):
        self.victim = victim  # To associate this object with a particular computer under investigation
        self.investigation_id = investigation_id
        self.parsed_successfully = False
        self.consider_valid = False  # Errors with parsing a file will set this to False.  No errors = True.
        self.record_count = 0
        self.columns = None
        self.reader_obj = None
        self.fh = None
        self.file_name = source_file  # This should be a Path object, not a string.
        self.encoding = file_encoding
        self.delimiter = file_delimiter
        self.lines_to_skip = skip_lines
        self.skip_initial_space = skip_space
        self.quoting = quoting
        self.quote_char = quote_char


    def __str__(self):
        return (f'Default Class Parser "{self.file_name}" associated with {self.victim} '
                f'for investigation case {self.investigation_id}')

    def __repr__(self):
        return self.file_name

    def parse(self):
        #assert self.columns  # We should not get here without self.columns being set
        with open(self.file_name, 'r', encoding=self.encoding) as self.fh:
            for i in range(self.lines_to_skip):
                self.fh.readline()  # Skip over any garbage lines
            self.reader_obj = DictReader(self.fh, delimiter=self.delimiter,
                                         fieldnames=self.columns, skipinitialspace=self.skip_initial_space)
            for row in self.reader_obj:
                yield row

    def convert_wmi_time_to_iso(self, wmi_time):
        year = wmi_time[0:4]
        month = wmi_time[4:6]
        day = wmi_time[6:8]
        hours = wmi_time[8:10]
        minutes = wmi_time[10:12]
        seconds = wmi_time[12:14]
        microseconds = wmi_time[15:21]
        dirty = wmi_time[0:14]
        offset = int(wmi_time[22:])
        tz = str(timezone(timedelta(minutes=offset)))
        clean = dateparse(dirty + tz).isoformat(' ')
        return clean


class IIS_Parser(Parser):
    def __init__(self):
        pass

    def __str__(self):
        pass

    def __repr__(self):
        pass


class Netstat_Parser(Parser):
    netstat_columns = ('Proto', 'Local Address', 'Foreign Address', 'State', 'PID')
    def __init__(self, source_file, victim, investigation_id):
        super().__init__(source_file, victim, investigation_id, file_delimiter=' ', skip_lines=4, skip_space=True)
        self.columns = ('Proto', 'Local Address', 'Foreign Address', 'State', 'PID')

    def __str__(self):
        return (f'Netstat Parser "{self.file_name}" associated with {self.victim} '
                f'for investigation case {self.investigation_id}')

    def __repr__(self):
        return self.file_name

    def parse(self):
        '''Overrides the default Parser method to handle IPv6 address notations in Netstat output.'''
        with open(self.file_name, 'r', encoding=self.encoding) as self.fh:
            for i in range(self.lines_to_skip):
                self.fh.readline()  # Skip over any garbage lines
            self.reader_obj = DictReader(self.fh, delimiter=self.delimiter,
                                         fieldnames=self.columns, skipinitialspace=self.skip_initial_space)
            for row in self.reader_obj:
                if row['Proto'] == 'UDP':
                    cleaned_row = {'state': 'N/A', 'pid': int(row['State']), 'proto': 'UDP'}
                else:
                    cleaned_row = {'pid': int(row['PID']), 'state': row['State'], 'proto': row['Proto']}

                if row['Local Address'].startswith('['):
                    cleaned_row['local_address'], cleaned_row['local_port'] = row['Local Address'].split(']:')
                    cleaned_row['local_address'] = cleaned_row['local_address'].strip('[')
                else:
                    cleaned_row['local_address'], cleaned_row['local_port'] = row['Local Address'].split(':')

                if row['Foreign Address'].startswith('['):
                    cleaned_row['foreign_address'], cleaned_row['foreign_port'] = row['Foreign Address'].split(']:')
                    cleaned_row['foreign_address'] = cleaned_row['foreign_address'].strip('[')
                else:
                    cleaned_row['foreign_address'], cleaned_row['foreign_port'] = row['Foreign Address'].split(':')

                yield cleaned_row


class WMIC_Parser(Parser):
    def __init__(self, source_file, victim, investigation_id):
        super().__init__(source_file, victim, investigation_id, skip_lines=1, file_encoding='utf-16')
        # Different Microsoft tools export CSV using different encodings....sigh.

    def __str__(self):
        return (f'WMIC Parser "{self.file_name}" associated with victim {self.victim} '
                f'for investigation case {self.investigation_id}')

    def __repr__(self):
        return self.file_name

    def parse(self):
        '''Overrides the default Parser method to handle blank paths by appending NOT_AVAILABLE.'''
        #assert self.columns  # We should not get here without self.columns being set
        with open(self.file_name, 'r', encoding=self.encoding) as self.fh:
            for i in range(self.lines_to_skip):
                self.fh.readline()  # Skip over any garbage lines
            self.reader_obj = DictReader(self.fh, delimiter=self.delimiter,
                                         fieldnames=self.columns, skipinitialspace=self.skip_initial_space)
            for row in self.reader_obj:
                # Before throwing out the redundant column, make sure it's actually redundant
                assert row['Node'] == self.victim
                cleaned_row = {'pid': int(row['ProcessId']), 'creation_date': row['CreationDate']}
                if not row['ExecutablePath']:
                    cleaned_row['executable_path'] = 'NOT_AVAILABLE'
                else:
                    cleaned_row['executable_path'] = row['ExecutablePath']
                yield cleaned_row


class Netconfig_Parser(Parser):
    def __init__(self, source_file, victim, investigation_id):
        super().__init__(source_file, victim, investigation_id, skip_lines=1, file_encoding='utf-16')
        # Different Microsoft tools export CSV using different encodings....sigh.

    def __str__(self):
        return (f'Netconfig Parser "{self.file_name}" associated with victim {self.victim} '
                f'for investigation case {self.investigation_id}')

    def __repr__(self):
        return self.file_name

    def parse(self):
        with open(self.file_name, 'r', encoding=self.encoding) as self.fh:
            for i in range(self.lines_to_skip):
                self.fh.readline()  # Skip over any garbage lines
            self.reader_obj = DictReader(self.fh, delimiter=self.delimiter,
                                         fieldnames=self.columns, skipinitialspace=self.skip_initial_space)
            for row in self.reader_obj:
                assert row['Node'] == self.victim
                del row['Node']
                if row['DHCPServer']:
                    row['DHCPLeaseExpires'] = self.convert_wmi_time_to_iso(row['DHCPLeaseExpires'])
                    row['DHCPLeaseObtained'] = self.convert_wmi_time_to_iso(row['DHCPLeaseObtained'])
                adapter_num, caption = row['Caption'].split(']')
                row['Caption'] = caption.strip()
                chars_to_strip = ['{', '}']
                for bad_char in chars_to_strip:

                    row['DNSServerSearchOrder'] = row['DNSServerSearchOrder'].strip(bad_char)
                    row['IPAddress'] = row['IPAddress'].strip(bad_char)
                    row['IPSubnet'] = row['IPSubnet'].strip(bad_char)
                    row['DefaultIPGateway'] = row['DefaultIPGateway'].strip(bad_char)
                yield row


class Tasklist_Parser(Parser):
    def __init__(self, source_file, victim, investigation_id):
        super().__init__(source_file, victim, investigation_id, skip_space=True)

    def __str__(self):
        return(f'Tasklist Parser "{self.file_name}" associated with victim {self.victim} '
               f'for investigation case {self.investigation_id}')

    def __repr__(self):
        return self.file_name


class Windows_Event_Parser(Parser):
    def __init__(self):
        pass

    def __str__(self):
        pass

    def __repr__(self):
        pass

