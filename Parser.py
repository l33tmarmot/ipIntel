from csv import DictReader, QUOTE_ALL


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
                cleaned_row = {'pid': int(row['ProcessId'])}
                if not row['ExecutablePath']:
                    cleaned_row['executable_path'] = 'NOT_AVAILABLE'
                else:
                    cleaned_row['executable_path'] = row['ExecutablePath']
                yield cleaned_row

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

