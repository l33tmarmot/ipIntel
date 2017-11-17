from csv import DictReader, QUOTE_ALL


class Parser:
    def __init__(self, source_file, victim, investigation_id,
                 file_encoding='utf-8', file_delimiter=',', skip_lines=0,
                 skip_space=False, quote_char='"', quoting=QUOTE_ALL, sniff_columns=False):
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
        self.sniff = sniff_columns
        if self.sniff:
            self._sniff_columns_from_first_row()


    def __str__(self):
        pass

    def __repr__(self):
        pass

    def parse(self):
        assert self.columns  # We should not get here without self.columns being set
        with open(self.file_name, 'r', encoding=self.encoding) as self.fh:
            for i in range(self.lines_to_skip):
                self.fh.readline()  # Skip over any garbage lines
            self.reader_obj = DictReader(self.fh, delimiter=self.delimiter,
                                         fieldnames=self.columns, skipinitialspace=self.skip_initial_space)
            for row in self.reader_obj:
                yield row  #todo: Fix Tasklist.  It's splitting each char in the column into it's own dict key.

    def _sniff_columns_from_first_row(self):
        '''Attempt to set the DictReader columns based on the fields encountered in the first row.'''
        with open(self.file_name, 'r', encoding=self.encoding) as self.fh:
            for i in range(self.lines_to_skip):
                self.fh.readline()
            self.columns = self.fh.readline()



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
        print(f'Netstat Parser "{self.file_name}" associated with {self.victim} '
              f'for investigation case {self.investigation_id}')

    def __repr__(self):
        return self.file_name


class WMIC_Parser(Parser):
    def __init__(self):
        pass

    def __str__(self):
        pass

    def __repr__(self):
        pass


class Tasklist_Parser(Parser):
    def __init__(self, source_file, victim, investigation_id):
        super().__init__(source_file, victim, investigation_id, skip_space=True, sniff_columns=True)

    def __str__(self):
        print(f'Tasklist Parser "{self.file_name}" associated with {self.victim} '
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

