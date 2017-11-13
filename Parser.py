from csv import DictReader


class Parser:
    def __init__(self, source_file, columns, file_encoding='utf-8', file_delimiter=',', skip_lines=0, skip_space=False):
        self.parsed_successfully = False
        self.consider_valid = False  # Errors with parsing a file will set this to False.  No errors = True.
        self.record_count = 0
        self.columns = []
        self.reader_obj = None
        self.fh = None
        self.file_name = source_file
        self.columns = columns
        self.encoding = file_encoding
        self.delimiter = file_delimiter
        self.lines_to_skip = skip_lines
        self.skip_initial_space = skip_space

    def __str__(self):
        pass

    def __repr__(self):
        pass

    def parse(self):
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
    def __init__(self):
        pass

    def __str__(self):
        pass

    def __repr__(self):
        pass


class WMIC_Parser(Parser):
    def __init__(self):
        pass

    def __str__(self):
        pass

    def __repr__(self):
        pass


class Tasklist_Parser(Parser):
    def __init__(self):
        pass

    def __str__(self):
        pass

    def __repr__(self):
        pass


class Windows_Event_Parser(Parser):
    def __init__(self):
        pass

    def __str__(self):
        pass

    def __repr__(self):
        pass
