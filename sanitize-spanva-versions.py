import os
import argparse
pattern = "'+--------------------------+----------------+-------+----------------+------------------+------------------------+-----+------+------+-------------------------------------+'"
csv_header="SpanVaId,Name,IpAddress,Version,AvailableUpdateVersion,CPU,Disk,Mem,CreatedBy"

class SanitizePrettyTable():
    def __init__(self, path_of_pretty_table_file, destination_file):
        self.source_file_path = path_of_pretty_table_file
        if os.path.exists(destination_file):
            os.remove(destination_file)
        if os.path.exists("intermediate_file.txt"):
            os.remove("intermediate_file.txt")

        self.destination_file_path = destination_file

    def sanitize_and_get_csv(self):
        self.remove_table_and_print_in_groups()
        self.read_grouped_and_write_csv()

    def remove_table_and_print_in_groups(self):
        with open(self.source_file_path, 'r') as fp:
            with open("intermediate_file.txt", "a") as fpw:
                lines = fp.readlines()
                for line in lines:
                    if "SpanVaId" in line:
                        continue
                    if pattern in line:
                        continue
                    if "****" in line:
                        tenant = line.strip().split()[1].split(":")[1]
                        fpw.write("TENANT:" + tenant + "\n")
                    else:
                        data = [a.strip() for a in line.split('|')]
                        if len(data) > 1:
                            data.pop(0)
                            fpw.write(",".join(data) + "\n")

    def read_grouped_and_write_csv(self):
        with open("intermediate_file.txt", "r") as fpr:
            with open(self.destination_file_path, "a") as fpw:
                fpw.write(csv_header)
                for i, group in enumerate(self.__get_groups(fpr, "TENANT:"), start=1):
                    tenant = group[0].strip().replace("TENANT:", "")
                    for index in range(1, len(group)):
                        result = tenant + "," + group[index]
                        fpw.write(result + "\n")

    def __get_groups(self, seq, group_by):
        data = []
        for line in seq:
            # Here the `startswith()` logic can be replaced with other
            # condition(s) depending on the requirement.
            if line.startswith(group_by):
                if data:
                    yield data
                    data = []
            data.append(line)

        if data:
            yield data


def main():
    parser = argparse.ArgumentParser(description='Convert PrettTable of SpanVa to CSV')
    parser.add_argument('--input', help='The File which needs to be converted')
    parser.add_argument('--output', help='Result of Conversion Process')
    args = parser.parse_args()
    source_path = args.input
    destination_file = args.output
    SanitizePrettyTable(source_path, destination_file).sanitize_and_get_csv()


if __name__ == "__main__":
    main()
