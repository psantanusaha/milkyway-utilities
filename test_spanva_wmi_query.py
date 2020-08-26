#!/usr/bin/env python
import os
import subprocess


def main():
    print (sorted(file in os.listdir("/opt/agent/data/ad_sync/"),key=os.path.getmtime))


def query():
    """
    Override base class` query() method only to change the last line
    to use our custom parse_wmic_output method which can handle multiline values
    """
    try:
        # construct the arguments to wmic
        arguments = ['/bin/wmic', '--delimiter=\x01', '--user=Administrator@dccwpqa.com%great@123', '//10.105.164.120', "Select * from Win32_NTLogEvent where Logfile='Security' and EventCode='4624' and EventType='4' and TimeGenerated  > '20200801110713.757285-000'"]

        # execute the command
        output = subprocess.check_output(arguments)

        # just to be sure? sh is weird sometimes.
        output = str(output)

        # and now parse the output
        #return ElWMIClient._parse_wmic_output(output, delimiter=self.delimiter)

    except subprocess.CalledProcessError as e:
        print e.message
        # Make sure no credentials are leaked here.
        raise RuntimeError("Command Failed for AD server: %s query: %s " )

    except Exception:
        print(
            "Exception while WMI querying the domain controller for logon events")

    return None


if __name__ == "__main__":
    query()
