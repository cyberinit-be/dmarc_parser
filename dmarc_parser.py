import sys
from defusedxml.ElementTree import parse as ET_parse
import csv

# Function to parse the XML report
import os

import os
import datetime

def parse_xml(xml_file):
    tree = ET_parse(xml_file)
    root = tree.getroot()
    data = []

    # Get the date range (begin and end) and convert epoch timestamps to "DD/MM/YYYY" format
    date_range = root.find('.//date_range')
    begin_timestamp = int(find_text(date_range, './/begin'))
    end_timestamp = int(find_text(date_range, './/end'))
    begin_date = datetime.datetime.fromtimestamp(begin_timestamp).strftime('%d/%m/%Y')
    end_date = datetime.datetime.fromtimestamp(end_timestamp).strftime('%d/%m/%Y')

    # Get the filename (without the path)
    filename = os.path.basename(xml_file)

    for record in root.findall('.//record'):
        row = {}
        row['begin_date'] = begin_date
        row['end_date'] = end_date
        row['source_ip'] = find_text(record, './/source_ip')
        row['count'] = find_text(record, './/count')
        policy_evaluated = record.find('.//policy_evaluated')
        row['disposition'] = find_text(policy_evaluated, './/disposition')
        row['dkim'] = find_text(policy_evaluated, './/dkim')
        row['spf'] = find_text(policy_evaluated, './/spf')

        identifiers = record.find('.//identifiers')
        row['header_from'] = find_text(identifiers, './/header_from')
        row['envelope_from'] = find_text(identifiers, './/envelope_from', default='')
        row['envelope_to'] = find_text(identifiers, './/envelope_to', default='')

        auth_results = record.find('.//auth_results')
        dkim_auths = auth_results.findall('.//dkim')
        spf_auths = auth_results.findall('.//spf')

        if dkim_auths:
            dkim_auth = dkim_auths[0]
            row['dkim_domain'] = find_text(dkim_auth, './/domain')
            row['dkim_selector'] = find_text(dkim_auth, './/selector')
            row['dkim_result'] = find_text(dkim_auth, './/result')

        if spf_auths:
            spf_auth = spf_auths[0]
            row['spf_domain'] = find_text(spf_auth, './/domain')
            row['spf_scope'] = find_text(spf_auth, './/scope', default='')
            row['spf_result'] = find_text(spf_auth, './/result')

        row['filename'] = filename
        data.append(row)

    return data









def find_text(element, path, default=''):
    elem = element.find(path)
    return elem.text if elem is not None else default

# Function to write data to a CSV file
def write_to_csv(data, csv_file):
    keys = data[0].keys()
    with open(csv_file, 'w', newline='') as output_file:
        dict_writer = csv.DictWriter(output_file, keys)
        dict_writer.writeheader()
        dict_writer.writerows(data)

# Main function
def main():
    if len(sys.argv) < 3:
        print("Usage: python dmarc_parser.py output.csv input1.xml input2.xml ...")
        sys.exit(1)

    csv_file = sys.argv[1]
    xml_files = sys.argv[2:]
    data = []
    for xml_file in xml_files:
        data.extend(parse_xml(xml_file))
    write_to_csv(data, csv_file)

if __name__ == "__main__":
    main()
