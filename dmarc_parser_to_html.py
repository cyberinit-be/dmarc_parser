import sys
import matplotlib
matplotlib.use('agg')
from defusedxml.ElementTree import parse as ET_parse
import csv
import os
import datetime
import jinja2
import matplotlib.pyplot as plt
import matplotlib.text as mtext
import io
import base64

def parse_xml(xml_file):
    tree = ET_parse(xml_file)
    root = tree.getroot()
    data = []

    date_range = root.find('.//date_range')
    begin_timestamp = int(find_text(date_range, './/begin'))
    end_timestamp = int(find_text(date_range, './/end'))
    begin_date = datetime.datetime.fromtimestamp(begin_timestamp).strftime('%d/%m/%Y')
    end_date = datetime.datetime.fromtimestamp(end_timestamp).strftime('%d/%m/%Y')

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

        dkim_result = None
        if dkim_auths:
            dkim_auth = dkim_auths[0]
            row['dkim_domain'] = find_text(dkim_auth, './/domain')
            row['dkim_selector'] = find_text(dkim_auth, './/selector')
            dkim_result = find_text(dkim_auth, './/result')
        else:
            row['dkim_domain'] = ''
            row['dkim_selector'] = ''

        if dkim_result is None:
            dkim_result = row['dkim']

        row['dkim_result'] = dkim_result

        if spf_auths:
            spf_auth = spf_auths[0]
            row['spf_domain'] = find_text(spf_auth, './/domain')
            row['spf_scope'] = find_text(spf_auth, './/scope', default='')
            row['spf_result'] = find_text(spf_auth, './/result')
        else:
            row['spf_domain'] = ''
            row['spf_scope'] = ''
            row['spf_result'] = row['spf']

        row['filename'] = filename
        data.append(row)

    return data

def find_text(element, path, default=''):
    elem = element.find(path)
    return elem.text if elem is not None else default

def read_csv(csv_file):
    data = []
    try:
        with open(csv_file, 'r', newline='') as input_file:
            reader = csv.DictReader(input_file)
            for row in reader:
                data.append(row)
    except FileNotFoundError:
        pass
    return data


def write_to_csv(data, csv_file):
    keys = data[0].keys()
    with open(csv_file, 'a', newline='') as output_file:
        dict_writer = csv.DictWriter(output_file, keys)

        # Write the header only if the file is empty or does not exist
        if os.path.getsize(csv_file) == 0 or not os.path.exists(csv_file):
            dict_writer.writeheader()

        dict_writer.writerows(data)



def generate_pie_chart(results, title, result_type):
    labels = ['Pass', 'Fail', 'Softfail', 'None']
    sizes = [results['pass'], results['fail'], results['softfail'], results['none']]
    colors = ['#5cb85c', '#d9534f', '#f0ad4e', '#5bc0de']

    fig, ax = plt.subplots()
    ax.pie(sizes, labels=labels, colors=colors, autopct='%1.1f%%')
    ax.axis('equal')
    ax.set_title(title)

    fail_text = f'Failed: {results["fail"]}\nSoftfailed: {results["softfail"]}'
    ax.text(0.6, 0.6, fail_text, transform=ax.transAxes, fontsize=14, bbox=dict(facecolor='white', alpha=0.5))

    buf = io.BytesIO()
    plt.savefig(buf, format='png')
    plt.close(fig)
    buf.seek(0)
    return buf


def main():
    if len(sys.argv) < 3:
        print("Usage: python dmarc_parser.py output.csv input1.xml [input2.xml ...]")
        sys.exit(1)

    csv_file = sys.argv[1]
    xml_files = sys.argv[2:]

    data = []
    dkim_results = {'pass': 0, 'fail': 0, 'softfail': 0, 'none': 0}
    spf_results = {'pass': 0, 'fail': 0, 'softfail': 0, 'none': 0}


    template_string = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>DMARC Report</title>
    <style>
        table {
            width: 100%;
            border-collapse: collapse;
        }
        th, td {
            padding: 8px;
            text-align: left;
            border-bottom: 1px solid #ddd;
        }
        th {
            background-color: #f2f2f2;
        }
    </style>
</head>
<body>
    <h1>DMARC Report</h1>
    <br>
    <div>
        <img src="{{ dkim_chart }}" alt="DKIM Results" style="width: 45%;">
        <img src="{{ spf_chart }}" alt="SPF Results" style="width: 45%; float: right;">
    </div>
    <br>
    <table>
        <thead>
            <tr>
                <th>Begin Date</th>
                <th>End Date</th>
                <th>Source IP</th>
                <th>Count</th>
                <th>Disposition</th>
                <th>DKIM</th>
                <th>SPF</th>
                <th>Header From</th>
                <th>Envelope From</th>
                <th>Envelope To</th>
                <th>DKIM Domain</th>
                <th>DKIM Selector</th>
                <th>DKIM Result</th>
                <th>SPF Domain</th>
                <th>SPF Scope</th>
                <th>SPF Result</th>
                <th>Filename</th>
            </tr>
        </thead>
        <tbody>
            {% for row in data %}
            <tr>
                <td>{{ row.begin_date }}</td>
                <td>{{ row.end_date }}</td>
                <td>{{ row.source_ip }}</td>
                <td>{{ row.count }}</td>
                <td>{{ row.disposition }}</td>
                <td>{{ row.dkim }}</td>
                <td>{{ row.spf }}</td>
                <td>{{ row.header_from }}</td>
                <td>{{ row.envelope_from }}</td>
                <td>{{ row.envelope_to }}</td>
                <td>{{ row.dkim_domain }}</td>
                <td>{{ row.dkim_selector }}</td>
                <td>{{ row.dkim_result }}</td>
                <td>{{ row.spf_domain }}</td>
                <td>{{ row.spf_scope }}</td>
                <td>{{ row.spf_result }}</td>
                <td>{{ row.filename }}</td>
            </tr>
            {% endfor %}
        </tbody>
    </table>

</body>
</html>
'''


    # Read existing data from CSV file
    existing_data = read_csv(csv_file)

    for xml_file in xml_files:
        file_data = parse_xml(xml_file)
        data.extend(file_data)

        for row in file_data:
            dkim_result = row.get('dkim_result', 'none')
            dkim_results[dkim_result] += int(row['count'])

            spf_result = row.get('spf_result', 'none')
            spf_results[spf_result] += int(row['count'])

    # Update data list with existing data from CSV file
    data.extend(existing_data)

    # Update dkim_results and spf_results with data from CSV file
    for row in existing_data:
        dkim_result = row.get('dkim_result', 'none')
        dkim_results[dkim_result] += int(row['count'])

        spf_result = row.get('spf_result', 'none')
        spf_results[spf_result] += int(row['count'])

    # Write data to CSV file
    write_to_csv(data, csv_file)

    # Generate pie charts as in-memory images
    dkim_chart = generate_pie_chart(dkim_results, 'DKIM Results', 'dkim')
    spf_chart = generate_pie_chart(spf_results, 'SPF Results', 'spf')

    # Encode the in-memory images as base64 strings
    dkim_chart_base64 = base64.b64encode(dkim_chart.read()).decode('utf-8')
    spf_chart_base64 = base64.b64encode(spf_chart.read()).decode('utf-8')

    # Generate HTML report with embedded images
    template_env = jinja2.Environment(autoescape=True)
    template = template_env.from_string(template_string)
    html_content = template.render(data=data, dkim_chart='data:image/png;base64,' + dkim_chart_base64, spf_chart='data:image/png;base64,' + spf_chart_base64)

    with open('report.html', 'w') as html_file:
        html_file.write(html_content)

    print(f"CSV saved to {csv_file}")
    print("HTML report saved to report.html")

if __name__ == "__main__":
    main()
