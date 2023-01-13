from flask import Flask, render_template
from flask_table import Table, Col
from scapy.all import *
from scapy.layers.dns import DNS, DNSQR, DNSRR
from datetime import datetime
import threading
import socket


app = Flask(__name__)


class ItemTable(Table):
    timestamp = Col('Time')
    domain = Col('Domain')
    ip = Col('IP Address')


class Init(object):
    def __init__(self, time, domain, ip):
        self.time = time
        self.domain = domain
        self.ip = ip


@app.route('/')
def index():
    return render_template('home.html', table=table, title='DNS Monitoring App')


def sniffer():
    global table
    table = []
    while True:
        sniff(filter="udp and port 53", prn=collect_dns, count=1)


def collect_dns(pkt):
    global table
    
    if DNSQR in pkt and pkt.dport == 53 or DNSRR in pkt and pkt.sport == 53:
        domain = pkt.getlayer(DNS).qd.qname.decode()
        time = datetime.fromtimestamp(pkt.time).strftime('%Y-%m-%d %H:%M:%S')
        ip = socket.gethostbyname(domain)

        # ტერმინალში გამოაქვს შესაბამისი მწკრივები
        # print('Time: ' + str(time) + ', domain: ' + str(domain) + ', source IP: ' + str(ip))
            
        item = Init(time, domain, ip)
        table.append(item)

        if len(table) > 100:
            table.pop(0)


if __name__ == '__main__':
    result = threading.Thread(target=sniffer)
    result.start()
    app.run(debug=True) 