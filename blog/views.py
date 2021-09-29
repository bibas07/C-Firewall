import scapy
from django.contrib.auth.models import User
from scapy.data import PPI_TYPES
from blog import models
from os import cpu_count, posix_fadvise, uname
import re
from scapy.all import ARP, Ether, srp, arping
from django.http import request
from django import forms
from django.forms.utils import pretty_name
from django.http.response import HttpResponse
from django.shortcuts import render, redirect
from django.contrib import messages
from django.contrib.auth.decorators import login_required
import subprocess
import psutil
import platform
from datetime import date, datetime
import sys
import socket
import select
import random
from itertools import cycle
import os
from . import forms
# Create your views here.
def home(request):
    context = {
        'title':'Firewall Project',
    }
    return render(request, 'blog/home.html',context)

@login_required
def services(request):
    context = {
        'title':'C-Firewall Services',
    }
    return render(request, 'blog/services.html',context)

#navbar port option all about ufw
@login_required
def port_allow(request):
    if request.method == 'POST' and 'port-allow' in request.POST:
        form = forms.PortForm(request.POST)
        if form.is_valid():
            port_number = form.cleaned_data['port']
            start = subprocess.run(["sudo","ufw",'allow','{}' .format(port_number)], capture_output=True)
            messages.success(request,'{} has been opened into your system \n {}' .format(port_number, start))
            return redirect('port-allow')
    elif request.method == 'POST' and 'port-deny' in request.POST:
        form = forms.PortForm(request.POST)
        if form.is_valid():
            port_number = form.cleaned_data['port']
            start = subprocess.run(["sudo","ufw","deny",'{}'.format(port_number)], capture_output=True)
            messages.success(request,'{} has been disabled from your system' .format(port_number))
            return redirect('port-allow')
    else:
        form = forms.PortForm()
    return render(request, 'blog/port.html', {'title':'Port Configuration', 'form':form})

def port_reset(request):
    start = subprocess.run(["sudo","ufw","reset"], capture_output=True)
    messages.success(request,'UFW has been reset and set inactive')
    return redirect('port-allow')

def port_enable(request):
    start = subprocess.run(["sudo","ufw","enable"], capture_output=True)
    messages.success(request,'UFW has been enable')
    return redirect('port-allow')

def port_disable(request):
    start = subprocess.run(["sudo","ufw","disable"], capture_output=True)
    messages.success(request,'UFW has been disable/inactive')
    return redirect('port-allow')

#option from the navbar
def options_screen(request):
    return render(request, 'blog/options.html')

#System information
''' using psutil to get system information '''
@login_required
def show_system_information(request, suffix="B"):
    uname = platform.uname()
    boot_timestamp = psutil.boot_time()
    boot_time = datetime.fromtimestamp(boot_timestamp)
    physical_core = psutil.cpu_count(logical=False)
    total_core = psutil.cpu_count(logical=True)
    cpufreq = psutil.cpu_freq()
    meminfo = psutil.virtual_memory()

    context = {
        'uname':uname,
        'boot_time':boot_time,
        'physical_core':physical_core,
        'total_core': total_core,
        'cpufreq':cpufreq,
        'meminfo':meminfo,

    }
    return render(request, 'blog/information.html', context)

''' IP Address is manually set for test purpose only'''
@login_required
def connected_devices(request):
    target_ip = "192.168.100.0/24"
    # IP Address for the destination
    # create ARP packet
    arp = ARP(pdst=target_ip)
    # create the Ether broadcast packet
    # ff:ff:ff:ff:ff:ff MAC address indicates broadcasting
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    # stack them
    packet = ether/arp
    try:
        result = srp(packet, timeout=3, verbose=False)[0]
        result.summary()
        print(result)
    except PermissionError:
        messages.info(request, '[Connected Devices] Permission Denied')
        return redirect('options')
    # a list of clients, we will fill this in the upcoming loop
    clients = []
    for sent, received in result:
        # for each response, append ip and mac address to `clients` list
        clients.append({'ip': received.psrc, 'mac': received.hwsrc})
    for client in clients:
        client_ip = client['ip']
        client_mac = client['mac']

    return render(request, 'blog/connected_device.html', {'client_ip':client_ip, 'client_mac':client_mac})

#Load Balancing

SERVER_POOL = [('10.157.0.238', 8888)]
ITER = cycle(SERVER_POOL)
def round_robin(iter):
    # round_robin([A, B, C, D]) --> A B C D A B C D A B C D ...
    return next(iter)

class LoadBalancer(object):
    """ Socket implementation of a load balancer.
    Flow Diagram:
    +---------------+      +-----------------------------------------+      +---------------+
    | client socket | <==> | client-side socket | server-side socket | <==> | server socket |
    |   <client>    |      |          < load balancer >              |      |    <server>   |
    +---------------+      +-----------------------------------------+      +---------------+
    Attributes:
        ip (str): virtual server's ip; client-side socket's ip
        port (int): virtual server's port; client-side socket's port
        algorithm (str): algorithm used to select a server
        flow_table (dict): mapping of client socket obj <==> server-side socket obj
        sockets (list): current connected and open socket obj
    """
    flow_table = dict()
    sockets = list()
    def __init__(self, ip, port, algorithm='random'):
        self.ip = ip
        self.port = port
        self.algorithm = algorithm
        # init a client-side socket
        self.cs_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # the SO_REUSEADDR flag tells the kernel to reuse a local socket in TIME_WAIT state,
        # without waiting for its natural timeout to expire.
        self.cs_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.cs_socket.bind((self.ip, self.port))
        print ('init client-side socket: %s' % (self.cs_socket.getsockname(),))
        self.cs_socket.listen(10) # max connections
        self.sockets.append(self.cs_socket)
    def start(self):
        while True:
            read_list, write_list, exception_list = select.select(self.sockets, [], [])
            for sock in read_list:
                # new connection
                if sock == self.cs_socket:
                    print ('='*40+'flow start'+'='*39)
                    self.on_accept()
                    break
                # incoming message from a client socket
                else:
                    try:
                        # In Windows, sometimes when a TCP program closes abruptly,
                        # a "Connection reset by peer" exception will be thrown
                        data = sock.recv(4096) # buffer size: 2^n
                        if data:
                            self.on_recv(sock, data)
                        else:
                            self.on_close(sock)
                            break
                    except:
                        sock.on_close(sock)
                        break
    def on_accept(self):
        client_socket, client_addr = self.cs_socket.accept()
        print ('client connected: %s <==> %s' % (client_addr, self.cs_socket.getsockname()))
        # select a server that forwards packets to
        server_ip, server_port = self.select_server(SERVER_POOL, self.algorithm)
        # init a server-side socket
        ss_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            ss_socket.connect((server_ip, server_port))
            print ('init server-side socket: %s' % (ss_socket.getsockname(),))
            print ('server connected: %s <==> %s' % (ss_socket.getsockname(),(socket.gethostbyname(server_ip), server_port)))
        except:
            print ("Can't establish connection with remote server, err: %s" % sys.exc_info()[0])
            print ("Closing connection with client socket %s" % (client_addr,))
            client_socket.close()
            return
        self.sockets.append(client_socket)
        self.sockets.append(ss_socket)
        self.flow_table[client_socket] = ss_socket
        self.flow_table[ss_socket] = client_socket
    def on_recv(self, sock, data):
        print ('recving packets: %-20s ==> %-20s, data: %s' % (sock.getpeername(), sock.getsockname(), [data]))
        # data can be modified before forwarding to server
        # lots of add-on features can be added here
        remote_socket = self.flow_table[sock]
        remote_socket.send(data)
        print ('sending packets: %-20s ==> %-20s, data: %s' % (remote_socket.getsockname(), remote_socket.getpeername(), [data]))
    def on_close(self, sock):
        print ('client %s has disconnected' % (sock.getpeername(),))
        print ('='*41+'flow end'+'='*40)
        ss_socket = self.flow_table[sock]
        self.sockets.remove(sock)
        self.sockets.remove(ss_socket)
        sock.close()  # close connection with client
        ss_socket.close()  # close connection with server
        del self.flow_table[sock]
        del self.flow_table[ss_socket]
    def select_server(self, server_list, algorithm):
        if algorithm == 'random':
            return random.choice(server_list)
        elif algorithm == 'round robin':
            return round_robin(ITER)
        else:
            raise Exception('unknown algorithm: %s' % algorithm)

@login_required
def start_LoadBalancer(request):
    try:
        LoadBalancer('localhost', 5555, 'round robin').start()
        messages.success(request, 'Load Balancer Started successfully')
    except OSError:
        messages.info(request, "Load Balancing has been stopped.")
        return redirect('options')
    return render(request, 'blog/load_balancer.html')

@login_required
def maltrail_home(request):
    return render(request, 'blog/maltrail.html')

def run_superuser(request):
    run = subprocess.run(['sudo','su'], capture_output=True)
    return redirect('maltrail')
def maltrail_server(request):
    start_server = subprocess.run(["python3","../maltrail/server.py","python3","../maltrail/sensor.py"], capture_output=True)
    # start = subprocess.run(["python3","../maltrail/sensor.py",], capture_output=True)
    messages.success(request,'Maltrail Server started')
    return render(request,'blog/maltrail_server.html')

def maltrail_sensor(request):
    start = subprocess.run(["python3","../maltrail/sensor.py",], capture_output=True)
    messages.success(request,'Maltrail Sensor Started')
    return render(request,'blog/maltrail_sensor.html')

#IP BLACKLIST FROM THE OPTIONS NAVBAR
def ip_blacklist_form(request):
    form = forms.BlacklistForm()
    if request.method == 'POST':
        form = forms.BlacklistForm(request.POST)
        if form.is_valid():
            ip_addr = form.cleaned_data['ip_address']
            if len(ip_addr) != 0:
                cmd = "sudo iptables -I INPUT -s {0} -j DROP".format(ip_addr)
                result = subprocess.Popen(cmd, stdout=subprocess.PIPE, shell=True,universal_newlines=True)
                (output, err) = result.communicate()
                result_status = result.wait()
                if result:
                    form.save()
                    messages.success(request, '{0} has been listed in blacklist'.format(ip_addr))
                    return redirect('ip-blacklist-form')
            else:
                messages.error(request, 'Please enter IP Address')
    else:
        form = forms.BlacklistForm()
    return render(request, 'blog/ip_blacklist.html', {'form':form})

def ip_blacklist_logs(request):
    context = {   
    }
    return render(request, 'blog/ip_blacklist.html',{'blacklisted': models.Blacklist.objects.filter('ip_address')})

#IP WHITELIST FROM THE OPTIONS NAVBAR
def ip_whitelist_form(request):
    INIT_CMDS = ["sudo iptables -F",#clean all
    "sudo iptables -X",
    "sudo iptables -t nat -F",
    "sudo iptables -t nat -X",
    "sudo iptables -P INPUT DROP",#forbid all
    "sudo iptables -A INPUT -i lo -j ACCEPT"#accept all localhost
    ]
    
    #INPUT: local(DPORT) <- remote(SPORT)
    #remote port service can access
    INPUT_ALLOWED_UDP_SPORTS = [53]#DNS,
    INPUT_ALLOWED_TCP_SPORTS = [80,443,#http,https,
    5222,5223,#xmpp
    1352,#lotusnote
    22,#ssh
    3389,#xrdp
    ]
    #local port service can be access
    INPUT_ALLOWED_TCP_DPORTS = [22,3389]#ssh,xrdp,
    INPUT_ALLOWED_IP = ["192.168.0.0/24",#your full access ip
        ]
    form = forms.WhitelistForm()
    if request.method == 'POST':
        form = forms.WhitelistForm(request.POST)
        if form.is_valid():
            ip_addr = form.cleaned_data['ip_address']
            cmd = "sudo iptables -A INPUT -s {} -j ACCEPT".format(ip_addr)
            result = subprocess.Popen(cmd, stdout=subprocess.PIPE, shell=True,universal_newlines=True)
            (output, err) = result.communicate()
            result_status = result.wait()
            dry_run= False
            for reset_cmd in INIT_CMDS:
                if not dry_run:
                    result = subprocess.Popen(reset_cmd, stdout=subprocess.PIPE, shell=True,universal_newlines=True)
                    (output, err) = result.communicate()
                    result_status = result.wait()
            for port in INPUT_ALLOWED_UDP_SPORTS:
                if not dry_run:
                    cmd2 = "sudo iptables -A INPUT -p udp --sport %d -j ACCEPT"%(port)
                    result = subprocess.Popen(cmd2, stdout=subprocess.PIPE, shell=True,universal_newlines=True)
            for port in INPUT_ALLOWED_TCP_SPORTS:
                if not dry_run:
                    cmd2 = "sudo iptables -A INPUT -p tcp --sport %d -j ACCEPT"%(port)
                    result = subprocess.Popen(cmd2, stdout=subprocess.PIPE, shell=True,universal_newlines=True)
                    (output, err) = result.communicate()
                    result_status = result.wait()
            for port in INPUT_ALLOWED_TCP_DPORTS:
                if not dry_run:
                    cmd2 = "sudo iptables -A INPUT -p tcp --dport %d -j ACCEPT"%(port)
                    result = subprocess.Popen(cmd2, stdout=subprocess.PIPE, shell=True,universal_newlines=True)
                    (output, err) = result.communicate()
                    result_status = result.wait()
            for ip in INPUT_ALLOWED_IP:
                if not dry_run:
                    cmd2 = "sudo iptables -A INPUT -s %s -j ACCEPT"%(ip)
                    result = subprocess.Popen(cmd2, stdout=subprocess.PIPE, shell=True,universal_newlines=True)
                    (output, err) = result.communicate()
                    result_status = result.wait()
            form.save()
            
            messages.success(request,'{} has been whitelisted'.format(ip_addr))
            return redirect('ip-whitelist-form')
    else:
        form = forms.WhitelistForm()
    return render(request, 'blog/ip_whitelist.html',{'title':'IP Whitelist', 'form':form})
