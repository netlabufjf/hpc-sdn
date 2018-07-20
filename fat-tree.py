#!/usr/bin/python
# Script para criacao de topologia FatTree no Mininet - Versao 2.0

from mininet.net import Mininet
from mininet.node import Controller, RemoteController, OVSController
from mininet.node import CPULimitedHost, Host, Node
from mininet.node import OVSKernelSwitch
from mininet.cli import CLI
from mininet.log import setLogLevel, info
from mininet.link import TCLink
from mininet.util import dumpNodeConnections
import os
import sys

def timer(n):
    for i in range(n):
	os.system("sleep 1")
	sys.stdout.write('.')
	sys.stdout.flush()
    sys.stdout.write('\n')

def myNetwork():

    info('*** Stopping Network Manager\n')
    os.system("stop network-manager")

    n_host = m*((m/2)**(n-1))			# Calculo do numero de hosts
    n_switch = (2*n-1)*((m/2)**(n-1))		# Calculo do numero total de switches
    n_switch_edge = n_host/(m/2)		# Calculo do numero de switches de borda/intermediario
    n_switch_root = n_switch-(n_switch_edge*2)	# Calculo do numero de switches de nucleo
    n_link = (3*(m**3))/4			# Calculo de numero total de links

    net = Mininet(topo=None,
		  build=False,
		  autoSetMacs=True,
		  host=CPULimitedHost,
		  link=TCLink)

    info('*** Adding controller\n')
    c0 = net.addController(name='c0',
			   controller=RemoteController,
			   ip='127.0.0.1',
			   protocol='tcp',
			   port=6633)

    info('*** Adding %d hosts\n' %n_host)
    for i in range(n_host):
    	host = 'h'+str(i+1)
	host = net.addHost(host, cls=Host)
    
    info('*** Adding NFS server\n')
    srv = net.addHost('srv1', cls=Host)		# Adicao do servidor NFS

    info('*** Adding %d switches\n' %n_switch)
    for i in range(n_switch):
    	switch = 's'+str(i+1)
	switch = net.addSwitch(switch, cls=OVSKernelSwitch)

    linkopts = dict(bw=1000,delay='100us',loss=0,max_queue_size=10000,use_htb=True)	# Parametros de links

    info('*** Adding links from hosts to edge switches\n')
    se = n_switch-n_switch_edge+1
    for i in range(n_host):
    	host = 'h'+str(i+1)
	switch_e = 's'+str(se)
	net.addLink(host, switch_e, 0, (i%(m/2))+1, **linkopts)
	#net.addLink(host, switch_e, 0, (i%(m/2))+1)
	if (i%(m/2))==((m/2)-1):
	    se += 1

    info('*** Adding links from intermediate switches to edge switches\n')
    si = n_switch_root+1
    se = n_switch-n_switch_edge+1
    port = (m/2)+1
    for i in range(n_switch_edge):
	switch_i = 's'+str(i+si)
	for j in range(m/2):
	    switch_e = 's'+str(j+se)
	    net.addLink(switch_i, switch_e, j+1, port, **linkopts)
	    #net.addLink(switch_i, switch_e, j+1, port)
	port += 1
	if (i%(m/2))==((m/2)-1):
	    se += (m/2)
	    port = (m/2)+1

    info('*** Adding links from root switches to intermediate switches\n')
    si = n_switch_root+1
    port = (m/2)+1
    for i in range(n_switch_root):
	switch_r = 's'+str(i+1)
	for j in range(m):
	    switch_i = 's'+str((j*(m/2))+si)
	    net.addLink(switch_r, switch_i, j+1, port, **linkopts)
	    #net.addLink(switch_r, switch_i, j+1, port)
	port += 1
	if (i%(m/2))==((m/2)-1):
	    si += 1
	    port = (m/2)+1

    info('*** Adding links from NFS server to root switches\n')
    for i in range(n_switch_root):
	switch_r = 's'+str(i+1)
	net.addLink('srv1', switch_r, i, m+1, **linkopts)
	#net.addLink('srv1', switch_r, i, m+1)

    info('*** Starting network with %d + %d links\n' %(n_link,n_switch_root))
    net.build()

    info('*** Starting controllers\n')
    for controller in net.controllers:
        controller.start()

    info('*** Starting switches\n')
    for switch in net.switches:
	switch.start([c0])
    
    info('*** Restarting NFS and SSH server on srv1\n')
    srv.cmd('service nfs-kernel-server restart')
    srv.cmd('/usr/sbin/sshd')
    
    info('*** Mounting shared directories and restarting SSH servers on hosts ')
    timer(30)
    command = 'mount -t nfs 10.0.0.'+str(n_host+1)+':/root/scratch /home/atavares/scratch &'
    for i in range(n_host):
	host = net.get('h'+str(i+1))
	host.cmd(command)
	host.cmd('/usr/sbin/sshd')
    
    info('*** Post configure switches and hosts\n')
    dumpNodeConnections(net.hosts)

    CLI(net)
    net.stop()

    info('*** Starting Network Manager\n')
    os.system("start network-manager")

    info('*** Killing pending processes\n')
    os.system("killall -9 /usr/sbin/sshd")
    os.system("service nfs-kernel-server stop")
    

if __name__ == '__main__':
    m = int(sys.argv[1])	# Numero de portas dos switches (m-port)
    n = int(sys.argv[2])	# Numero de niveis da FatTree (n-tree)
    setLogLevel('info')
    myNetwork()
