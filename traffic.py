# Modulo de estatistica de trafego POX - Versao 2.0
# Registra informacoes de taxas de transmissao e recepcao de bytes (acumuladas e instantaneas) das portas dos switches
# Formato da estrutura: {switch:{porta:(taxa,dif),porta:(taxa,dif),...},switch:{porta:(taxa,dif),porta:(taxa,dif),...},...}

from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.openflow.of_json import *
from pox.lib.recoco import Timer

log = core.getLogger()

class Traffic(object):

	'''
	Registra a coleta de estatisticas de
	trafego	das portas dos switches
	'''

	def __init__(self,time):
		self.switches = {}		#Lista com informacoes de switches, portas e taxas
		self.time = time		#Tempo entre atualizacoes de estatisticas

		core.openflow.addListenerByName('ConnectionUp',self._handle_ConnectionUp)
		core.openflow.addListenerByName('PortStatsReceived',self._handle_PortStatsReceived)
		Timer(time,self.stats_request,recurring=True)
	
	def _handle_ConnectionUp (self,event):
		self.switches[event.dpid] = {}
		for p in event.ofp.ports:
			self.switches[event.dpid][p.port_no] = (0,0)
		log.info('Identificado switch %d' %event.dpid)

	def _handle_PortStatsReceived(self,event):
		stats = flow_stats_to_list(event.stats)
		for p in event.stats:
			tx,_ = self.switches[event.dpid][p.port_no]
			curtx = p.tx_bytes + p.rx_bytes
			curdif = curtx - tx
			self.switches[event.dpid][p.port_no] = (curtx,curdif)

	def stats_request(self):
		for s in self.switches.keys():
			try:
				core.openflow.getConnection(s).send(of.ofp_stats_request(body=of.ofp_port_stats_request()))
				#log.info('Requisitando estatisticas do switch %d a cada %d segundos' %(s,self.time))
			except:
				log.warning('Sem conexao ao Switch %s... Impossivel coletar estatisticas' %s)

	def view(self):
		for i in self.switches.keys():
			for j in self.switches[i].keys():
				curtx,curdif = self.switches[i][j]
				log.info('Switch: %d - Porta: %d - Tx acu: %d MB - Tx inst: %d MB' %(i,j,curtx/1048576,curdif/1048576))


def launch(time='1'):
	
	'''
	Registra a instancia da classe Traffic que
	coleta estatisticas de trafego dos switches
	'''

	core.registerNew(Traffic,int(time))
	log.info('traffic ready')
