
"""
ross lazarus december 2019 
forked from mateuszk87/PcapViz
changed geoIP lookup to use maxminddb
added reverse DNS lookup and cache with host names added to node labels
added CL parameters to adjust image layout and shapes
"""


from collections import OrderedDict

import networkx
import itertools
from networkx import DiGraph

from scapy.layers.inet import TCP, IP, UDP
from scapy.all import *
from scapy.layers.http import *
import logging

import os
import socket
import maxminddb
import datetime


class GraphManager(object):
	""" Generates and processes the graph based on packets
	"""

	def __init__(self, packets, layer=3, args=None):
		self.graph = DiGraph()
		self.layer = layer
		self.geo_ip = None
		self.args = args
		self.data = {}
		self.deeNS = {} # cache for reverse lookups
		try:
			self.geo_ip = maxminddb.open_database(self.args.geopath) # command line -G
		except:
			logging.warning("could not load GeoIP data from supplied parameter geopath %s" % self.args.geopath)

		if self.layer == 2:
			edges = map(self._layer_2_edge, packets)
		elif self.layer == 3:
			edges = map(self._layer_3_edge, packets)
		elif self.layer == 4:
			edges = map(self._layer_4_edge, packets)
		else:
			raise ValueError("Other layers than 2,3 and 4 are not supported yet!")

		for src, dst, packet in filter(lambda x: not (x is None), edges):
			if src in self.graph and dst in self.graph[src]:
				self.graph[src][dst]['packets'].append(packet)
			else:
				self.graph.add_edge(src, dst)
				self.graph[src][dst]['packets'] = [packet]

		for node in self.graph.nodes():
			self._retrieve_node_info(node)

		for src, dst in self.graph.edges():
			self._retrieve_edge_info(src, dst)

	def resolve_internal_ip(self, ip):
		IP_TO_HOSTNAME = {
			"192.168.1.34": "Host 2 (Init)",
			"192.168.1.35": "Host 1 (AM)",
			"192.168.1.36": "Host 3",
			"192.168.1.37": "Host 4",
			"192.168.1.38": "Host 5",
			"192.168.1.39": "Host 6",
			"192.168.1.40": "Host 7",
			"148.187.111.10": "Login Node", 
			"148.187.111.34": "Host 2 (Init)",
			"148.187.111.35": "Host 1 (AM)",
			"148.187.111.36": "Host 3",
			"148.187.111.37": "Host 4",
			"148.187.111.38": "Host 5",
			"148.187.111.39": "Host 6",
			"148.187.111.40": "Host 7",
		}
		hostname = IP_TO_HOSTNAME.get(ip, None)
		return hostname


	def lookup(self,ip):
		"""deeNS caches all slow! fqdn reverse dns lookups from ip"""
		kname = self.deeNS.get(ip,None)
		if kname == None:
			kname = socket.getfqdn(ip) 
			self.deeNS[ip] = kname
		return (kname)


	def get_in_degree(self, print_stdout=True):
		unsorted_degrees = self.graph.in_degree()
		return self._sorted_results(unsorted_degrees, print_stdout)

	def get_out_degree(self, print_stdout=True):
		unsorted_degrees = self.graph.out_degree()
		return self._sorted_results(unsorted_degrees, print_stdout)

	def _sorted_results(self,unsorted_degrees, print_stdout):
		sorted_degrees = OrderedDict(sorted(list(unsorted_degrees), key=lambda t: t[1], reverse=True))
		for i in sorted_degrees:
			if print_stdout:
				nn = self.lookup(i)
				if (nn == i):
					print(sorted_degrees[i], i)
				else:
					print(sorted_degrees[i],i,nn)
		return sorted_degrees

	def _retrieve_node_info(self, node):
		self.data[node] = {}
		city = None
		country = None
		if self.layer >= 3 and self.geo_ip:
			if self.layer == 3:
				self.data[node]['ip'] = node
			elif self.layer == 4:
				self.data[node]['ip'] = node.split(':')[0]
			node_ip = self.data[node]['ip']
			try:
				mmdbrec = self.geo_ip.get(node_ip)
				if mmdbrec != None:
					countryrec = mmdbrec.get('city',None)
					cityrec = mmdbrec.get('country',None)
					if countryrec: # some records have one but not the other....
						country = countryrec['names'].get(self.args.geolang,None)
					if cityrec:
						city =  cityrec['names'].get(self.args.geolang,None)
				self.data[node]['country'] = country if country else 'private'
				self.data[node]['city'] = city if city else 'private'
			except:
				logging.debug("could not load GeoIP data for node %s" % node_ip)
				# no lookup so not much data available
				#del self.data[node]
				
		#TODO layer 2 info?


	def _retrieve_edge_info(self, src, dst):
		edge = self.graph[src][dst]
		if edge:
			packets = edge['packets']
			edge['layers'] = set(list(itertools.chain(*[set(GraphManager.get_layers(p)) for p in packets])))
			edge['transmitted'] = sum(len(p) for p in packets)
			edge['connections'] = len(packets)

	@staticmethod
	def get_layers(packet):
		return list(GraphManager.expand(packet))

	@staticmethod
	def expand(x):
		yield x.name
		while x.payload:
			x = x.payload
			yield x.name

	@staticmethod
	def _layer_2_edge(packet):
		return packet[0].src, packet[0].dst, packet

	@staticmethod
	def _layer_3_edge(packet):
		if packet.haslayer(IP):
			return packet[1].src, packet[1].dst, packet

	@staticmethod
	def _layer_4_edge(packet):
		if any(map(lambda p: packet.haslayer(p), [TCP, UDP])):
			src = packet[1].src
			dst = packet[1].dst
			_ = packet[2]
			return "%s:%i" % (src, _.sport), "%s:%i" % (dst, _.dport), packet

	def draw(self, filename=None):
		self.graph.label ="Layer %d traffic graph for packets from %s" % (self.layer,str(self.args.pcaps))

		graph = self.get_graphviz_format()

		unique_ips = set()
		for node in self.graph.nodes():
			ip = node.split(':')[0]
			unique_ips.add(ip)

		host_colors = {
			"Host 1": "#F08705",
			"Host 2": "#14969F",
			"Host 3": "#61C6CE",
			"Host 4": "#61C6CE",
			"Host 5": "#61C6CE",
			"Host 6": "#61C6CE",
			"Host 7": "#61C6CE"
		}
		default_color = "gray"
				
		for node in graph.nodes():
			if node not in self.data:
				# node might be deleted, because it's not legit etc.
				continue
			
			snode = str(node)  # Full node address, possibly with a port
			ip_only = snode.split(':')[0]  # Extract just the IP
			port = snode.split(':')[1] if ':' in snode else None  # Extract the port if present

			nnode = self.resolve_internal_ip(ip_only)  # Get the hostname

			# Use the hostname and optionally append the port
			if nnode:
				if port:
					nodelab = f"{nnode}:{port}"  # Show hostname with port
				else:
					nodelab = nnode  # Show hostname only
			else:
				nodelab = snode  # Fallback to the original node (IP + port)

			node_color = default_color
			for host_prefix, color in host_colors.items():
				if nnode and nnode.startswith(host_prefix):
					node_color = color
					break

			node.attr['label'] = nodelab
			node.attr['shape'] = self.args.shape
			node.attr['fontsize'] = '10'
			node.attr['width'] = '0.5'
			node_ip = snode.split(':')[0] 
			node.attr['color'] = node_color
			node.attr['style'] = 'filled,rounded'
		
		# Extract the start time for each edge
		edge_start_times = []
		for edge in graph.edges():
			connection = self.graph[edge[0]][edge[1]]
			if connection['packets']:
				first_packet_time = min(packet.time for packet in connection['packets'])
				edge_start_times.append((edge, first_packet_time))

		# Sort edges based on their start time
		sorted_edges = sorted(edge_start_times, key=lambda x: x[1])

		# Map edges to their order
		edge_order_map = {edge: idx + 1 for idx, (edge, _) in enumerate(sorted_edges)}

		step = 1
		for edge in graph.edges():
			connection = self.graph[edge[0]][edge[1]]

			transmitted = connection['transmitted']
			num_packets = connection['connections']

			edge_order = edge_order_map.get(edge, "N/A")

			if self.args.message_detail == 'full':
				packet_details = []
				for packet in connection['packets']:
					timestamp = float(packet.time)
					capture_time = datetime.datetime.fromtimestamp(timestamp, datetime.timezone.utc).strftime('%H:%M:%S.%f')
					
					# Extract packet type (TCP flags)
					flags = packet[TCP].flags if packet.haslayer(TCP) else None
					flag_desc = []
					if flags:
						if flags & 0x02:
							flag_desc.append("SYN")
						if flags & 0x10:
							flag_desc.append("ACK")
						if flags & 0x01:
							flag_desc.append("FIN")
						if flags & 0x08:
							flag_desc.append("PSH")
						if flags & 0x04:
							flag_desc.append("RST")
					packet_type = "|".join(flag_desc) if flag_desc else "DATA"
					
					size = len(packet)
					packet_details.append(f"{packet_type}, {capture_time}, {size} bytes")
				
				if edge_order%2 == 1:
					edge_label = f" Step {step}    \n {num_packets} packets    \n {transmitted} bytes    \n"
					step = step + 1
				else:
					edge_label = f"{num_packets} packets    \n {transmitted} bytes    \n"
				edge_label += "\n".join(packet_details)

			elif self.args.message_detail == 'summary':
				if edge_order%2 == 1:
					edge_label = f" Step {step}    \n {num_packets} packets    \n {transmitted} bytes    \n"
					step = step + 1
				else:
					edge_label = f"{num_packets} packets    \n {transmitted} bytes    \n"

			# Show initiating edges in red	
			if edge_order%2 == 1:
				edge.attr['color'] = 'red'

			edge.attr['label'] = edge_label
			edge.attr['fontsize'] = '8'
			edge.attr['minlen'] = '2'
			edge.attr['penwidth'] = min(max(0.05, connection['connections'] * 1.0 / len(self.graph.nodes())), 2.0)

		graph.layout(prog=self.args.layoutengine)
		graph.draw(filename)

	def get_graphviz_format(self, filename=None):
		agraph = networkx.drawing.nx_agraph.to_agraph(self.graph)
		# remove packet information (blows up file size)
		for edge in agraph.edges():
			del edge.attr['packets']
		if filename:
			agraph.write(filename)
		return agraph
