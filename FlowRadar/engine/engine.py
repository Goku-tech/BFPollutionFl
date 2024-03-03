import math
import zlib
import hashlib
import mmh3 #Murmur3 Hash function.
from struct import unpack, pack, calcsize
import bitarray
import struct
import random
import socket
import binascii
import string
import pickle
import timeit
import numpy as np
import sys
import csv
import argparse
from copy import deepcopy
import pandas as pd
import matplotlib.pyplot as plt
from scapy.all import *
from nfstream import NFStreamer
import time
import tracemalloc

try:
	import bitarray
except ImportError:
	raise ImportError('pybloom requires bitarray >= 0.3.4')

__version__ = '1.1'
__author__  = "Jay Baird <jay@mochimedia.com>, Bob Ippolito <bob@redivi.com>,\
			   Marius Eriksen <marius@monkey.org>,\
			   Alex Brasetvik <alex@brasetvik.com>"

data_base = {}
def make_hashfuncs(num_slices, num_bits):

	seeds = [i for i in range(1,num_slices+1)]

	def _make_hashfuncs(key):
		'''
		rval = value obtained after hashing.
		'''
		# if isinstance(key, unicode): #For Python 2.7
		# salt_str=189
		if isinstance(key, str): #For Python 3
			# key=key+str(salt_str))
			key = key.encode('utf-8')
			# print "key : ", key
		else:
			key = str(key)
			# print "key : ", key
		rval = []
		rval.extend(int(abs(mmh3.hash(key, seed))%num_bits) for seed in seeds)
		# print type(rval[0])

		# for salt in salts:
		#     h = salt.copy()
		#     h.update(key)
		#     rval.extend(uint % num_bits for uint in unpack(fmt, h.digest()))
		#     print "rval1", rval
		# print rval[num_slices:]
		del rval[num_slices:]
		return rval
	return _make_hashfuncs

class BloomFilter(object):
	FILE_FMT = '<dQQQQ'
	

	def __init__(self, capacity, error_rate=0.001):
		"""Implements a space-efficient probabilistic data structure
		capacity
			this BloomFilter must be able to store at least *capacity* elements
			while maintaining no more than *error_rate* chance of false
			positives
		error_rate
			the error_rate of the filter returning false positives. This
			determines the filters capacity. Inserting more than capacity
			elements greatly increases the chance of false positives.
		>>> b = BloomFilter(capacity=100000, error_rate=0.001)
		>>> b.add("test")
		False
		>>> "test" in b
		True
		"""
		self.indices = []
		self.insert_index = []
		if not (0 < error_rate < 1):
			raise ValueError("Error_Rate must be between 0 and 1.")
		if not capacity > 0:
			raise ValueError("Capacity must be > 0")
		# given M = num_bits, k = num_slices, p = error_rate, n = capacity
		# solving for m = bits_per_slice
		# n ~= M * ((ln(2) ** 2) / abs(ln(P)))
		# n ~= (k * m) * ((ln(2) ** 2) / abs(ln(P)))
		# m ~= n * abs(ln(P)) / (k * (ln(2) ** 2))
		num_slices = int(math.ceil(math.log(1 / error_rate, 2)))
		# print "No. of hash functions(k): ", num_slices

		# the error_rate constraint assumes a fill rate of 1/2
		# so we double the capacity to simplify the API

		bits_per_slice = int(math.ceil(
			(capacity * abs(math.log(error_rate))) /
			(num_slices * (math.log(2) ** 2))))

		self._setup(error_rate, num_slices, bits_per_slice, capacity, 0)
		self.bitarray = bitarray.bitarray(self.num_bits, endian='little')
		self.bitarray.setall(False)

	def _setup(self, error_rate, num_slices, bits_per_slice, capacity, count):
		self.error_rate = error_rate
		self.num_slices = num_slices
		self.bits_per_slice = bits_per_slice
		self.capacity = capacity
		self.num_bits = num_slices * bits_per_slice
		self.count = count
		self.make_hashes = make_hashfuncs(self.num_slices, self.bits_per_slice)

	def __contains__(self, key):
		"""Tests a key's membership in this bloom filter.
		>>> b = BloomFilter(capacity=100)
		>>> b.add("hello")
		False
		>>> "hello" in b
		True
		"""
		bits_per_slice = self.bits_per_slice
		bitarray = self.bitarray
		if not isinstance(key, list):
			hashes = self.make_hashes(key)
			# print "Hashes: ", hashes
		else:
			hashes = key
			# print "Hashes key: ", hashes
		offset = 0

		for k in hashes:
			if not bitarray[offset + k]:
				return False
			offset += bits_per_slice

		# Return FALSE if atleast one cell is set to 0.
		# Return TRUE if all  the cells are set to 1.(That is item is already present.)
		return True

	def all_bit_unset(self, key):
		"""Returns true only if all the items are pointing to the indices are not set to one."""
		bits_per_slice = self.bits_per_slice
		bitarray = self.bitarray
		if not isinstance(key, list):
			hashes = self.make_hashes(key)
			# print "Hashes: ", hashes
		else:
			hashes = key
			# print "Hashes key: ", hashes
		offset = 0
		ind = []
		bits = []
		for k in hashes:
			bits.append(bitarray[offset + k])
			if bitarray[offset + k]:
				return False
			offset += bits_per_slice
			ind.append(offset + k)
		return True

	def __len__(self):
		"""Return the number of keys stored by this bloom filter."""
		return self.count

	def get_hash_count(self):
		return self.num_slices

	def get_filter_size(self):
		return self.bits_per_slice*self.num_slices

	def copy(self):
		"""Return a copy of this bloom filter.
		"""
		new_filter = BloomFilter(self.capacity, self.error_rate)
		new_filter.bitarray = self.bitarray.copy()
		return new_filter

	def add(self, key, skip_check=False):
		""" Adds a key to this bloom filter. If the key already exists in this
		filter it will return True. Otherwise False.
		"""
		bitarray = self.bitarray
		bits_per_slice = self.bits_per_slice
		hashes = self.make_hashes(key)
		self.indices.append(sorted(hashes))

		# print "Keys: ", key
		# print "Hashes: ", hashes
		if not skip_check and hashes in self:
			return True
		if self.count > self.capacity:
			raise IndexError("BloomFilter is at capacity: ",self.count)
		offset = 0

		for k in hashes:
			self.bitarray[offset + k] = True
			offset += bits_per_slice
			self.insert_index.append(offset + k)
		# print "Insert Index: ", insert_index
		self.count += 1

		return False

	def __or__(self, other):
		return self.union(other)

	def __and__(self, other):
		return self.intersection(other)

	def __getstate__(self):
		d = self.__dict__.copy()
		del d['make_hashes']
		return d

	def __setstate__(self, d):
		self.__dict__.update(d)
		self.make_hashes = make_hashfuncs(self.num_slices, self.bits_per_slice)

map_hex_to_dec = {}

def ip_to_int(ip):
	int_ip = 0
	octets = ip.split(".")

	int_ip = int(octets[0])*(256**3) + int(octets[1])*(256**2) + int(octets[2])*(256**1) + int(octets[3])*(256**0)
	return int_ip

def find_insertion_counts(cap, fpr, hash_count):
	'''This function calculate the number of insertions needed for Optimal and Adversarial senarios.(Will use it later)'''
	# m = float(input("\n\tEnter Filter capacity(m):"))
	# f = float(input("\n\tEnter expected false Positive rate(FPR):"))
	# k = float(input("\n\tEnter number of hash functions used:"))
	m = float(cap)
	f = float(fpr)
	k = float(hash_count)
	print("\nFinding number of insertions needed to achieve {} FPR in optimal case.".format(f))
	n_opt = -m * ((math.log(2))**2 / math.log(f))
	print("{} normal insertions needed.".format(n_opt))

	print("\nFinding number of insertions needed to achieve {} FPR in case of Choosen Insertions.".format(f))
	n_adv = (m/k)*(f**(1/k))
	print("{} choosen insertions needed.".format(n_adv))

	return n_adv, n_opt

def get_absolute_index(f, item):
	ind = []
	offset = 0
	for i in f.make_hashes(item):
		ind.append(i+offset)
		offset += f.bits_per_slice
	return ind

class Flowset(object):
	""" 
	capacity = maximum no. of items to insert
	error_rate = FPR of flow_filter(BloomFilter)
	kc = No. of hash functions in CountingTable
	count_size = No. of cells in the counting table
	"""
	def __init__(self, capacity, error_rate=0.001, kc = 4):
		self.capacity = capacity
		self.kc = kc

		if not (0 < error_rate < 1):
			raise ValueError("Error_Rate must be between 0 and 1.")
		if not capacity > 0:
			raise ValueError("Capacity must be > 0")

		num_slices = int(math.ceil(math.log(1 / error_rate, 2)))
		bits_per_slice = int(math.ceil(
			(capacity * abs(math.log(error_rate))) /
			(num_slices * (math.log(2) ** 2))))

		self._setup(error_rate, num_slices, bits_per_slice, capacity, 0)

		print("engine base bit array size",self.num_bits)
		print("No of BF hash functions",self.num_slices)
		print("bits per slice ",self.bits_per_slice)
		#BloomFilter
		self.flowfilter = bitarray.bitarray(self.num_bits, endian='little')
		self.flowfilter.setall(False)

		#CountingTable: List of List.
		self.flowxor = []

		# for i in range(self.kc * self.count_size):
		for i in range(self.count_size):
			self.flowxor.append('0')

		# Added for debugging purpose.
		self.check_array = self.flowxor.copy()

		self.flowcount = []
		# for i in range(self.kc * self.count_size):
		for i in range(self.count_size):
			self.flowcount.append(0)
		# for i in range(self.kc):
		#     y = []
		#     for j in range(self.count_size):
		#         y.append(0)
			# self.flowcount.append(y)

		self.pktcount = []
		# for i in range(self.kc * self.count_size):
		for i in range(self.count_size):
			self.pktcount.append(0)
		# for i in range(self.kc):
		#     z = []
		#     for j in range(self.count_size):
		#         z.append(0)
		#     self.pktcount.append(z)

	def _setup(self, error_rate, num_slices, bits_per_slice, capacity, count):
		self.error_rate = error_rate
		self.num_slices = num_slices
		self.bits_per_slice = bits_per_slice
		self.capacity = capacity
		self.num_bits = num_slices * bits_per_slice
		self.count = count

		# self.count_cell_size = int(math.log(self.num_bits * 0.8, 2))
		# For counting table
		# self.count_size = int(self.capacity * 0.8) #80% of the total number of expected number of flows(Capacity).
		ck = {} #It is a constant, which is used to decide the size of Counting Table(As per the paper "IBLT")
		ck[3] = 1.222
		ck[4] = 1.295
		ck[5] = 1.425
		ck[6] = 1.570
		ck[7] = 1.721
		print("\n >>> Ck : ", ck[self.kc])
		self.count_size = int(self.capacity * ck[self.kc]) + 10 #Increased capacity
		self.count_per_slice_ct = int(math.floor(self.count_size / self.kc))
		self.make_hashes_ff = make_hashfuncs(self.num_slices, self.bits_per_slice)
		self.make_hashes_ct = make_hashfuncs(self.kc, self.count_per_slice_ct)

	def __contains__(self, key):
		bits_per_slice = self.bits_per_slice
		flowfilter = self.flowfilter
		if not isinstance(key, list):
			hashes = self.make_hashes_ff(key)
			#(print "Hashes: ", hashes)
		else:
			hashes = key
			#(print "Hashes key: ", hashes)
		offset = 0

		for k in hashes:
			if not flowfilter[offset + k]:
				return False
			offset += bits_per_slice

		# Return FALSE if atleast one cell is set to 0.
		# Return TRUE if all  the cells are set to 1.(That is item is already present.)
		return True

	def __len__(self):
		"""Return the number of keys stored by this bloom filter."""
		return self.count

	def do_xor(self, old_value, flow):
		""" update this method to return a dictionary of five tuples.
		Initially the old_value will be zero, if no flow is mapped to the cell."""
		# print("############ DO_XOR(START)#############")
		res = []
		flag = 0
		# print("OLD VALUE: ",old_value, type(old_value))
		# print("FLOW: ",flow, type(flow))

		if old_value == '0' or old_value == ['0', '0', '0', '0', '0']:
			#If the cell is empty. Then simply update the 5-tupe in the cell. No XOR operation needed.
			res = flow

			# print(">>>>#### RES:", flow, res)
			
		else:
			#If the cell is not empty. Read the old value and do the XOR operation on 5-tuples.
			s_ip = (hex(int(old_value[0],16) ^ int(flow[0],16))[2:]).zfill(8)
			d_ip = (hex(int(old_value[1],16) ^ int(flow[1],16))[2:]).zfill(8)
			s_port = hex(int(old_value[2],16) ^ int(flow[2],16)).replace('0x', '')
			d_port = hex(int(old_value[3],16) ^ int(flow[3],16)).replace('0x', '')
			proto = hex(int(old_value[4],16) ^ int(flow[4],16)).replace('0x', '')

			res.append(s_ip)
			res.append(d_ip)
			res.append(s_port)
			res.append(d_port)
			res.append(proto)

		# print("############ DO_XOR(END) #############")

		if res == ['fba6e8e', '29b11ab0', 'd7c7', '50', '6']:
			print(">>>>: ",old_value, flow, res)
			exit(0)
		
		return res
	
	def check_item(self,item):
		"""
		Checks for presence of an item in the flowfilter
		"""
		flowfilter = self.flowfilter

		flow = convert_to_hex(item)
		flow_id = [i for i in flow][0]
		hashes = self.make_hashes_ff(flow_id)
		if hashes in self:
			return True
		return False


	def add_ff(self, key, skip_check=False):
		""" Adds a key to this bloom filter. If the key already exists in this
		filter it will return True. Otherwise False.
		"""
		flowfilter = self.flowfilter
		bits_per_slice = self.bits_per_slice
		hashes = self.make_hashes_ff(key)

		if not skip_check and hashes in self:
			#If the items are present return "True".
			return True
		# if self.count > self.capacity:
		# 	# raise IndexError("BloomFilter is at capacity: ",self.count)
		# 	print("BloomFilter is at capacity: ",self.count)
		offset = 0

		for k in hashes:
			self.flowfilter[offset + k] = True
			
			# print("#### offset, k, offset+k(Flow Filter): ", offset, k, offset+k)
			offset += bits_per_slice

		self.count += 1
		# print("COUNT: ",self.count)

		return False

	def add_ct(self, flow, skip_check=False):
		""" Adds an item in the counting table.
			Updates the Flow Fiter,
			Updates the Flow Count and Packet Count,
			(Add one item at a time.) """

		# check_array = self.flowxor.copy() #used for debugging purpose
		# check_array[index] = (check_array[index], new_flow)

		flow = convert_to_hex(flow)

		# if flow == -1:
		# 	print("IPv6 not supported...!!! add_ct()")
		# 	exit(0)
			
		flow_id = [i for i in flow][0]

		hashes = self.make_hashes_ct(flow_id)

		# if type(flow) is dict:
		#     flow_id = [i for i in flow][0]
		#     print("flow_id: ", flow_id)
		# else:
		#     pass
			
		state = self.add_ff(flow_id)
		if state:
			"""If the item is already present in the Flow Filter. Then increment only pktcount field."""
			# pktcount = self.pktcount
			count_per_slice_ct = self.count_per_slice_ct

			offset = 0

			for k in hashes:
				self.pktcount[offset + k] += 1 

				offset += count_per_slice_ct
				# print("\n CT_INDICES:",offset + k)
				# print(">>>>>(Counting Table Index) offset, k, offset+k: ", offset, k, offset+k)

				"""
				Update the flowxor field structure in the Flowset class(line 391) as well as add_ct():
				Dictionary with keys as:
				1) src_ip
				2) dst_ip
				3) src_port
				4) dst_port
				5) protocol
				"""

		else:
			"""If the item is not present. Then update flowxor and increment flowcount and pktcount fields."""

			pktcount = self.pktcount
			flowcount = self.flowcount
			flowxor = self.flowxor

			#It contains the number of bits in one slice.
			count_per_slice_ct = self.count_per_slice_ct
			offset = 0

			for k in hashes:

				# print(">>>>$$: ", flowxor[offset + k], flow[flow_id])

				#Added this for debugging. 
				# self.check_array[offset + k] = [self.check_array[offset + k], flow[flow_id]]
				if type(self.check_array[offset + k]) == str:
					self.check_array[offset + k] = [self.check_array[offset + k], flow[flow_id]]
				elif type(self.check_array[offset + k]) == list:
					self.check_array[offset + k].append(flow[flow_id])

				self.flowxor[offset + k] = self.do_xor(self.flowxor[offset + k], flow[flow_id])
				self.flowcount[offset + k] += 1 
				self.pktcount[offset + k] += 1 
				# print(">>>>>(Counting Table Index) offset, k, offset+k: ", offset, k, offset+k)
				offset += count_per_slice_ct
				# print("\n CT_INDICES:",offset + k)

		#If the value is already present in the FLOWSET, then return FALSE.

		return False

def convert_to_hex(data):
	"""
		INPUT: Pandas.DataFrame OR list() as input.
		OUTPUT: Disctionary of {"KEY":["SRC_IP_IN_HEX", "DST_IP_IN_HEX", "SRC_PORT_IN_HEX", "DST_PORT_IN_HEX", "PROTO_IN_HEX"]}
		If IP addresses are in IPv6. It gives "-1" as OUTPUT.
		Update:15/10/2022: Now IPv6 is supporting.
	"""

	flow_details = {} # Flow ID to five tuples.
	# print("TYPE: ", type(data), data)
	if(isinstance(data, list)):
		if len(data) == 5:
			if data[0].count('.') == 3 and data[1].count('.') == 3:
				src_ip_str = '{:02x}{:02x}{:02x}{:02x}'.format(*map(int, data[0].split('.')))
				dst_ip_str = '{:02x}{:02x}{:02x}{:02x}'.format(*map(int, data[1].split('.')))
			elif data[0].count(':') == 7 and data[1].count(':') == 7:
				# print("IPv6 not supported as of now.")
				src_ip_str = data[0].replace(":","")
				dst_ip_str = data[1].replace(":","")
			elif data[0].count(':') == 2 and data[1].count(':') == 2:
				# print("IPv6 not supported as of now.")
				src_ip_str = data[0].replace(":","")
				dst_ip_str = data[1].replace(":","")
			else:
				return -1
				#Put a check at the receiving side.
			src_port_str = format(int(data[2]),'x')
			dst_port_str = format(int(data[3]),'x')
			proto_str = format(int(data[4]),'x')
			items = str(src_ip_str)+str(dst_ip_str)+str(src_port_str)+str(dst_port_str)+str(proto_str)
			flow_details[items] = [src_ip_str,dst_ip_str,src_port_str,dst_port_str,proto_str]
	else:
		sip = data['src_ip'].to_list()
		dip = data['dst_ip'].to_list()
		sport = data['src_port'].to_list()
		dport = data['dst_port'].to_list()
		proto = data['protocol'].to_list()

		for row in zip(sip, dip, sport, dport, proto):
			# Only for IPv4
			if row[0].count('.') == 3 and row[1].count('.') == 3:
				src_ip_str = '{:02x}{:02x}{:02x}{:02x}'.format(*map(int, row[0].split('.')))
				dst_ip_str = '{:02x}{:02x}{:02x}{:02x}'.format(*map(int, row[1].split('.')))
			elif ':' in row[0] or ':' in row[0]:
				src_ip_str = src_ip_str.replace(":","")
				dst_ip_str = dst_ip_str.replace(":","")

			src_port_str = format(int(row[2]),'x')
			dst_port_str = format(int(row[3]),'x')
			proto_str = format(int(row[4]),'x')
			items = str(src_ip_str)+str(dst_ip_str)+str(src_port_str)+str(dst_port_str)+str(proto_str)
			flow_details[items] = [src_ip_str,dst_ip_str,src_port_str,dst_port_str,proto_str]

	return flow_details

def hexip_to_decip(hex_ip):
	"""
	This function converts IP in HEX format to a DECIMAL format.
	"""
	if len(hex_ip) <= 8:
		bytes = ["".join(x) for x in zip(*[iter(hex_ip)]*2)]
		bytes = [int(x, 16) for x in bytes]
		int_ip = ".".join(str(x) for x in bytes)
	else:
		int_ip = str(hex_ip[0:4]) +":"+ str(hex_ip[4:8]) +":"+ str(hex_ip[8:12]) +":"+ str(hex_ip[12:16]) +":"+str(hex_ip[16:20]) +":"+\
				str(hex_ip[20:24]) +":"+str(hex_ip[24:28]) +":"+ str(hex_ip[28:32])
	return int_ip

def single_decode(en_flowset):
	"""
	Taking the first pure cell found and reducing the packet count, flow count and Flow filter by it
	"""

	# print("#### Single-Decode Started ####")
	dec_flows = []
	packets = []
	# for i in en_flowset.pktcount:
	# 	packets.append(i)
	for f_set in zip(en_flowset.flowxor, en_flowset.flowcount, en_flowset.pktcount):
		# print("f_set : ",f_set)
		if f_set[1] == 1:
			flow = f_set[0]
			pkt_count = f_set[2]

			# if flow not in dec_flowset:
			#     dec_flowset.append(flow)
			dec_flows.append(flow)

			# if flow == -1:
			# 	print("IPv6 not supported...!!! SingleDecode()")
			# 	exit(0)
			flow_id = "".join(flow) #Joing 5-tuples to make flow_id

			# List of every offset the flow hashes to 
			hashes = en_flowset.make_hashes_ct(flow_id)

			offset = 0

			# print(">>HASHES: ", )
			for h in hashes:

				# print("HASHES: ",h, h+offset, flow)
				# if type(en_flowset.check_array[h+offset]) == list and flow not in en_flowset.check_array[h+offset]:
				# 	print("NO: ", flow,"HASHES: ",hashes, flow)
				# 	input(">>>")
				# 	exit(0)

				en_flowset.flowxor[h + offset] = en_flowset.do_xor(en_flowset.flowxor[h + offset],flow)
				# print("HASHES: ",h, h+offset, en_flowset.flowcount[h + offset], f_set[1], f_set[0])
				# print("HASHES: ",h, h+offset, flow)

				en_flowset.flowcount[h + offset] = en_flowset.flowcount[h + offset] - 1

				en_flowset.pktcount[h + offset] = en_flowset.pktcount[h + offset] - pkt_count

				offset = offset + en_flowset.count_per_slice_ct

	# Returns the flow found and the flowset received after the flow is removedd from it.
	return dec_flows, en_flowset

def CounterDecode(en_flowset,decode_flows,b):
	"""
	To run CounterDecode on the flowlist. The target is to solve Ax = B where B -> Packet counts and A is a binary matrix
	"""
	
	#Creating a zero matrix
	a = [[0 for i in range(len(decode_flows))] for _ in range(en_flowset.count_size)]

	#Filling the binary matrix
	for i in range(len(decode_flows)):
		flow_id = decode_flows[i][0]
		hashes = en_flowset.make_hashes_ct(flow_id)
		offset = 0
		# For every hashed location of the flow, set the value of the flow to 1
		for h in hashes:
			a[offset+h][i] = 1
			offset = offset + en_flowset.count_per_slice_ct
	A = np.array(a)
	B = np.array(b)
	print("Solving linear equations using least squares...")
	start = time.time()

	print("Dimension of A and B: ", A.size, B.size)
	print("Shape of A and B: ", A.shape, B.shape)

	X = np.linalg.lstsq(A, B, rcond=None)[0]
	end = time.time()
	total_time = end - start
	print("Counter Decode Time: "+ str(total_time))

	cd_output = []
	for i in range(len(decode_flows)):
		tmp = list(decode_flows[i])
		tmp.append(X[i])
		cd_output.append(tmp)
	return cd_output

def calculate_fpr(f, inserted_items, non_inserted_items):
	false_positive = 0 #Items present in the filter and item also present while querying it.
	true_negative = 0 #Items not present in the filter and also not present while querying the BloomFilter.
	fpr = 0

	for item in non_inserted_items:
		flow = convert_to_hex(item)
		flow_id = [i for i in flow][0]

		if flow_id in f and flow_id not in inserted_items:
			false_positive += 1
		elif not(flow_id in f) and flow_id not in inserted_items:
			true_negative += 1
	# fpr = float(false_positive / (false_positive + true_negative))
	if false_positive + true_negative > 0:
		fpr = float(float(false_positive) / float(false_positive + true_negative))
	else:
		fpr = 0

	return fpr

def get_fpr(f, cap, items, non_inserted_items):
	insertion_count = 0
	insertions = []
	inserted_items = []
	fpr_per_insertion = []
	true_negative = 0
	false_positive = 0
	trigger = True
	t_fpr = 0

	print("\nTest data(Non Inserted Items) Count: ", len(non_inserted_items))

	for item in items:
		flow = convert_to_hex(item)
		flow_id = [i for i in flow][0]

		if len(f)<cap:
			if not f.add(item): 
				#Only add item if the item is not present in the filter.
				inserted_items.append(item)
			# random.shuffle(non_inserted_items)
			# t_fpr = calculate_fpr(f, inserted_items, non_inserted_items[:cap+1])
			t_fpr = calculate_fpr(f, inserted_items, non_inserted_items)
			fpr_per_insertion.append(t_fpr)
			insertion_count += 1
			insertions.append(insertion_count)

			if t_fpr > EXP_FPR and trigger:
				trigger = False
				print( "Threshold crossed after {} insertions.".format(insertion_count))

	return insertions, fpr_per_insertion

def get_flow_count(file_name):

	unique_flows = []
	# normal_packet = PcapReader(path)
	# while(1):
		# packet = normal_packet.next()
	for packet in PcapReader(file_name):
		if IP in packet and TCP in packet:
			flow = [packet[IP].src, packet[IP].dst, str(packet[TCP].sport), str(packet[TCP].dport), str(packet[IP].proto)]

		elif IP in packet and UDP in packet:
			flow = [packet[IP].src, packet[IP].dst, str(packet[UDP].sport), str(packet[UDP].dport), str(packet[IP].proto)]
			
		elif IP in packet and UDP not in packet and TCP not in packet:
			flow = [packet[IP].src, packet[IP].dst, str("0"), str("0"), str(packet[IP].proto)]
		else:
			continue
					
		hex_flow = convert_to_hex(flow)
		h = list(hex_flow.keys())[0]
		flow.insert(0,h)

		if flow not in unique_flows:
			unique_flows.append(flow)

	# return len(unique_flows), max(pkt_counts), sum(pkt_counts)
	return len(unique_flows), 24527, 887647

def insert_flows(path, mal_flows, per_cent, flowset,filename):
	"""
	To insert flows into the BF
	"""

	fl = flowset
	i = 0
	k=0
	
	#The insertion probability that the flow inserted is malicious
	prob = math.ceil((per_cent/100) * 10000) 
	print("Percentage of Malicious traffic(with packets): ", prob)

	cd_g_truth = {} #Ground Truth for CounterDecode()

	#We are using PcapReader since the pcap files are usually very large
	normal_packet = PcapReader(path)
	# normal_packet = rdpcap(path)


	while(len(mal_flows)>0):
		flow = []
		#Generating a random integer
		rand_int = random.randint(1, 10000) 
		if rand_int > prob: 
			#Send Normal flows from pcap file
			try:
				packet = normal_packet.next()
				# if IP in packet and packet[IP].version == 4 and TCP in packet:
				if IP in packet and TCP in packet:
					flow = [packet[IP].src, packet[IP].dst, str(packet[TCP].sport), str(packet[TCP].dport), str(packet[IP].proto)]
					# print("\nFLOW: ", convert_to_hex(flow).values())
					# print("1) FLOW: ",flow)
					fl.add_ct(flow)

					h = convert_to_hex(flow[0:5]) #We have to send tonly 5 tuple values to the convert_to_hex()
					h = list(h.keys())[0]

					#Creating Ground Truth for COUNTERDECODE
					if h in cd_g_truth.keys():
						cd_g_truth[h][-1] += 1
					else:
						cd_g_truth[h] = flow + [1]
					
					# print(" -->> INSERTED")
					i = i + 1
					# print(i)
				# elif IP in packet and packet[IP].version == 4 and UDP in packet:
				elif IP in packet and UDP in packet:
					flow = [packet[IP].src, packet[IP].dst, str(packet[UDP].sport), str(packet[UDP].dport), str(packet[IP].proto)]
					# print("\nFLOW: ", convert_to_hex(flow).values())
					# print("2) FLOW: ",flow)
					fl.add_ct(flow)

					h = convert_to_hex(flow[0:5]) #We have to send tonly 5 tuple values to the convert_to_hex()
					h = list(h.keys())[0]

					#Creating Ground Truth for COUNTERDECODE
					if h in cd_g_truth.keys():
						# cd_g_truth[h] = cd_g_truth[h] + 1
						cd_g_truth[h][-1] += 1
					else:
						cd_g_truth[h] = flow + [1]
					
					i = i + 1
				
				elif IPv6 in packet and TCP in packet:
					k+=1
					flow = [packet[IPv6].src, packet[IPv6].dst, str(packet[TCP].sport), str(packet[TCP].dport), str(packet[IPv6].nh)]
					# print("\nFLOW: ", convert_to_hex(flow).values())
					# print("2) FLOW: ",flow)
					fl.add_ct(flow)

					h = convert_to_hex(flow[0:5]) #We have to send tonly 5 tuple values to the convert_to_hex()
					h = list(h.keys())[0]

					#Creating Ground Truth for COUNTERDECODE
					if h in cd_g_truth.keys():
						# cd_g_truth[h] = cd_g_truth[h] + 1
						cd_g_truth[h][-1] += 1
					else:
						cd_g_truth[h] = flow + [1]
					
					i = i + 1
				
				elif IPv6 in packet and UDP in packet:
					k+=1
					flow = [packet[IPv6].src, packet[IPv6].dst, str(packet[UDP].sport), str(packet[UDP].dport), str(packet[IPv6].nh)]
					# print("\nFLOW: ", convert_to_hex(flow).values())
					# print("2) FLOW: ",flow)
					fl.add_ct(flow)

					h = convert_to_hex(flow[0:5]) #We have to send tonly 5 tuple values to the convert_to_hex()
					h = list(h.keys())[0]

					#Creating Ground Truth for COUNTERDECODE
					if h in cd_g_truth.keys():
						# cd_g_truth[h] = cd_g_truth[h] + 1
						cd_g_truth[h][-1] += 1
					else:
						cd_g_truth[h] = flow + [1]
					
					i = i + 1

				elif IP in packet and UDP not in packet and TCP not in packet:
					flow = [packet[IP].src, packet[IP].dst, str("0"), str("0"), str(packet[IP].proto)]
					# print("\nFLOW: ", convert_to_hex(flow).values())
					# print("2.1) FLOW: ",flow)
					fl.add_ct(flow)

					h = convert_to_hex(flow[0:5]) #We have to send only 5 tuple values to the convert_to_hex()
					h = list(h.keys())[0]

					#Creating Ground Truth for COUNTERDECODE
					if h in cd_g_truth.keys():
						# cd_g_truth[h] = cd_g_truth[h] + 1
						cd_g_truth[h][-1] += 1
					else:
						# cd_g_truth[h] = 1
						cd_g_truth[h] = flow + [1]
					
					i = i + 1
				
				elif IPv6 in packet and UDP not in packet and TCP not in packet and packet[IPv6].src!='::1':
					k+=1
					flow = [packet[IPv6].src, packet[IPv6].dst, str("0"), str("0"), str(packet[IPv6].nh)]
					fl.add_ct(flow)

					h = convert_to_hex(flow[0:5]) #We have to send only 5 tuple values to the convert_to_hex()
					h = list(h.keys())[0]

					if h in cd_g_truth.keys():
						# cd_g_truth[h] = cd_g_truth[h] + 1
						cd_g_truth[h][-1] += 1
					else:
						# cd_g_truth[h] = 1
						cd_g_truth[h] = flow + [1]
					
					i = i + 1

			except Exception as e:
				#if normal flows are over then break the loop.
				print("Exception CHECKING 1")
				print("Exception: ", e)
				# sys.exit(-1)
				break

		else :
			#Inserting a malicious flows
			a = random.choice(list(mal_flows))
			fl.add_ct(list(a))
			mal_flows[a]-=1
			if mal_flows[a] == 0:
				del mal_flows[a]

	#Inserting the leftover malicious flows
	while len(mal_flows)>0:
		a = random.choice(list(mal_flows))
		fl.add_ct(list(a))
		mal_flows[a]-=1
		if mal_flows[a] == 0:
			del mal_flows[a]
	
	#Inserting the leftover benign flows
	while True:
		flow = []
		try:
			packet = normal_packet.next()
			# if IP in packet and packet[IP].version == 4 and TCP in packet:
			if IP in packet and TCP in packet:
				flow = [packet[IP].src, packet[IP].dst, str(packet[TCP].sport), str(packet[TCP].dport), str(packet[IP].proto)]
				# print("\nFLOW: ", convert_to_hex(flow).values())
				# print("1) FLOW: ",flow)
				fl.add_ct(flow)

				h = convert_to_hex(flow[0:5]) #We have to send tonly 5 tuple values to the convert_to_hex()
				h = list(h.keys())[0]

				#Creating Ground Truth for COUNTERDECODE
				if h in cd_g_truth.keys():
					cd_g_truth[h][-1] += 1
				else:
					cd_g_truth[h] = flow + [1]
				
				# print(" -->> INSERTED")
				i = i + 1
				# print(i)
			# elif IP in packet and packet[IP].version == 4 and UDP in packet:
			elif IP in packet and UDP in packet:
				flow = [packet[IP].src, packet[IP].dst, str(packet[UDP].sport), str(packet[UDP].dport), str(packet[IP].proto)]
				# print("\nFLOW: ", convert_to_hex(flow).values())
				# print("2) FLOW: ",flow)
				fl.add_ct(flow)

				h = convert_to_hex(flow[0:5]) #We have to send tonly 5 tuple values to the convert_to_hex()
				h = list(h.keys())[0]

				#Creating Ground Truth for COUNTERDECODE
				if h in cd_g_truth.keys():
					# cd_g_truth[h] = cd_g_truth[h] + 1
					cd_g_truth[h][-1] += 1
				else:
					cd_g_truth[h] = flow + [1]
				
				i = i + 1
			
			elif IPv6 in packet and TCP in packet:
				k+=1
				flow = [packet[IPv6].src, packet[IPv6].dst, str(packet[TCP].sport), str(packet[TCP].dport), str(packet[IPv6].nh)]
				# print("\nFLOW: ", convert_to_hex(flow).values())
				# print("2) FLOW: ",flow)
				fl.add_ct(flow)

				h = convert_to_hex(flow[0:5]) #We have to send tonly 5 tuple values to the convert_to_hex()
				h = list(h.keys())[0]

				#Creating Ground Truth for COUNTERDECODE
				if h in cd_g_truth.keys():
					# cd_g_truth[h] = cd_g_truth[h] + 1
					cd_g_truth[h][-1] += 1
				else:
					cd_g_truth[h] = flow + [1]
				
				i = i + 1
			
			elif IPv6 in packet and UDP in packet:
				k+=1
				flow = [packet[IPv6].src, packet[IPv6].dst, str(packet[UDP].sport), str(packet[UDP].dport), str(packet[IPv6].nh)]
				# print("\nFLOW: ", convert_to_hex(flow).values())
				# print("2) FLOW: ",flow)
				fl.add_ct(flow)

				h = convert_to_hex(flow[0:5]) #We have to send tonly 5 tuple values to the convert_to_hex()
				h = list(h.keys())[0]

				#Creating Ground Truth for COUNTERDECODE
				if h in cd_g_truth.keys():
					# cd_g_truth[h] = cd_g_truth[h] + 1
					cd_g_truth[h][-1] += 1
				else:
					cd_g_truth[h] = flow + [1]
				
				i = i + 1

			elif IP in packet and UDP not in packet and TCP not in packet:
				flow = [packet[IP].src, packet[IP].dst, str("0"), str("0"), str(packet[IP].proto)]
				# print("\nFLOW: ", convert_to_hex(flow).values())
				# print("2.1) FLOW: ",flow)
				fl.add_ct(flow)

				h = convert_to_hex(flow[0:5]) #We have to send only 5 tuple values to the convert_to_hex()
				h = list(h.keys())[0]

				#Creating Ground Truth for COUNTERDECODE
				if h in cd_g_truth.keys():
					# cd_g_truth[h] = cd_g_truth[h] + 1
					cd_g_truth[h][-1] += 1
				else:
					# cd_g_truth[h] = 1
					cd_g_truth[h] = flow + [1]
				
				i = i + 1
			
			elif IPv6 in packet and UDP not in packet and TCP not in packet and packet[IPv6].src!='::1':
				k+=1
				flow = [packet[IPv6].src, packet[IPv6].dst, str("0"), str("0"), str(packet[IPv6].nh)]
				fl.add_ct(flow)
				h = convert_to_hex(flow[0:5]) #We have to send only 5 tuple values to the convert_to_hex()
				h = list(h.keys())[0]

				if h in cd_g_truth.keys():
					# cd_g_truth[h] = cd_g_truth[h] + 1
					cd_g_truth[h][-1] += 1
				else:
					# cd_g_truth[h] = 1
					cd_g_truth[h] = flow + [1]
				
				i = i + 1

		except Exception as e:
				#if normal flows are over then break the loop.
				print("Exception CHECKING 2")
				print("Exception: ", e)
				# sys.exit(-1)
				break

	
	# Printing some of the debugging parameters
	print("TOTAL INSERTIONS: ",i)
	print("Total IPv6 packets: ",k)
	print("\nWRITING GROUND TRUTH FILE...!!!")

	myFile1 = open(filename, 'w',newline='')
	writer1 = csv.writer(myFile1)
	writer1.writerow(['flow_id','src_ip','dst_ip', 'src_port', 'dst_port', 'protocol','packet_count'])
	for tup in cd_g_truth:
		writer1.writerow([tup] + cd_g_truth[tup])
	myFile1.close()
	return cd_g_truth,fl

def insert_flows_controlled(path, mal_flows, per_cent, flowset,filename,percentage):
	"""
	Same as insert_flows but in here the user can decide the point of insertion of all the flows.
	Once the 'percentage' of benign packets has been inserted, all the malicious packets are inserted,
	before the insertion of benign packets are continued.
	"""
	fl = flowset
	i = 0
	k=0
	prob = math.ceil((per_cent/100) * 10000)
	print("Percentage of Malicious traffic(with packets): ", prob)
	y = 400000/100
	cd_g_truth = {} #Ground Truth for CounterDecode()
	normal_packet = PcapReader(path)
	pkt = 0 # Number of benign packets inserted
	packet = normal_packet.next()
	while True and pkt < y*percentage:
		flow = []
		try:
			pkt+=1
			# if IP in packet and packet[IP].version == 4 and TCP in packet:
			if IP in packet and TCP in packet:
				flow = [packet[IP].src, packet[IP].dst, str(packet[TCP].sport), str(packet[TCP].dport), str(packet[IP].proto)]
				# print("\nFLOW: ", convert_to_hex(flow).values())
				# print("1) FLOW: ",flow)
				fl.add_ct(flow)

				h = convert_to_hex(flow[0:5]) #We have to send tonly 5 tuple values to the convert_to_hex()
				h = list(h.keys())[0]

				#Creating Ground Truth for COUNTERDECODE
				if h in cd_g_truth.keys():
					cd_g_truth[h][-1] += 1
				else:
					cd_g_truth[h] = flow + [1]
				
				# print(" -->> INSERTED")
				i = i + 1
				# print(i)
			# elif IP in packet and packet[IP].version == 4 and UDP in packet:
			elif IP in packet and UDP in packet:
				flow = [packet[IP].src, packet[IP].dst, str(packet[UDP].sport), str(packet[UDP].dport), str(packet[IP].proto)]
				# print("\nFLOW: ", convert_to_hex(flow).values())
				# print("2) FLOW: ",flow)
				fl.add_ct(flow)

				h = convert_to_hex(flow[0:5]) #We have to send tonly 5 tuple values to the convert_to_hex()
				h = list(h.keys())[0]

				#Creating Ground Truth for COUNTERDECODE
				if h in cd_g_truth.keys():
					# cd_g_truth[h] = cd_g_truth[h] + 1
					cd_g_truth[h][-1] += 1
				else:
					cd_g_truth[h] = flow + [1]
				
				i = i + 1
			
			elif IPv6 in packet and TCP in packet:
				k+=1
				flow = [packet[IPv6].src, packet[IPv6].dst, str(packet[TCP].sport), str(packet[TCP].dport), str(packet[IPv6].nh)]
				# print("\nFLOW: ", convert_to_hex(flow).values())
				# print("2) FLOW: ",flow)
				fl.add_ct(flow)

				h = convert_to_hex(flow[0:5]) #We have to send tonly 5 tuple values to the convert_to_hex()
				h = list(h.keys())[0]

				#Creating Ground Truth for COUNTERDECODE
				if h in cd_g_truth.keys():
					# cd_g_truth[h] = cd_g_truth[h] + 1
					cd_g_truth[h][-1] += 1
				else:
					cd_g_truth[h] = flow + [1]
				
				i = i + 1
			
			elif IPv6 in packet and UDP in packet:
				k+=1
				flow = [packet[IPv6].src, packet[IPv6].dst, str(packet[UDP].sport), str(packet[UDP].dport), str(packet[IPv6].nh)]
				# print("\nFLOW: ", convert_to_hex(flow).values())
				# print("2) FLOW: ",flow)
				fl.add_ct(flow)

				h = convert_to_hex(flow[0:5]) #We have to send tonly 5 tuple values to the convert_to_hex()
				h = list(h.keys())[0]

				#Creating Ground Truth for COUNTERDECODE
				if h in cd_g_truth.keys():
					# cd_g_truth[h] = cd_g_truth[h] + 1
					cd_g_truth[h][-1] += 1
				else:
					cd_g_truth[h] = flow + [1]
				
				i = i + 1

			elif IP in packet and UDP not in packet and TCP not in packet:
				flow = [packet[IP].src, packet[IP].dst, str("0"), str("0"), str(packet[IP].proto)]
				# print("\nFLOW: ", convert_to_hex(flow).values())
				# print("2.1) FLOW: ",flow)
				fl.add_ct(flow)

				h = convert_to_hex(flow[0:5]) #We have to send only 5 tuple values to the convert_to_hex()
				h = list(h.keys())[0]

				#Creating Ground Truth for COUNTERDECODE
				if h in cd_g_truth.keys():
					# cd_g_truth[h] = cd_g_truth[h] + 1
					cd_g_truth[h][-1] += 1
				else:
					# cd_g_truth[h] = 1
					cd_g_truth[h] = flow + [1]
				
				i = i + 1
			
			elif IPv6 in packet and UDP not in packet and TCP not in packet:
				k+=1
				flow = [packet[IPv6].src, packet[IPv6].dst, str("0"), str("0"), str(packet[IPv6].nh)]
				fl.add_ct(flow)

				h = convert_to_hex(flow[0:5]) #We have to send only 5 tuple values to the convert_to_hex()
				h = list(h.keys())[0]

				if h in cd_g_truth.keys():
					# cd_g_truth[h] = cd_g_truth[h] + 1
					cd_g_truth[h][-1] += 1
				else:
					# cd_g_truth[h] = 1
					cd_g_truth[h] = flow + [1]
				
				i = i + 1
			packet = normal_packet.next()
			print("packets inserted : ",(pkt/y),"%",end='\r')
		
		except Exception as e:
				#if normal flows are over then break the loop.
				print("Exception: ", e)
				# sys.exit(-1)
				break
	print("packets inserted : ",(pkt/y),"%")

	while len(mal_flows)>0:
		a = random.choice(list(mal_flows))
		fl.add_ct(list(a))
		mal_flows[a]-=1
		if mal_flows[a] == 0:
			del mal_flows[a]
	
	while True:
		flow = []
		try:
			pkt+=1
			# if IP in packet and packet[IP].version == 4 and TCP in packet:
			if IP in packet and TCP in packet:
				flow = [packet[IP].src, packet[IP].dst, str(packet[TCP].sport), str(packet[TCP].dport), str(packet[IP].proto)]
				# print("\nFLOW: ", convert_to_hex(flow).values())
				# print("1) FLOW: ",flow)
				fl.add_ct(flow)

				h = convert_to_hex(flow[0:5]) #We have to send tonly 5 tuple values to the convert_to_hex()
				h = list(h.keys())[0]

				#Creating Ground Truth for COUNTERDECODE
				if h in cd_g_truth.keys():
					cd_g_truth[h][-1] += 1
				else:
					cd_g_truth[h] = flow + [1]
				
				# print(" -->> INSERTED")
				i = i + 1
				# print(i)
			# elif IP in packet and packet[IP].version == 4 and UDP in packet:
			elif IP in packet and UDP in packet:
				flow = [packet[IP].src, packet[IP].dst, str(packet[UDP].sport), str(packet[UDP].dport), str(packet[IP].proto)]
				# print("\nFLOW: ", convert_to_hex(flow).values())
				# print("2) FLOW: ",flow)
				fl.add_ct(flow)

				h = convert_to_hex(flow[0:5]) #We have to send tonly 5 tuple values to the convert_to_hex()
				h = list(h.keys())[0]

				#Creating Ground Truth for COUNTERDECODE
				if h in cd_g_truth.keys():
					# cd_g_truth[h] = cd_g_truth[h] + 1
					cd_g_truth[h][-1] += 1
				else:
					cd_g_truth[h] = flow + [1]
				
				i = i + 1
			
			elif IPv6 in packet and TCP in packet:
				k+=1
				flow = [packet[IPv6].src, packet[IPv6].dst, str(packet[TCP].sport), str(packet[TCP].dport), str(packet[IPv6].nh)]
				# print("\nFLOW: ", convert_to_hex(flow).values())
				# print("2) FLOW: ",flow)
				fl.add_ct(flow)

				h = convert_to_hex(flow[0:5]) #We have to send tonly 5 tuple values to the convert_to_hex()
				h = list(h.keys())[0]

				#Creating Ground Truth for COUNTERDECODE
				if h in cd_g_truth.keys():
					# cd_g_truth[h] = cd_g_truth[h] + 1
					cd_g_truth[h][-1] += 1
				else:
					cd_g_truth[h] = flow + [1]
				
				i = i + 1
			
			elif IPv6 in packet and UDP in packet:
				k+=1
				flow = [packet[IPv6].src, packet[IPv6].dst, str(packet[UDP].sport), str(packet[UDP].dport), str(packet[IPv6].nh)]
				# print("\nFLOW: ", convert_to_hex(flow).values())
				# print("2) FLOW: ",flow)
				fl.add_ct(flow)

				h = convert_to_hex(flow[0:5]) #We have to send tonly 5 tuple values to the convert_to_hex()
				h = list(h.keys())[0]

				#Creating Ground Truth for COUNTERDECODE
				if h in cd_g_truth.keys():
					# cd_g_truth[h] = cd_g_truth[h] + 1
					cd_g_truth[h][-1] += 1
				else:
					cd_g_truth[h] = flow + [1]
				
				i = i + 1

			elif IP in packet and UDP not in packet and TCP not in packet:
				flow = [packet[IP].src, packet[IP].dst, str("0"), str("0"), str(packet[IP].proto)]
				# print("\nFLOW: ", convert_to_hex(flow).values())
				# print("2.1) FLOW: ",flow)
				fl.add_ct(flow)

				h = convert_to_hex(flow[0:5]) #We have to send only 5 tuple values to the convert_to_hex()
				h = list(h.keys())[0]

				#Creating Ground Truth for COUNTERDECODE
				if h in cd_g_truth.keys():
					# cd_g_truth[h] = cd_g_truth[h] + 1
					cd_g_truth[h][-1] += 1
				else:
					# cd_g_truth[h] = 1
					cd_g_truth[h] = flow + [1]
				
				i = i + 1
			
			elif IPv6 in packet and UDP not in packet and TCP not in packet:
				k+=1
				flow = [packet[IPv6].src, packet[IPv6].dst, str("0"), str("0"), str(packet[IPv6].nh)]
				fl.add_ct(flow)

				h = convert_to_hex(flow[0:5]) #We have to send only 5 tuple values to the convert_to_hex()
				h = list(h.keys())[0]

				if h in cd_g_truth.keys():
					# cd_g_truth[h] = cd_g_truth[h] + 1
					cd_g_truth[h][-1] += 1
				else:
					# cd_g_truth[h] = 1
					cd_g_truth[h] = flow + [1]
				
				i = i + 1
			packet = normal_packet.next()
			print("packets inserted : ",(pkt/y),"%",end='\r')
		
		except Exception as e:
				#if normal flows are over then break the loop.
				print("Exception: ", e)
				# sys.exit(-1)
				break
		
	print("packets inserted : ",(pkt/y),"%")


	print("TOTAL INSERTIONS: ",i)
	print("Total IPv6 packets: ",k)
	print("\nWRITING GROUND TRUTH FILE...!!!")

	myFile1 = open(filename, 'w',newline='')
	writer1 = csv.writer(myFile1)
	writer1.writerow(['flow_id','src_ip','dst_ip', 'src_port', 'dst_port', 'protocol','packet_count'])
	for tup in cd_g_truth:
		writer1.writerow([tup] + cd_g_truth[tup])
	myFile1.close()
	return cd_g_truth,fl
############################ SINGLEDECODE() and COUNTERDECODE() ################################
def Decode(encoded_flowset,foldername):
	"""
	Main program controlling singledecode and counterdecode
	"""
	copy_encoded_flowset = copy.deepcopy(encoded_flowset)
	
	# list of decoded flows
	decode_flows = []
	sd_start_time = time.time()

	#list of packet counts in the FlowFilter
	pkt_count_list = []
	for i in encoded_flowset.pktcount:
		pkt_count_list.append(i)
	
	tracemalloc.start()

	#Running Singledecode
	dec_flows, e_fl = single_decode(encoded_flowset)
	decode_flows = decode_flows + dec_flows
	while(1):    
		if e_fl.flowcount.count(1) <= 0: #If pure cells don't exist we break out of single decode
			print("STOPPING SINGLEDECODE...!!!")
			break

		dec_flows, e_fl = single_decode(e_fl)
		decode_flows = decode_flows + dec_flows
		print("\nPure Cell count: ", e_fl.flowcount.count(1))
	sd_stop_time = time.time()
	print("\nSINGLEDECODE finished...!!!", len(decode_flows))
	print("\nSINGLEDECODE time(in sec) :", sd_stop_time - sd_start_time)
	print("\nSINGLEDECODE Memory consumed :",tracemalloc.get_traced_memory())
	tracemalloc.stop()

	print( "Undecode flows: " )
	print( sum(e_fl.flowcount) )
		

	########## Writing the DECODED flows in a csv file ###############
	myFile = open( foldername + 'decode_flows.csv', 'w', newline='' )
	writer = csv.writer(myFile)
	writer.writerow(['flow_id','src_ip','dst_ip', 'src_port', 'dst_port', 'protocol'])
	for data_list in decode_flows:
		data_list[0] = hexip_to_decip(data_list[0])
		data_list[1] = hexip_to_decip(data_list[1])
		data_list[2]= int(data_list[2], 16)
		data_list[3] = int(data_list[3],16)
		data_list[4] = int(data_list[4],16)

		h = convert_to_hex(data_list)

		# print(">>>>>> data_list: ",data_list, h)
		
		data_list.insert(0,list(h.keys())[0])

		writer.writerow(data_list)
	myFile.close()
	print("\n\nSaved the decoded flows in the file 'decode_flows.csv' ...!!!")

	# ############################# COUNTERDECODE() #########################
	tracemalloc.start()
	cd_start_time = time.time()
	final_flows = CounterDecode(copy_encoded_flowset, decode_flows ,pkt_count_list)
	cd_stop_time = time.time()
	print("\nCOUNTERDECODE finished...!!!")
	print("\nCOUNTERDECODE time :", cd_stop_time - cd_start_time)
	print("\n COUNTERDECODE Memory consumed : ",tracemalloc.get_traced_memory())
	tracemalloc.stop()

	myFile = open(foldername+'mal.csv', 'w', newline='')
	writer = csv.writer(myFile)
	writer.writerow(['flow_id','src_ip','dst_ip', 'src_port', 'dst_port', 'protocol', 'packet_count'])
	for data_list in final_flows:
		writer.writerow(data_list)
	myFile.close()
	print("\n\nSaved the decoded flows in the file 'mal.csv' ...!!!")