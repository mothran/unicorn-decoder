#!/usr/bin/python
import sys
from unicorn import *
from unicorn.x86_const import *
from capstone import *
import argparse

class SimpleEngine:
	def __init__(self, mode):
		if mode == '32':
			cur_mode = CS_MODE_32
		elif mode == '16':
			cur_mode = CS_MODE_16
		else:
			cur_mode = CS_MODE_64

		self.capmd = Cs(CS_ARCH_X86, cur_mode)

	def disas_single(self, data, addr):
		for i in self.capmd.disasm(data, addr):
			print("  0x%x:\t%s\t%s" % (i.address, i.mnemonic, i.op_str))
			break

	def disas_all(self, data, addr):
		for i in self.capmd.disasm(data, addr):
			print("  0x%x:\t%s\t%s" % (i.address, i.mnemonic, i.op_str))

# globals for the hooks
write_bounds = [None, None]

def mem_reader(uc, addr, size):
	tmp = uc.mem_read(addr, size)

	for i in tmp:
		print("   0x%x" % i),
	print("")

# bail out on INT 0x3 (0xCC)
def hook_intr(uc, intno, user_data):
	if intno == 0x3:
		return False;
	else:
		return True

def hook_mem_invalid(uc, access, address, size, value, user_data):
	eip = uc.reg_read(UC_X86_REG_EIP)

	if access == UC_MEM_WRITE:
		print("invalid WRITE of 0x%x at 0x%X, data size = %u, data value = 0x%x" % (address, eip, size, value))
	if access == UC_MEM_READ:
		print("invalid READ of 0x%x at 0x%X, data size = %u" % (address, eip, size))

	return False

def hook_smc_check(uc, access, address, size, value, user_data):
	SMC_BOUND = 0x200
	eip = uc.reg_read(UC_X86_REG_EIP)

	# Just check if the write target addr is near EIP
	if abs(eip - address) < SMC_BOUND:
		if write_bounds[0] == None:
			write_bounds[0] = address
			write_bounds[1] = address
		elif address < write_bounds[0]:
			write_bounds[0] = address
		elif address > write_bounds[1]:
			write_bounds[1] = address

def hook_mem_read(uc, access, address, size, value, user_data):
	print("mem READ:  0x%x, data size = %u, data value = 0x%x" % (address, size, value))
	print("Printing near deref:")
	mem_reader(uc, address, 32)

	return True

def hook_code(uc, addr, size, user_data):
	mem = uc.mem_read(addr, size)
	uc.disasm.disas_single(str(mem), addr)
	return True

# Using new JIT blocks as a heuristic could really add to the simple SMC system if implemented correctly.
# TODO: attempt to make a new-block based heuristic, I am thinking repeated addresses / size of blocks, 
# maybe even disasm them and poke around.

def main():
	parser = argparse.ArgumentParser(description='Decode supplied x86 / x64 shellcode automatically with the unicorn engine')
	parser.add_argument('-f', dest='file', help='file to shellcode binary file', required=True, type=file)
	parser.add_argument('-m', dest='mode', help='mode of the emulator (16|32|64)', required=False, default="32")
	parser.add_argument('-i', dest='max_instruction', help='max instructions to emulate', required=False)
	parser.add_argument('-d', dest='debug', help='Enable extra hooks for debugging of shellcode', required=False, default=False, action='store_true')

	args = parser.parse_args()

	bin_code = args.file.read()
	disas_engine = SimpleEngine(args.mode)

	if args.mode == "32":
		cur_mode = UC_MODE_32
	elif args.mode == "16":
		cur_mode = UC_MODE_16
	else:
		cur_mode = UC_MODE_64

	PAGE_SIZE = 2 * 1024 * 1024
	START_RIP = 0x0

	# setup engine and write the memory there.
	emu = Uc(UC_ARCH_X86, cur_mode)
	emu.disasm = disas_engine # python is silly but it works.
	emu.mem_map(0, PAGE_SIZE)
	# write machine code to be emulated to memory
	emu.mem_write(START_RIP, bin_code)

	# write a INT 0x3 near the end of the code blob to make sure emulation ends
	emu.mem_write(len(bin_code) + 0xff, "\xcc\xcc\xcc\xcc")

	emu.hook_add(UC_HOOK_MEM_INVALID, hook_mem_invalid)
	emu.hook_add(UC_HOOK_MEM_WRITE, hook_smc_check)
	emu.hook_add(UC_HOOK_INTR, hook_intr)
	
	if args.debug:
		emu.hook_add(UC_HOOK_MEM_READ, hook_mem_read)
		emu.hook_add(UC_HOOK_CODE, hook_code)

	# arbitrary address for ESP.
	emu.reg_write(UC_X86_REG_ESP, 0x2000)

	if args.max_instruction:
		end_addr = -1
	else:
		args.max_instruction = 0x1000
		end_addr = len(bin_code)

	try: 
		emu.emu_start(START_RIP, end_addr, 0, int(args.max_instruction))
	except UcError as e:
		print("ERROR: %s" % e)

	if write_bounds[0] != None:
		print("Shellcode address ranges:")
		print("   low:  0x%X" % write_bounds[0])
		print("   high: 0x%X" % write_bounds[1])
		print("")
		print("Decoded shellcode:")
		mem = emu.mem_read(write_bounds[0], (write_bounds[1] - write_bounds[0]))
		emu.disasm.disas_all(str(mem), write_bounds[0])

	else:
		print("No SMC hits, no encoder detected")

if __name__ == '__main__':
	main()

