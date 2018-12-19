# SPDX-License-Identifier: GPL-2.0
#
# Nuvoton IGPS: Image Generation And Programming Scripts For Poleg BMC
#
# Copyright (C) 2018 Nuvoton Technologies, All Rights Reserved
#-------------------------------------------------------------------------

import sys
import os
import filecmp

import MemoryControllerInit
import ProgrammingErrors
import UartUpdate

programmer_monitor_addr = 0xFFFD6000
programmer_monitor_bin = os.path.join("inputs", "Poleg_programmer_monitor.bin")

header_location = 0xFFFDC000
otp_cmp_bin = "_otp.bin.cmp"

body_location = 0xFFFE0000

otp_size = 1024

def not_8(x): return x ^ 0xff

fuse_fields = {
	'DAC_Calibration_Word': (16, 20),
	'ADC_Calibration_Word': (24, 28)
}

def check_field(current_fuse_array, fuse_array_to_program, field):

	curr = current_fuse_array[fuse_fields[field][0]:fuse_fields[field][1]]
	to_prog = fuse_array_to_program[fuse_fields[field][0]:fuse_fields[field][1]]

	# if current is not zeroes and is not equal to the current
	if any(i != 0 for i in curr) and cmp(curr, to_prog) != 0:
		if all(i == 0 for i in to_prog):
			# if field is already programmed but the input is zeroes, change the input
			fuse_array_to_program[fuse_fields[field][0]:fuse_fields[field][1]] = curr
		else:
			# if current field and new field are different, programming is not allowed
			raise Exception("Error: %s is already programmed" % field)

	return fuse_array_to_program

def check_fuse_bin(current_fuse_array, fuse_array_to_program):

	origin_fuse_array_to_program = fuse_array_to_program[:]

	# check fields, change the fuse array if needed
	fuse_array_to_program = check_field(current_fuse_array, fuse_array_to_program, 'DAC_Calibration_Word')
	fuse_array_to_program = check_field(current_fuse_array, fuse_array_to_program, 'ADC_Calibration_Word')

	# check if the fuse array was changed
	if cmp(origin_fuse_array_to_program, fuse_array_to_program) == 0:
		return [False, fuse_array_to_program]

	return [True, fuse_array_to_program]


def check_otp_bin(otp_name, current_otp_filename, otp_bin_filename):

	_file = open(current_otp_filename, "rb")
	current = bytearray(_file.read())
	_file.close()

	_file = open(otp_bin_filename, "rb")
	to_program = bytearray(_file.read())
	_file.close()

	new_image = False

	if otp_name == "fuse":
		[new_image, to_program] = check_fuse_bin(current, to_program)

	for i in range(0, otp_size):
		# check if there are 0's that are going to be written on '1's
		if (not_8(current[i]) | (current[i] & to_program[i])) == 0:
			new_image = True
			print("byte %d (0x%x) cannot be programmed to the otp (current value is 0x%x)" % (i, to_program[i], current[i]))
			to_program[i] |= current[i]

	if new_image:
		reply = str(raw_input("Warning: otp is not empty, after programming the otp may be different from the input image. Type 'y' to continue:").strip())
		if reply != "y":
			raise Exception("Please modify your input file to be compatible with the current otp image (%s)" % current_otp_filename)

		modified_otp_bin_filename = "%s.modified" % otp_bin_filename
		_file = open(modified_otp_bin_filename, "wb")
		_file.write(to_program)
		_file.close()

		return modified_otp_bin_filename

	return otp_bin_filename


def run(otp_name, otp_prog_header, otp_bin, otp_read_header):

	currpath = os.getcwd()
	os.chdir(os.path.dirname(os.path.abspath(__file__)))

	cmp_bin = otp_name + otp_cmp_bin

	try:	
		if (not os.path.exists(otp_prog_header)):
			raise ValueError(otp_prog_header + " is missing") 

		if (not os.path.exists(otp_read_header)):
			raise ValueError(otp_read_header + " is missing") 

		if (not os.path.exists(otp_bin)):
			raise ValueError(otp_bin + " is missing")

		[port, baudrate] = UartUpdate.check_com()

		print("Monitor programming...")
		UartUpdate.uart_write_to_mem(port, baudrate, programmer_monitor_addr, programmer_monitor_bin)

		print("Memory init...")
		MemoryControllerInit.memory_controller_init(port, baudrate)

		print("==============================")
		print(otp_name + ": read otp..." )
		print("==============================")
		UartUpdate.uart_write_to_mem(port, baudrate, header_location, otp_read_header)
		UartUpdate.uart_execute_returnable_code(port, baudrate, programmer_monitor_addr)
		UartUpdate.uart_read_from_mem(port, baudrate, 0xFFFE1000, otp_size, cmp_bin)

		# check if the input file can be programmed to the otp
		otp_bin = check_otp_bin(otp_name, cmp_bin, otp_bin)

		print("==============================")
		print(otp_name + ": programming...")
		print("otp_prog_header " + otp_prog_header + "    prog file " + otp_bin) 
		print("==============================")
		UartUpdate.uart_write_to_mem(port, baudrate, header_location, otp_prog_header)
		UartUpdate.uart_write_to_mem(port, baudrate, body_location, otp_bin)
		UartUpdate.uart_execute_returnable_code(port, baudrate, programmer_monitor_addr)

		print("==============================")
		print(otp_name + ": compare entire binary..." )
		print("==============================")
		UartUpdate.uart_write_to_mem(port, baudrate, header_location, otp_read_header)
		UartUpdate.uart_execute_returnable_code(port, baudrate, programmer_monitor_addr)
		UartUpdate.uart_read_from_mem(port, baudrate, 0xFFFE1000, otp_size, cmp_bin)

		if not filecmp.cmp(otp_bin, cmp_bin):
			ProgrammingErrors.print_error_compare_error(run.__name__, otp_bin, cmp_bin)

		print("==============================")
		print(otp_name + ":  read monitor log to file " + otp_name + "_monitor_log.bin" )
		print("==============================")		
		UartUpdate.uart_read_from_mem(port, baudrate, 0xFFFDBF00, 256, otp_name + "_monitor_log.bin")

		print("==============================")
		print(otp_name + ": program %s Pass" % (otp_bin))
		print("==============================")

	except (UartUpdate.UartError, IOError) as e:
		ProgrammingErrors.print_error(e.value)

	finally:
		os.chdir(currpath)
