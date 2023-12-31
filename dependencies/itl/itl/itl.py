#!/usr/bin/env python3

"""This module is for patching binaries to use different linkers."""

# For more info, checkout: https://github.com/guyinatuxedo/itl

import os
import sys
import stat
import argparse

INSTALL_DIRECTORY = "/home/kevin/Desktop/remenissions/dependencies/itl"

HELP_DESCRIPTION = "This tool ilt (Inspire The Liars) is for dealing with \
ld_preloading a libc file, that you don't have the linker for. It \
essentially checks to see what libc version you have, grabs the corresponding \
linker, and patches the binary to use that linker using patchelf. For more \
info checkout: github.com/guyinatuxedo/itl"

HELP_BINARY = "The binary you are working with."

HELP_LIBC = "The libc you want to link the binary with."

HELP_EXPLOIT = "If used, will generate a script \
'exploit.py' to handle ld_preloading for you."

def check_if_exists(binary: str):
	"""Check if a file exists, if not print help function"""
	if not os.path.exists(binary):
		print("Does Not Exist: %s" % binary)
		print_help_function()

def print_help_function():
	"""Display the help menu for this tool"""
	print("Usage:\n\nitl -b <binary name> -l <libc name>\n")
	print("For more info checkout: https://github.com/guyinatuxedo/itl")
	sys.exit(0)

class LinkerPatcher:
	"""Our Class for patching the linker"""
	def __init__(self, binary, libc, create_exploit=False):
		"""Make a Patcher object"""
		self.binary = binary
		self.libc = libc
		self.linker_name = None
		self.arch = None
		self.libc_version = None
		self.create_exploit = create_exploit

	def check_binaries(self):
		"""Check if the binary and the libc exist"""
		check_if_exists(self.binary)
		check_if_exists(self.libc)

	def check_arch(self):
		"""Get the architecture of the target binary"""
		output = os.popen("file %s" % self.binary).read()
		if "32-bit" in output:
			self.arch = "x86"
		elif "64-bit" in output:
			self.arch = "x64"

	def parse_libc_version(self):
		"""Parse the libc version from the libc"""
		libc_file = open(self.libc, 'rb')
		libc_contents = libc_file.read()
		if b"stable release version" in libc_contents:
			index = libc_contents.index(b"stable release version")
			libc_version = libc_contents[index + 23:index + 27]
			libc_version = str(libc_version, 'utf-8')
			print("Libc Version: " + libc_version)
			libc_file.close()
			self.libc_version = libc_version
		else:
			print("not a libc file")
			print_help_function()

	def patch_binary(self):
		"""Patch the binary to use a different linker"""
		libc_path = "%s/%s" % (os.getcwd(), self.linker_name)
		binary_path = "./%s" % self.binary
		os.system("patchelf --set-interpreter %s %s" % (libc_path, binary_path))

	def get_ld_name(self):
		"""Get the linker name for the libc version"""
		self.linker_name = "ld-%s.so" % self.libc_version

	def get_linker(self):
		"""Get the linker path for the libc version"""
		self.get_ld_name()
		linker_file = open(INSTALL_DIRECTORY + "/linkers/%s/%s" % (self.arch, self.linker_name), "rb")
		linker_contents = linker_file.read()
		linker_file.close()

		new_linker = open(self.linker_name, "wb")
		new_linker.write(linker_contents)
		new_linker.close()

		permissions = os.stat(self.linker_name)
		os.chmod(self.linker_name, permissions.st_mode | stat.S_IEXEC)

	def create_ldpreload_exploit(self):
		"""Create an exploit to do the LD_PRELOAD"""
		print("Creating Exploit")
		exploit = open("exploit.py", "w")

		exploit.write('from pwn import *\n\n')
		exploit.write('target = process("./%s", env={"LD_PRELOAD":"./%s"})\n' % (self.binary, self.libc))
		exploit.write('gdb.attach(target)\n\n\n')
		exploit.write('target.interactive()\n')

		exploit.close()

	def patch_linker_for_binary(self):
		"""Function for handling the process of patching for a different linker"""

		# Check that the binary / libc exists
		self.check_binaries()

		# Grab the Architecture
		self.check_arch()

		# Parse out the libc version
		self.parse_libc_version()

		# Get the new linker
		self.get_linker()

		# Patch the binary to use the new linker
		self.patch_binary()

		# Create the new exploit if it was specified
		if self.create_exploit:
			self.create_ldpreload_exploit()

def main():
    # Parse out the arguments
    parser = argparse.ArgumentParser(description=HELP_DESCRIPTION)
    parser.add_argument("-b", metavar='-B', type=str, help=HELP_BINARY, default=None)
    parser.add_argument('-l', metavar='-L', type=str, help=HELP_LIBC, default=None)
    parser.add_argument('-e', metavar='-E', type=bool, help=HELP_EXPLOIT, nargs='?', \
    const=True, default=False)

    args = parser.parse_args()

    binary_name = args.b
    libc_name = args.l
    exploit_name = args.e

    # Patch in a new linker so we can ld_preload
    ld_patcher = LinkerPatcher(binary_name, libc_name, exploit_name)
    ld_patcher.patch_linker_for_binary()

if __name__ == "__main__":
    main()
