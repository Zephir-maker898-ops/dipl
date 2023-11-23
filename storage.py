import os
import shutil

'''
+-----------------------------------------------------------+
|                     Constants                             |
+-----------------------------------------------------------+
'''

BIN_SH_STRINGS = [b"/bin/sh", b"/bin/bash"]

INSTALL_DIR = "/home/kevin/Desktop/remenissions/"

ROPGADGET_DIR = "%sdependencies/ropgadget/" % INSTALL_DIR

THE_NIGHT_LIBCS = "%sdependencies/The_Night/libcs/" % INSTALL_DIR


EXECUTE_STRING = "gdbscript"

VERIFICATION_START_STRING = "# Exploit Verification starts here 15935728"

LIBC_EXPLOITS_DIRECTORY_NAME = "libcExploits"

DYNAMIC_ANALYZER_NAME = "diamond_eyes.py"

BOF_VAR_PROMPT = ["Overwrite Variables"]

BOF_FUNC_PROMPT = ["Bof Win Function"]
BOF_FUNC_ARGV_PROMPT = ["Bof Win Function Argv"]
BOF_FUNC_INFOLEAK_PROMPT = ["Bof Win Function Infoleak"]
BOF_FUNC_SYSTEM_PROMPT = ["Bof System"]
BOF_FUNC_SYSTEM_INFOLEAK_PROMPT = ["Bof System Infoleak"]

INDR_CALL_PROMPT = ["Indirect Call"]
INDR_CALL_PIE_PROMPT = ["Indirect Call Pie"]
INDR_CALL_LIBC_PROMPT = ["Indirect Call Libc"]

CALL_INPUT_PROMPT = ["Call Input"]

BOF_STATIC_PROMPT = ["Bof Static"]

RET_2_LIBC_PROMPT = ["Return to Libc"]
RET_2_LIBC_PUTS_INFOLEAK_PROMPT = ["Return to Libc Puts Infoleak"]
LIBC_ID_PROMPT = ["Libc ID Return to Libc"]

FMT_STRING_WINFUNC_PROMPT = ["Format String Winfunc"]
FMT_STRING_WINFUNC_PIE_PROMPT = ["Format String Winfunc Pie"]
FMT_STRING_WINFUNC_PIE_FSLEAK_PROMPT = ["Format String Winfunc Pie FsLeak"]
FMT_STRING_GOT_SYSTEM_PROMPT = ["Format String GOT System"]
FMT_STRING_GOT_SYSTEM_PIE_PROMPT = ["Format String GOT System Pie"]
FMT_STRING_RET_WINFUNC_PROMPT = ["Format String Ret Winfunc"]
FMT_STRING_GOT_LIBC_PROMPT = ["Format String GOT Libc"]
FMT_STRING_GOT_LIBC_FSLEAK_PROMPT = ["Format String GOT Libc FsLeak"]
FMT_STRING_GOT_ONESHOT_PROMPT = ["Format String GOT Oneshot"]


VERIFIED_EXPLOITS_PROMPT = {
							"BofVar": BOF_VAR_PROMPT,

							"BofFuncArgv": BOF_FUNC_ARGV_PROMPT,
							"BofFuncWInfoleak": BOF_FUNC_INFOLEAK_PROMPT,
							"BofSystemWInfoleak": BOF_FUNC_SYSTEM_INFOLEAK_PROMPT,
							"BofFunc": BOF_FUNC_PROMPT,
							"BofSystem": BOF_FUNC_SYSTEM_PROMPT,							

							"IndrCallPie": INDR_CALL_PIE_PROMPT,
							"IndrCallLibc": INDR_CALL_LIBC_PROMPT,
							"IndrCall": INDR_CALL_PROMPT,

							"CallInput": CALL_INPUT_PROMPT,

							"BofStatic": BOF_STATIC_PROMPT,

							"Ret2LibcPutsInfoleak": RET_2_LIBC_PUTS_INFOLEAK_PROMPT,

							"Ret2LibcId": LIBC_ID_PROMPT,
							"Ret2Libc": RET_2_LIBC_PROMPT,

							"FsGotWinFuncPieFsleak": FMT_STRING_WINFUNC_PIE_FSLEAK_PROMPT,
							"FsGotWinFuncPie": FMT_STRING_WINFUNC_PIE_PROMPT,
							"FsGotWinFunc": FMT_STRING_WINFUNC_PROMPT,

							"FsGotSystemPie": FMT_STRING_GOT_SYSTEM_PIE_PROMPT,
							"FsGotSystem": FMT_STRING_GOT_SYSTEM_PROMPT,
							"FsRetWinFunc": FMT_STRING_RET_WINFUNC_PROMPT,
							"FsGotLibcFsleakLoop": FMT_STRING_GOT_LIBC_FSLEAK_PROMPT,
							"FsGotLibc": FMT_STRING_GOT_LIBC_PROMPT,
							"FsGotOneshot": FMT_STRING_GOT_ONESHOT_PROMPT
						}
'''
+-----------------------------------------------------------+
|            Exploit File Handling                          |
+-----------------------------------------------------------+
'''
def get_single_exploit_name(name):
	return "exploit-%s.py" % name


def setup_exploit(elf_name, elf, attack_name, verification = None):
	exploit_name = get_single_exploit_name(attack_name)
	exploit = open(exploit_name, "w")
	exploit.write('from pwn import *\n\n')
	exploit.write("import os\n")
	exploit.write("import sf\n")
	exploit.write("import sys\n")
	exploit.write("import signal\n\n")
	exploit.write('target = process("./%s")\n' % elf_name)
	if verification == None:
		#exploit.write('gdb.attach(target, %s="verify_exploit")\n\n' % EXECUTE_STRING)
		pass
	elif verification == "static":
		#exploit.write('gdb.attach(target, %s="verify_exploit_static")\n\n' % EXECUTE_STRING)
		pass
	if elf.arch == "amd64":
		exploit.write('bof_payload = sf.BufferOverflow(arch=64)\n\n')
	elif elf.arch == "i386":
		exploit.write('bof_payload = sf.BufferOverflow(arch=32)\n\n')
	exploit.write('')		
	exploit.close()
	return exploit_name

def setup_libc_exploit(elf, elf_name, libc_name, attack_name):
	exploit_name = get_single_exploit_name(attack_name)
	exploit = open(exploit_name, "w")
	exploit.write('from pwn import *\n\n')
	exploit.write("import os\n")
	exploit.write("import sf\n")
	exploit.write("import sys\n")
	exploit.write("import signal\n\n")
	exploit.write('target = process("./%s", env={"LD_PRELOAD":"./%s"})\n' % (elf_name, libc_name))
	exploit.write('gdb.attach(target, %s="verify_exploit")\n' % EXECUTE_STRING)

	if elf.arch == "amd64":
		exploit.write('bof_payload = sf.BufferOverflow(arch=64)\n\n')
	elif elf.arch == "i386":
		exploit.write('bof_payload = sf.BufferOverflow(arch=32)\n\n')

	exploit.close()
	return exploit_name

def setup_filler_exploit(elf_name, elf, libc_name):
	exploit_name = 'binded-in-chains.py'
	exploit = open(exploit_name, "w")
	exploit.write('from pwn import *\n\n')
	exploit.write("import sf\n")
	if elf.arch == "amd64":
		exploit.write("import time\n\n")
	exploit.write("import sys\n\n")
	if libc_name != None:
		exploit.write('target = process("./%s", env={"LD_PRELOAD":"./%s"})\n' % (elf_name, libc_name))
	else:
		exploit.write('target = process("./%s")\n' % elf_name)		
	exploit.write('gdb.attach(target, %s="get_libc_puts_address")\n\n' % EXECUTE_STRING)	
	if elf.arch == "amd64":
		exploit.write('bof_payload = sf.BufferOverflow(arch=64)\n\n')
	elif elf.arch == "i386":
		exploit.write('bof_payload = sf.BufferOverflow(arch=32)\n\n')

	exploit.close()
	return exploit_name

def setup_id_exploit(elf_name, elf, ip_port):
	exploit_name = 'afterlife.py'
	exploit = open(exploit_name, "w")
	exploit.write('from pwn import *\n\n')
	exploit.write('import sf\n\n')
	exploit.write('import thenight\n\n')
	if elf.arch == "amd64":
		exploit.write("import time\n\n")
	exploit.write("import sys\n\n")
	if ip_port != None:
		exploit.write('target = remote("%s", %s)\n' % (ip_port[0], ip_port[1]))
	else:
		exploit.write('target = process("./%s")\n' % elf_name)
	if elf.arch == "amd64":
		exploit.write('bof_payload = sf.BufferOverflow(arch=64)\n\n')
	elif elf.arch == "i386":
		exploit.write('bof_payload = sf.BufferOverflow(arch=32)\n\n')
	exploit.close()
	return exploit_name


def multi_setup_exploit(elf_name, elf, attack_name):
	exploit_name = get_single_exploit_name(attack_name)
	if os.path.exists(exploit_name):
		os.remove(exploit_name)
		
	exploit = open(exploit_name, "w")
	exploit.write('from pwn import *\n')
	exploit.write("import time\n")
	exploit.write("import sys\n")
	exploit.write("import signal\n")
	exploit.write("import sf\n\n")
	exploit.write('target = process("./%s")\n' % elf_name)
	exploit.write('gdb.attach(target, %s="verify_exploit")\n\n' % EXECUTE_STRING)
	if elf.arch == "amd64":
		exploit.write('bof_payload = sf.BufferOverflow(arch=64)\n\n')
	elif elf.arch == "i386":
		exploit.write('bof_payload = sf.BufferOverflow(arch=32)\n\n')
	exploit.close()

	return exploit_name

def write_crash_detection(exploit_name):
	exploit = open(exploit_name, "a")
	exploit.write("\n# Exploit Verification starts here 15935728\n\n")

	exploit.write("def handler(signum, frame):\n")
	exploit.write('\traise Exception("Timed out")\n\n')

	exploit.write("def check_verification_done():\n")
	exploit.write("\twhile True:\n")
	exploit.write('\t\tif os.path.exists("pwned") or os.path.exists("rip"):\n')
	exploit.write('\t\t\tsys.exit(0)\n\n')

	exploit.write("signal.signal(signal.SIGALRM, handler)\n")
	exploit.write("signal.alarm(2)\n\n")

	exploit.write("try:\n")
	exploit.write("\twhile True:\n")
	exploit.write('\t\tcheck_verification_done()\n')
	exploit.write('except Exception:\n')
	exploit.write('\tprint("Exploit timed out")\n')
	exploit.close()

def write_crash_detection_libc(exploit_name):
	exploit = open(exploit_name, "a")
	exploit.write("\n# Exploit Verification starts here 15935728\n\n")

	exploit.write("time.sleep(.5)\n")
	exploit.close()

def exploit_write(inp, exploit_name):
	exploit = open(exploit_name, "a")
	exploit.write('%s\n' % inp)
	exploit.close() 


def finalize_exploit(exploit_name, ip_port, normie):
	final_exploit_name = "verified-%s" % exploit_name
	testedExploit = open(exploit_name, "r")
	exploit = open(final_exploit_name, "w")
	for line in testedExploit:
		if line[:3] == "gdb" and ip_port == None:
			exploit.write(line.split(',')[0] + ")\n")
			continue
		if 'process("./' in line and ip_port != None:
			exploit.write('target = remote("%s", %s)\n' % (ip_port[0], ip_port[1]))
			exploit.write('#%s' % line)
			continue
		if "gdb" in line and ip_port != None:
			exploit.write("#%s\n" % line.split(',')[0])
			continue
		elif VERIFICATION_START_STRING in line:
			exploit.write("\ntarget.interactive()\n")
			break			
		if ("import os" in line) or ("import signal" in line) or ("import sys" in line):
			continue
		else:
			exploit.write(f"{line}")

	exploit.close()
	shutil.copyfile(final_exploit_name, "../%s" % final_exploit_name)

def finalize_argv_exploit(exploit_name):
	final_exploit_name = "verified-%s" % exploit_name
	testedExploit = open(exploit_name, "r")
	exploit = open(final_exploit_name, "w")
	for line in testedExploit:
		if "15935728" in line:
			exploit.write("\ntarget.interactive()\n")
			break
		else:
			exploit.write(f"{line}")

	exploit.close()
	shutil.copyfile(final_exploit_name, "../%s" % final_exploit_name)
