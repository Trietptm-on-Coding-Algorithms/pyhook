import cPickle

from pydbg import *
from pydbg.defines import *

#import log
from database import *
from hook_function import *
from hook_point import *
#from hook_manager import *
from info_manager import *
from test import *
from hooking import *
def init_at_first_bp(dbg):
	log.d("[*] Pydbg first point at %#x, HookPoints init..."% dbg.context.Eip, dbg)
	#print dbg.disasm_around(dbg.context.Eip)
	#hook_man.start_hook(dbg)
	dlls = dbg.system_dlls
	for dll in dlls:
		if API.has_key(dll.name):
			for i in API[dll.name]:
				#address = dbg.func_resolve_debuggee(dll.name, i)
				for j in list_api:
					if j.name == i:
						try:
							if j.both_charset == True:
								address = dbg.func_resolve_debuggee(dll.name, i+'A')
								assert address!= None
								hc.add(dbg,address,j,'A')
								address = dbg.func_resolve_debuggee(dll.name, i+'W')
								assert address!= None
								hc.add(dbg,address,j,'W')
							else:
								address = dbg.func_resolve_debuggee(dll.name, i)
								hc.add(dbg,address,j)
								assert address!= None
							break
						except Exception,e:
							print j.name,dll.name,address
def handler_breakpoint(dbg):
	log.d("Pydbg breakpoint hits!")
	if dbg.first_breakpoint:
		pass
		init_at_first_bp(dbg)	

	return DBG_CONTINUE

def handler_create_process(dbg):
	log.i("New process.. ", dbg)
	info = CreateProcessInfo(dbg.pid, dbg.tid)
	info.save()

	return DBG_CONTINUE

def handler_exit_process(dbg):
	log.i("Exit process.. ", dbg)
	info = ExitProcessInfo(dbg.pid, dbg.tid)
	info.save()

	return DBG_CONTINUE

def handler_create_thread(dbg):
	log.i("New thread..  ", dbg)
	info = CreateThreadInfo(dbg.pid, dbg.tid)
	info.save()

	return DBG_CONTINUE

def handler_exit_thread(dbg):
	log.i("Exit thread.. ", dbg)
	info = ExitThreadInfo(dbg.pid, dbg.tid)
	info.save()

	return DBG_CONTINUE

def handler_load_dll(dbg):
	dll = dbg.system_dlls[-1]

	info = LoadDllInfo(dbg.pid, dbg.tid, path=dll.path)
	info.save()
	dbg.single_step(True)
	log.i(info.brief_info(), dbg)
# 	if API.has_key(dll.name):
# 		for i in API[dll.name]:
# 			address = dbg.func_resolve_debuggee(dll.name, i)
# 			print 'address',address
# 			address = dbg.func_resolve_debuggee(dll.name, i)
# 			for j in list_api:
# 				if j.name == i:
# 					
# 					hc.add(dbg,address,j)
# 					break
	return DBG_CONTINUE


def handler_unload_dll(dbg):
	base = dbg.dbg.u.UnloadDll.lpBaseOfDll

	unload_dll = ""
	for system_dll in dbg.system_dlls:
		if system_dll.base == base:
			unload_dll = system_dll
			break	

	info = UnloadDllInfo(dbg.pid, dbg.tid, path=system_dll.path)
	info.save()

	log.i(info.brief_info(), dbg)
	return DBG_CONTINUE

def handler_output_debug_string(dbg):
	addr = addressof(dbg.dbg.u.DebugString.lpDebugStringData.contents)
	size = dbg.dbg.u.DebugString.nDebugStringLength
	s = dbg.read_process_memory(addr, size)

	info = DebugStringInfo(dbg.pid, dbg.tid, debug_string= s)
	info.save()
	#log.i("Debug string: %s\n"%s,dbg)
	return DBG_CONTINUE

def handler_rip(dbg):	
	log.e("RIP Event:", dbg)
	log.e("Error code:%#x" % dbg.u.RipInfo.dwError, dbg)
	log.e("Error type:%#x" % dbg.u.RipInfo.dwType, dbg.dwProcessId,dbg.tid)
	return DBG_CONTINUE

#############################################################################################
def handler_access_violation(dbg):
	log.i("[!] Access violation.", dbg)
	return DBG_EXCEPTION_NOT_HANDLED

def handler_guard_page(dbg):
	log.i("Guard page...", dbg)
	return DBG_CONTINUE

def handler_single_step(dbg):
	#log.i("Single step...", dbg)
	return DBG_CONTINUE


def load_dbg():
	dbg = pydbg()
	
	dbg.set_callback(CREATE_PROCESS_DEBUG_EVENT, handler_create_process)
	dbg.set_callback(CREATE_THREAD_DEBUG_EVENT, handler_create_thread)
	dbg.set_callback(EXIT_PROCESS_DEBUG_EVENT, handler_exit_process)
	dbg.set_callback(EXIT_THREAD_DEBUG_EVENT, handler_exit_thread)
	dbg.set_callback(LOAD_DLL_DEBUG_EVENT, handler_load_dll)
	dbg.set_callback(UNLOAD_DLL_DEBUG_EVENT, handler_unload_dll)
	dbg.set_callback(OUTPUT_DEBUG_STRING_EVENT, handler_output_debug_string)
	dbg.set_callback(RIP_EVENT, handler_rip)

	dbg.set_callback(EXCEPTION_BREAKPOINT, handler_breakpoint)	
	dbg.set_callback(EXCEPTION_ACCESS_VIOLATION, handler_access_violation)
	dbg.set_callback(EXCEPTION_GUARD_PAGE, handler_guard_page)
	dbg.set_callback(EXCEPTION_SINGLE_STEP, handler_single_step)


	dbg.load(config.EXE_PATH, command_line = config.EXE_CMD, create_new_console=True)

	#dbg.load(r"E:\work\psiphon_new\psiphon3_unpacked.exe", create_new_console=True)
	#dbg.load(r"E:\work\DNS\DNS.exe", create_new_console=True)
	#dbg.load(r"E:\work\psiphon\psiphon3_old_unpacked.exe", create_new_console=True)
	#dbg.load(r"E:\work\psiphon\psiphon3_old.exe", create_new_console=True)
	#dbg.load(r"E:\work\ut\uTorrent.exe", create_new_console=True)	
	#dbg.load(r"C:\Moon\other\ftp_server.exe", create_new_console=True)
	#dbg.load(r'C:\DOCUME~1\moon\LOCALS~1\Temp\psiphon-tunnel-core.exe',r' --config "C:\Documents and Settings\moon\Application Data\Psiphon3\psiphon.config" --serverList "C:\Documents and Settings\moon\Application Data\Psiphon3\server_list.dat"',create_new_console=True)

	#dbg.load(r"C:\Program Files\Google\Chrome\Application\chrome.exe", create_new_console=True)
	#dbg.load(r"C:\Program Files\Astrill\astrill.exe", create_new_console=True)
	#dbg.load(r"C:\Moon\workspace\test_con_win32\Debug\test_con_win32.exe", create_new_console=True)	
	dbg.run()
	

def main():
	log.log_init()
	data_man.init()
	load_dbg()	
	#info_man.dump()
	#info_man.load()
	#info_man.gen_report()
	#info_man.open_report()

	print "-------END---------"


if __name__ == '__main__':
	main()
