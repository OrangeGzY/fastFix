
import collections
import pickle  
import time
import idaapi
import idautils
import idc
from datetime import datetime
from idaapi import simplecustviewer_t
import ida_kernwin

def search_eh_frame():
    all_segment = list(idautils.Segments())
    for i in all_segment:
        if '.eh_frame'== idc.SegName(i):
            return i
    raise Exception("NO .eh_frame!")

class fastFixArch():
    """
    Get important program ARCH information. 
    """
    information=''
    class info():
        """
        Inner Class in fastFixArch
        """
        cpu=''
        mode=''
        endian=''
        def __init__(self,ida):
            self.cpu = ida.procname.lower()
            if ida.is_64bit()==True :
                self.mode = '64'
                if ida.is_be()==False :
                    self.endian = 'Little'
                else:
                    print("Sorry don't support")
                    exit(-2)
            else:
                print("Sorry don't support")
                exit(-1)
        def __str__(self):
            return "fastArch->info"      
    def __init__(self):
        self.information = self.info(idaapi.get_inf_structure())
    
    def getArch(self):
        """
        return a list which tells basic ARCH infomation
        """
        return [self.information.cpu,self.information.mode,self.information.endian]

class fastFixGetAddr():
    """
    Get addr user want to patch
    """
    start = 0
    end = 0
    eh_frame = 0
    def __init__(self,start,end,eh_frame):
        self.start = start
        self.end = end
        self.eh_frame = eh_frame
        print("start addr:0x%lx\nend addr:0x%lx\neh_frame addr:0x%lx\n"%(self.start,self.end,self.eh_frame))
    
class fastFixPlugin(idaapi.plugin_t):
    flags = 0
    comment = 'Nothing'
    help = ''
    wanted_name = 'fastFix'
    wanted_hotkey = 'Alt-F6'
    NAME = 'fastFix.py'

    def __init__(self):

        idaapi.msg("++++++++++++++++++++++++++++++++++++++++++++++++++++\n")
        idaapi.msg("+                                                  +\n")
        idaapi.msg("+     fastFix starts. {0}   +\n".format(datetime.now()))
        idaapi.msg("+     by Guo Zi Yi, Sichuan University             +\n")
        idaapi.msg("+     version 0.1                                  +\n")
        idaapi.msg("+                                                  +\n")
        idaapi.msg("++++++++++++++++++++++++++++++++++++++++++++++++++++\n")

    def init(self):
        
        return idaapi.PLUGIN_KEEP

    def term(self):
        idaapi.msg(">>> My plugin ends. {0}\n".format(datetime.now()))
        return None

    def fixer(self):
        print("fastFix::fixer() ")
       # print(self.kp_asm.arch)


    def run(self, arg):
        """
        run the fastFix.py will call this
        """
        arch = fastFixArch()
        arch_info = arch.getArch()
        if arch_info[0]=='metapc' and arch_info[1]=='64' and arch_info[2]=='Little':
            """
            Ensure the ARCH is x86_64 Litlle endian
            """
            print("Program ARCH information:{},{},{}".format(arch_info[0],arch_info[1],arch_info[2]))
        else:   
            print("Sorry! fastFix doesn't support your ARCH!")
            exit(0)
        try:    
            l = (ida_kernwin.ask_str("", 0, "Please enter start and end address:")).split(",")  # popup a windows to ask user
            getAddr = fastFixGetAddr(int(l[0],16),int(l[1],16),search_eh_frame())                                 # Init addr information.
            print("[0x%lx]:%s\n[0x%lx]:%s\n"%(getAddr.start,idc.GetDisasm(getAddr.start),getAddr.end,idc.GetDisasm(getAddr.end)))
        except Exception,err:
            print(err)
            exit(0)

        return 
        
def PLUGIN_ENTRY():
    return fastFixPlugin()
