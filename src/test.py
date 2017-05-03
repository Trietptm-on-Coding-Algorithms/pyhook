#coding=utf8
from lxml import etree
from ctypes import *
import os
from __builtin__ import False
from pip._vendor.distlib._backport.tarfile import LENGTH_LINK

# API={'ws2_32.dll':['send','WSASend','recv','WSARecv','gethostbyname'],
#     'winhttp.dll':['WinHttpOpen','WinHttpConnect','WinHttpOpenRequest','WinHttpSendRequest'],
#     'kernel32.dll':['CreateFile','ReadFile','WriteFile','MoveFile','CopyFile','ReplaceFile','GetTempFileName','WinExec'],
#    
#     'advapi32.dll':['RegOpenKeyEx','RegCreateKeyEx','RegSetValueEx','RegQueryValueEx','CreateService']}
API={
    #'kernel32.dll':['CreateFile','WriteFile','MoveFile','CopyFile','ReplaceFile','GetTempFileName','WinExec']
    'ws2_32.dll':['send','WSASend','recv','WSARecv','gethostbyname']
    }

class Type_Info():
    def __init__(self,type,filename):
        self.type=type#id
        self.filename = filename
        ret_list = self.res_type2(type,None,filename)
        self.final_type = ret_list[0]
        self.size = ret_list[2]
        self.struct_size = 0
        self.__listfile = []
        if self.final_type == PSTRUCT:
            self.list_struct_param,self.struct_size = self.res_pstruct(self.type, None,filename)
    def res_pstruct(self,search_type,root,path):
        #return size,listpar   
        ret = self.res_type1(search_type,root,self.filename)
        ret = self.res_type1(ret[0].attrib['Base'],root,self.filename)
        print '[!]pstruct',ret[0].attrib['Name']
        evar = ret[0]
        efield_list = evar.findall('Field')
        struct_size = 0
        listParam = []
        for efield in efield_list:
            length = efield.attrib['Length'] if efield.attrib.has_key('Length') else None
            post_length = efield.attrib['PostLength'] if efield.attrib.has_key('PostLength') else None
            par = Sub_Struct_Type_Info(efield.attrib['Type'],ret[1],efield.attrib['Name'],length, post_length)
            listParam.append(par)
            struct_size += par.size                     
        return listParam,struct_size
    def res_direct(self,search_type):
        if search_type == '[ERROR_CODE]':
            return NORMAL
        return None
    def res_type2(self,search_type,root,path):
        self.__listfile = []
        ret = self.res_type1(search_type,root,path)
        if ret == None:
            assert False
        if isinstance(ret, int):
            return [ret,None,4]
        else:
            [evar,path] = ret
        if evar.attrib['Type'] == 'Pointer':
            size = Pointer_SIZE
            self.__listfile = []
            ret1 = self.res_type1(evar.attrib['Base'],None,path)
            if ret1 == None:
                assert False
            if isinstance(ret1, int):
                return [PDWORD,None,size]
            else:
                [evar1,path1] = ret1
            type = evar1.attrib['Type']
            if  type == 'Pointer':
                return [PDWORD,evar1.attrib['Base'],size]
            elif type == 'Void' or evar1.attrib['Name'] == 'BYTE' or evar1.attrib['Name'] == 'UCHAR':
                return [BUFFER,None,Pointer_SIZE]
            elif type == 'Character':
                return [STRING,None,Pointer_SIZE]
            elif type == 'TCharacter':
                return [TCHARACTER,None,Pointer_SIZE]
            elif type == 'UnicodeCharacter':
                return [UNICODE_STRING,None,Pointer_SIZE]
            elif type == 'Struct':
                return [PSTRUCT,None,Pointer_SIZE]
            elif 'Size' in evar1.keys() and int(evar1.attrib['Size']) == 4:
                return [PDWORD,None,Pointer_SIZE]
            else:
                
                print evar1.attrib['Type'],evar1.attrib['Name'],evar1.attrib['Size'],path1
                assert False
                return [PDWORD,None,int(evar.attrib['Size']) if 'Size' in evar.keys() else 0]        

        elif evar.attrib['Type'] == 'Struct':
            efield_list = evar.findall('Field')
            struct_size = 0
            for efield in efield_list:
                struct_size += self.res_type2(efield.attrib['Type'], root,path)[2]                       
            return [STRUCT,evar.attrib['Type'],struct_size]
        
        
        elif not 'Base' in evar.keys():
            if not 'Size' in evar.keys():
                return [NORMAL,evar.attrib['Type'],0]
            else:
                return [NORMAL,evar.attrib['Type'],int(evar.attrib['Size'])]  
        print '[!]',evar.attrib['Type']
        assert False
    def res_type1(self,search_type,root,path = None):
        #return node
        #print search_type,path
        ret = self.res_direct(search_type)
        if ret != None:
            return ret
        if root == None:
            fullpath = 'API/'+path
            if os.path.exists('API/Windows/'+path):
                fullpath = 'API/Windows/'+path
            f = open(fullpath)
            root = etree.fromstring(f.read())
            f.close()
        evar=root.findall('.//Variable[@Name="'+search_type+'"]')#没有点就要用elementtree
        if len(evar)==0:
            eheader = root.xpath('Include')
            for i in eheader:
                path = i.attrib['Filename']
                debug_print(path)
                if path in self.__listfile:
                    continue
                self.__listfile.append(path)
                f1 = open('API/'+path)
                root1 = etree.fromstring(f1.read())
                f1.close()
                ret = self.res_type1(search_type,root1,path)
                if ret != None:
                    self.__listfile = []
                    return ret
            return None
        else:
            assert len(evar) <= 2
            if len(evar) == 2:
                if evar[0].xpath('..')[0].attrib['Architecture'] == '32':
                    evar = evar[0]
                else:
                    evar = evar[1]
            else:
                evar = evar[0]
            if evar.attrib['Type'] == 'Alias':
                self.__listfile = []
                return self.res_type1(evar.attrib['Base'],root,path)
            else:
                return evar,path

    def __str__(self):
        str_ret = 'Name '+self.name+'\n'+'Type '+self.type + '\nFinal type '+str(self.final_type)+'\n'
        if self.length != None:
            str_ret += 'Length '+self.length+'\n'
        if self.post_length != None:
            str_ret += 'PostLength '+self.post_length+'\n'
        if self.final_type == PSTRUCT:
            str_ret += 'Struct_size '+str(self.struct_size)+'\n'
        return str_ret
class Sub_Struct_Type_Info(Type_Info):
    def __init__(self,type,filename,name = None,length = None,post_length = None):
        Type_Info.__init__(self, type, filename)
        self.name = name 
        self.length = length
        self.post_length = post_length
    
class Param_Info():
    def __init__(self,name,type,length,post_length,filename):
        self.name=name
        self.type = None
        for i in list_type:
            if type == i.type:
                self.type = i
                break
        if self.type == None:
            self.type=Type_Info(type,filename)
            list_type.append(self.type)
        self.length = length#string
        self.post_length = post_length#string
    
    def __str__(self):
        str_ret = 'Name '+self.name+'\n'+'Type '+self.type.type + '\nFinal type '+str(self.type.final_type)+'\n'
        if self.length != None:
            str_ret += 'Length '+self.length+'\n'
        if self.post_length != None:
            str_ret += 'PostLength '+self.post_length+'\n'
        if self.type.final_type == PSTRUCT:
            str_ret += 'Struct_size '+str(self.type.struct_size)+'\n'
        return str_ret
                

class Func_Info():
    def __init__(self,name,address,reg_list = None,par_num = 3):
        self.name = name 
        self.address = address 
        self.reg_list = reg_list
        self.par_num = par_num
        
class API_Info():
    def __init__(self,name,dll):
        self.name = name
        self.dll = dll
        self.xml = self.get_xml(dll)
        self.param = {}
        self.address=None
        self.active=True
        self.both_set = False
        f = open('API/Windows/'+self.xml)
        root = etree.fromstring(f.read())
        f.close()
        api = root.find('.//Api[@Name="'+name+'"]')
        self.both_charset = False if not 'BothCharset' in api.keys() else api.attrib['BothCharset'] == "True"
        listParam = api.xpath('Param')
        i = 0
        for param in listParam:
            par_name = param.attrib['Name']
            par_type = param.attrib['Type']
            length = None if not 'Length' in param.keys() else param.attrib['Length']
            post_length = None if not 'PostLength' in param.keys() else param.attrib['PostLength']
            par_info = Param_Info(par_name,par_type,length,post_length,self.xml)
            self.param[i]=par_info
            i+=1
        ret = api.find('Return')
        self.ret = Param_Info(None,ret.attrib['Type'],None,None,self.xml)
        
        
    def get_xml(self,dll):
        files = os.listdir('API/Windows/')
        #print files
        dll1 = dll.split('.')[0]
        for name in files:
            if dll1.lower()==name.split('.')[0].lower():
                return name
        return None
    def __str__(self):
        ret_str = self.dll+' '+self.name+'\n'
        for i in self.param:
            ret_str+=str(self.param[i])
        return ret_str
        
NORMAL=0
STRING=1
UNICODE_STRING=2
PDWORD=3
BUFFER=4
STRUCT=5
PSTRUCT=6
TCHARACTER=7
UNKNOWN=8
Pointer_SIZE=4
def debug_print(aaa):
    if 0:
        print aaa


def testall():
    for dll in API:
        print dll
        dllxml=''
        if dll=='ws2_32.dll':
            dllxml = 'Ws2_32.xml'    
        elif dll=='winhttp.dll':
            dllxml='Winhttp.xml'
        elif dll == 'kernel32.dll':
            dllxml = 'Kernel32.xml'
        elif dll == 'advapi32.dll':
            dllxml='Advapi32.xml'
        f = open('API/Windows/'+dllxml)
        root = etree.fromstring(f.read())
        f.close()
        for func in API[dll]:
            print func
            a = API_Info(func,dll)
            #print a
def testPar():
    a = Param_Info('lpSubKey','ACL',None,None,'Headers\security.h.xml')
    print a.size

list_type = []
#testall()
list_api = []
def load_api():
    for dll in API:
        for func in API[dll]:
            print func
            a = API_Info(func,dll)
            list_api.append(a)
load_api()