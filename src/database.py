'''
Created on May 18, 2016

@author: Jingyun Hu
'''

import sqlite3
import config



class my_sqlite:
    counter = 0
    args = []
    def init(self):
        # connect to database
        
        conn = sqlite3.connect("test.db")
        try:
                # create a Cursor
                cursor = conn.cursor()
                cursor.execute("create table Info (num int primary key,category varchar(20), pid varchar(20), tid varchar(20), timestamp varchar(20), tag varchar(20),brief_info varchar (200))")
                conn.commit()
                cursor.execute("create table DllInfo (num int primary key, path varchar(50))")
                conn.commit()
                cursor.execute("create table HookFunction (num int primary key, func_name varchar(20), func_addr varchar(20),module varchar(20),ret_addr varchar(20), ret_value varchar(20))")
                conn.commit()
                cursor.execute("create table DataEvent(num int primary key, data varchar(512),size int)")
                conn.commit()
                cursor.execute("create table HttpSessionEvent(num int primary key, user_agent varchar(20),proxy varchar(20),by_pass varchar(20))")
                conn.commit()
                cursor.execute("create table HttpOpenReqEvent(num int primary key, verb varchar(20), path varchar(50),version varchar(10),referer varchar(20),accepttype varchar(30))")
                conn.commit()
                cursor.execute("create table HttpSendReqEvent(num int primary key, header varchar(50), optional varchar(50))")
                conn.commit()
                cursor.execute("create table ProcessEvent(num int primary key, filename varchar(50), cmd varchar(50), env varchar(50), cur_dir varchar(50))")
                conn.commit()
                cursor.execute("create table RegCreateEvent(num int primary key, HKEY varchar(50), SKEY varchar(50), class varchar(50))")
                conn.commit()
                cursor.execute("create table RegValueEvent(num int primary key, HKEY varchar(50),name varchar(20), data varchar(50),size int)")
                conn.commit()
                cursor.close()
        except Exception ,e:
                a=1
                
        conn.close()
        
    def update(self,type,data,details=None):
        con = sqlite3.connect("test.db")
        self.counter += 1
        data.insert(0,int(self.counter))
        c = con.cursor()
        c.execute("insert Into info values (?,?,?,?,?,?,?)",data)
        con.commit()
        #print type
        if data[5] == 'LoadDllInfo':
            details.insert (0, int(self.counter))
            c.execute("insert into DllInfo values(?,?)",details)
            con.commit()
        if type == "Hook Functions":
            details.insert(0,int(self.counter))
            c.execute("insert into HookFunction (num, func_name, func_addr, module, ret_addr, ret_value) values (?,?,?,?,?,?)",details[0:6])
            con.commit()
            # add datails.args to table
            for name, t in details[6:]:
                #print name,t
                if name not in self.args:
                    #print "add success"
                    c.execute("alter table HookFunction add %s varchar(20)" % name)
                    con.commit()
                    self.args.append(name)
                    #print t
                c.execute("update HookFunction set %s = %s where num = %d " % (name, t,self.counter))
                con.commit()
        if type == "Events":
            print 'data[5]!',data[5]
            details.insert(0,int(self.counter))
            if data[5]=='SocketRecvEvent' or data[5]=='SocketSendEvent' or data[5]=='WSASocketSendEvent' or data[5]=='WSASocketRecvEvent' or data[5]=='ReadFileEvent' or data[5]=='WriteFileEvent':
                print "details!",details
                c.execute("insert into DataEvent values (?,?,?)",details)
            elif data[5]=='HTTPOpenSession':
                c.execute("insert into HttpSessionEvent values (?,?,?,?)",details)
            elif data[5]=='HTTPOpenRequestEvent':
                c.execute("insert into HttpOpenReqEvent values (?,?,?,?,?,?)",details)
            elif data[5]=='HTTPSendRequestEvent':
                c.execute("insert into HttpSendReqEvent values (?,?,?)",details)
            elif data[5] =='CreateProcessEvent':
                c.execute("insert into ProcessEvent values (?,?,?,?,?)",details)
            elif data[5]=='RegCreateEvent':
                c.execute("insert into RegCreateEvent values (?,?,?,?)",details)
            elif data[5]=='RegSetEvent' or data[5]=='RegQueryEvent':
                c.execute("insert into RegValueEvent values (?,?,?,?,?)",details)
            con.commit()
        c.close()
        con.close()
        return True
    
    def close(self):
        self.conn.close()
               
#data_man = my_sqlite()
