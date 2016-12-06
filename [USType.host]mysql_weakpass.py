# -*- coding: utf-8 -*-
import socket
import struct
import re
import logging
from hashlib import sha1
from lib.core.uspocbase import *


def intread(b):
    """Unpacks the given buffer to an integer"""
    try:
        if isinstance(b,int):
            return b
        l = len(b)
        if l == 1:
            return int(ord(b))
        if l <= 4:
            tmp = b + '\x00'*(4-l)
            return struct.unpack('<I', tmp)[0]
        else:
            tmp = b + '\x00'*(8-l)
            return struct.unpack('<Q', tmp)[0]
    except:
        raise

def read_string(buf, end=None, size=None):
    """
    Reads a string up until a character or for a given size.

    Returns a tuple (trucated buffer, string).
    """
    if end is None and size is None:
        raise ValueError('read_string() needs either end or size')

    if end is not None:
        try:
            idx = buf.index(end)
        except (ValueError), e:
            raise ValueError("end byte not precent in buffer")
        return (buf[idx+1:], buf[0:idx])
    elif size is not None:
        return read_bytes(buf,size)

    raise ValueError('read_string() needs either end or size (weird)')

def read_int(buf, size):
    """Read an integer from buffer

    Returns a tuple (truncated buffer, int)
    """

    try:
        res = intread(buf[0:size])
    except:
        raise

    return (buf[size:], res)

def read_bytes(buf, size):
    """
    Reads bytes from a buffer.

    Returns a tuple with buffer less the read bytes, and the bytes.
    """
    s = buf[0:size]
    return (buf[size:], s)

def int1store(i):
    """
    Takes an unsigned byte (1 byte) and packs it as string.

    Returns string.
    """
    if i < 0 or i > 255:
        raise ValueError('int1store requires 0 <= i <= 255')
    else:
        return struct.pack('<B',i)

def int4store(i):
    """
    Takes an unsigned integer (4 bytes) and packs it as string.

    Returns string.
    """
    if i < 0 or i > 4294967295L:
        raise ValueError('int4store requires 0 <= i <= 4294967295')
    else:
        return struct.pack('<I',i)

class _constants(object):

    prefix = ''
    desc = {}

    def __new__(cls):
        raise TypeError, "Can not instanciate from %s" % cls.__name__

    @classmethod
    def get_desc(cls,name):
        try:
            return cls.desc[name][1]
        except:
            return None

    @classmethod
    def get_info(cls,n):
        try:
            res = {}
            for v in cls.desc.items():
                res[v[1][0]] = v[0]
            return res[n]
        except:
            return None

    @classmethod
    def get_full_info(cls):
        res = ()
        try:
            res = ["%s : %s" % (k,v[1]) for k,v in cls.desc.items()]
        except StandardError, e:
            res = ('No information found in constant class.%s' % e)

        return res

class _constantflags(_constants):

    @classmethod
    def get_bit_info(cls, v):
        """Get the name of all bits set

        Returns a list of strings."""
        res = []
        for name,d in cls.desc.items():
            if v & d[0]:
                res.append(name)
        return res

class ClientFlag(_constantflags):
    """
    Client Options as found in the MySQL sources mysql-src/include/mysql_com.h
    """
    LONG_PASSWD             = 1 << 0
    FOUND_ROWS              = 1 << 1
    LONG_FLAG               = 1 << 2
    CONNECT_WITH_DB         = 1 << 3
    NO_SCHEMA               = 1 << 4
    COMPRESS                = 1 << 5
    ODBC                    = 1 << 6
    LOCAL_FILES             = 1 << 7
    IGNORE_SPACE            = 1 << 8
    PROTOCOL_41             = 1 << 9
    INTERACTIVE             = 1 << 10
    SSL                     = 1 << 11
    IGNORE_SIGPIPE          = 1 << 12
    TRANSACTIONS            = 1 << 13
    RESERVED                = 1 << 14
    SECURE_CONNECTION       = 1 << 15
    MULTI_STATEMENTS        = 1 << 16
    MULTI_RESULTS           = 1 << 17
    SSL_VERIFY_SERVER_CERT  = 1 << 30
    REMEMBER_OPTIONS        = 1 << 31

    desc = {
        'LONG_PASSWD':        (1 <<  0, 'New more secure passwords'),
        'FOUND_ROWS':         (1 <<  1, 'Found instead of affected rows'),
        'LONG_FLAG':          (1 <<  2, 'Get all column flags'),
        'CONNECT_WITH_DB':    (1 <<  3, 'One can specify db on connect'),
        'NO_SCHEMA':          (1 <<  4, "Don't allow database.table.column"),
        'COMPRESS':           (1 <<  5, 'Can use compression protocol'),
        'ODBC':               (1 <<  6, 'ODBC client'),
        'LOCAL_FILES':        (1 <<  7, 'Can use LOAD DATA LOCAL'),
        'IGNORE_SPACE':       (1 <<  8, "Ignore spaces before ''"),
        'PROTOCOL_41':        (1 <<  9, 'New 4.1 protocol'),
        'INTERACTIVE':        (1 << 10, 'This is an interactive client'),
        'SSL':                (1 << 11, 'Switch to SSL after handshake'),
        'IGNORE_SIGPIPE':     (1 << 12, 'IGNORE sigpipes'),
        'TRANSACTIONS':       (1 << 13, 'Client knows about transactions'),
        'RESERVED':           (1 << 14, 'Old flag for 4.1 protocol'),
        'SECURE_CONNECTION':  (1 << 15, 'New 4.1 authentication'),
        'MULTI_STATEMENTS':   (1 << 16, 'Enable/disable multi-stmt support'),
        'MULTI_RESULTS':      (1 << 17, 'Enable/disable multi-results'),
        'SSL_VERIFY_SERVER_CERT':     (1 << 30, ''),
        'REMEMBER_OPTIONS':           (1 << 31, ''),
    }

    default = [
        LONG_PASSWD,
        LONG_FLAG,
        CONNECT_WITH_DB,
        PROTOCOL_41,
        TRANSACTIONS,
        SECURE_CONNECTION,
        MULTI_STATEMENTS,
        MULTI_RESULTS,
    ]

    @classmethod
    def get_default(cls):
        flags = 0
        for f in cls.default:
            flags |= f
        return flags


class MySQL:
    def __init__(self, host, user, passwd, port = 3306):
        self.host = host
        self.port = port
        self.user = user
        self.passwd = passwd

        self._handshake = None
        self.sock = None
        self._client_flags = ClientFlag.get_default()

    def __del__(self):
        if self.sock is not None:
            self.sock.close()

    def _scramble_password(self, passwd, seed):
        """Scramble a password ready to send to MySQL"""
        hash4 = None
        try:
            hash1 = sha1(passwd).digest()
            hash2 = sha1(hash1).digest() # Password as found in mysql.user()
            hash3 = sha1(seed + hash2).digest()
            xored = [ intread(h1) ^ intread(h3)
                for (h1,h3) in zip(hash1, hash3) ]
            hash4 = struct.pack('20B', *xored)
        except Exception, err:
            raise errors.InterfaceError(
                'Failed scrambling password; %s' % err)

        return hash4

    def _prepare_auth(self, usr, pwd, db, flags, seed):
        """Prepare elements of the authentication packet"""
        if usr is not None and len(usr) > 0:
            _username = usr + '\x00'
        else:
            _username = '\x00'

        if pwd is not None and len(pwd) > 0:
            _password = int1store(20) +\
                self._scramble_password(pwd,seed)
        else:
            _password = '\x00'

        if db is not None and len(db):
            _database = db + '\x00'
        else:
            _database = '\x00'

        return (_username, _password, _database)

    def parse_handshake(self, packet):
        """Parse a MySQL Handshake-packet"""
        res = {}
        (packet, res['protocol']) = read_int(packet[4:], 1)
        (packet, res['server_version_original']) = read_string(
            packet, end='\x00')
        (packet, res['server_threadid']) = read_int(packet, 4)
        (packet, res['scramble']) = read_bytes(packet, 8)
        packet = packet[1:] # Filler 1 * \x00
        (packet, res['capabilities']) = read_int(packet, 2)
        (packet, res['charset']) = read_int(packet, 1)
        (packet, res['server_status']) = read_int(packet, 2)
        packet = packet[13:] # Filler 13 * \x00
        (packet, scramble_next) = read_bytes(packet, 12)
        res['scramble'] += scramble_next
        return res

    def make_auth(self, seed, username=None, password=None, database=None,
                  charset=33, client_flags=0,
                  max_allowed_packet=1073741824):
        if not seed:
            return False, 'Seed missing'

        auth = self._prepare_auth(username, password, database,
                                  client_flags, seed)
        return int4store(client_flags) +\
               int4store(max_allowed_packet) +\
               int1store(charset) +\
               '\x00' * 23 + auth[0] + auth[1] + auth[2]

    def get_exception(self, packet):
        """Returns an exception object based on the MySQL error

        Returns an exception object based on the MySQL error in the given
        packet.

        Returns an Error-Object.
        """
        errno = errmsg = None

        try:
            packet = packet[5:]
            (packet, errno) = read_int(packet, 2)
            if packet[0] != '\x23':
                # Error without SQLState
                errmsg = packet
            else:
                (packet, sqlstate) = read_bytes(packet[1:], 5)
                errmsg = packet
        except Exception, err:
            return -1, "Failed getting Error information (%r)" % err, 0
        else:
            return errno, errmsg, sqlstate

    def recv_plain(self):
        """Receive packets from the MySQL server"""
        try:
            header = self.sock.recv(4)
            if len(header) < 4:
                return None
            self._packet_number = ord(header[3])
            payload_length = struct.unpack("<I", header[0:3] + '\x00')[0]
            payload = ''
            while len(payload) < payload_length:
                chunk = self.sock.recv(payload_length - len(payload))
                if len(chunk) == 0:
                    return None
                payload = payload + chunk
            return header + payload
        except Exception, e:
            raise Exception(e.message)

    def _prepare_packets(self, buf, pktnr):
        """Prepare a packet for sending to the MySQL server"""
        pkts = []
        buflen = len(buf)
        maxpktlen = 16777215
        while buflen > maxpktlen:
            pkts.append('\xff\xff\xff' + struct.pack('<B', pktnr)
                        + buf[:maxpktlen])
            buf = buf[maxpktlen:]
            buflen = len(buf)
            pktnr = pktnr + 1
        pkts.append(struct.pack('<I', buflen)[0:3]
                    + struct.pack('<B', pktnr) + buf)
        return pkts

    def send_plain(self, buf, packet_number=None):
        """Send packets to the MySQL server"""
        packets = self._prepare_packets(buf, 1)
        for packet in packets:
            try:
                self.sock.sendall(packet)
            except Exception, err:
                raise Exception(str(err))

    def do_auth(self):
        packet = self.make_auth(
            seed=self._handshake['scramble'],
            username=self.user, password=self.passwd, database='',
            charset=33, client_flags=self._client_flags)
        try:
            self.send_plain(packet)
            buffer = self.recv_plain()

            if buffer[4] == '\xfe':
                return  False, "Authentication with old (insecure) passwords "\
                               "is not supported. For more information, lookup "\
                               "Password Hashing in the latest MySQL manual"
            elif buffer[4] == '\xff':
                errno, errmsg, sqlstate = self.get_exception(buffer)
                logging.debug("Error %d : %s"%(errno, errmsg))
                return False, "Error %d : %s"%(errno, errmsg)
        except Exception, e:
            return False, e.message

        return True, ""

    def open_connection(self):
        try:
            self.sock = socket.create_connection((self.host, int(self.port)), 10)
            #recv handshake
            buffer = self.recv_plain()
        except Exception,e:
            return False, "Recv handshake error(%s)."%e.message

        try:
            handshake = self.parse_handshake(buffer)
        except Exception,e:
            return False, "Parse handshake error(%s)."%e.message

        #if version < 4.1, return error
        regex_ver = re.compile("^(\d{1,2})\.(\d{1,2})\.(\d{1,3})(.*)")
        match = regex_ver.match(handshake['server_version_original'])
        if not match:
            return False,"Failed parsing MySQL version"
        version = tuple([ int(v) for v in match.groups()[0:3]])
        if version < (4, 1):
            return False,"MySQL Version '%s' is not supported." % handshake['server_version_original']

        self._handshake = handshake
        return True, handshake['server_version_original']

class USPlugin(USPocBase):
    def __init__(self, dict_args = {}):
        super(self.__class__, self).__init__()
        self.info = {
            "name" : 'MySQL 弱口令',                        #插件名称
            "author" : '系统',                               #作者名称
            "product" : 'MySQL',                            #存在漏洞的产品
            "product_version" : 'all',                        #存在漏洞的版本号
            "ref" : [],               #引用的URL
            "official_link" : 'http://www.mysql.com',      #产品官网链接
            "type" : USType.host,                             #插件类型
            "category" : USCategory.misconfiguration,                #漏洞类型
            "level" : USLevel.high,                         #漏洞级别
            "create_date" : '2016-08-27',                     #插件创建时间
            "description" : '''
            存在MySQL弱口令
            ''',                                              #插件描述
            "require_libs" : []                  #插件需要的第三方模块
        }

        self.register_params({                                #插件所需的参数
            USParams.host.str_ip : "127.0.0.1",
            USParams.host.int_port : "3306",
            USParams.host.str_service : "",
            USParams.host.list_dict : []
        }, dict_args)

        self.register_result({                                #插件返回的数据
            USLevel.high : {
                USResult.data : {
                    "user" : "",
                    "pass" : ""
                },
                USResult.desc : ""
            }
        })

    #验证函数，系统根据返回结果来确定是否调用该插件
    def assign(self):
        if 'mysql' in self.params[USParams.host.str_service]:
            return True
        return False

    #漏洞利用函数
    def run(self):
        ip = self.params[USParams.host.str_ip]
        port = self.params[USParams.host.int_port]
        passlist = "123456\nroot\nroot@123\nroot123\nroot1234\nrootroot\nroottoor\nqwert\nqwerty\nP!123456\nP@ssw0rd\nPa$$w0rd\npassport\npasswd\nPassword\n"
        errcnt = 0
        #将自定义字典与系统字典合并
        self.params[USParams.app.list_dict].insert(0, [['root', 'test'], passlist.split('\n')])
        for usernames, passwords in self.params[USParams.app.list_dict]:
            for usr in usernames:
                for psw in passwords:
                    my = MySQL(ip, usr, psw, port)
                    res = my.open_connection()
                    if res[0] == True:
                        errcnt = 0
                        authres = my.do_auth()
                        if authres[0] == True:
                            myverify = MySQL(ip, usr, psw + 'err', port)
                            res = myverify.open_connection()
                            if res[0] == True:
                                authres = myverify.do_auth()
                                if authres[0] == False:
                                    res_data = {}
                                    res_data['user'] = usr
                                    res_data['pass'] = psw
                                    self.append_result(USLevel.high, '主机 %s:%d 存在MySQL弱口令!'%(ip, port), res_data)
                                    return self.results
                    else:
                        errcnt += 1
                        print "Error cnt %d"%errcnt
                        if errcnt > 3:
                            break
                    del my
        return self.results

if __name__ == "__main__":
    usplugin = USPlugin({USParams.host.str_ip:"127.0.0.1", USParams.host.int_port: 3306, USParams.host.str_service : "mysql"})
    if usplugin.assign() == True:
        print usplugin.run()