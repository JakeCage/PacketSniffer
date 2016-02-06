# Originally:

#-------------------------------------------------------------------------------
# Name:        iflist.py
#
# Author:      Massimo Ciani
#
# Created:     01/09/2009
# Copyright:   (c) Massimo Ciani 2009
#
#-------------------------------------------------------------------------------

# Modified for general use

from ctypes import *
from winpcapy import *
import string
import time
import socket as sk
import platform

#
# Basic structures and data definitions for AF_INET family
#
class S_un_b(Structure):
    _fields_ = [("s_b1",c_ubyte),
                ("s_b2",c_ubyte),
                ("s_b3",c_ubyte),
                ("s_b4",c_ubyte)]

class S_un_w(Structure):
    _fields_ = [("s_wl",c_ushort),
                ("s_w2",c_ushort)]

class S_un(Union):
    _fields_ = [("S_un_b",S_un_b),
                ("S_un_w",S_un_w),
                ("S_addr",c_ulong)]

class in_addr(Structure):
    _fields_ = [("S_un",S_un)]



class sockaddr_in(Structure):
    _fields_ = [("sin_family", c_ushort),
                ("sin_port", c_ushort),
                ("sin_addr", in_addr),
                ("sin_zero", c_char * 8)]

#
# Basic structures and data definitions for AF_INET6 family
#
class _S6_un(Union):
    _fields_=[("_S6_u8",c_ubyte *16),
              ("_S6_u16",c_ushort *8),
              ("_S6_u32",c_ulong *4)]

class in6_addr(Structure):
    _fields_=[("_S6_un",_S6_un)]

s6_addr=_S6_un._S6_u8
s6_addr16=_S6_un._S6_u16
s6_addr32=_S6_un._S6_u32

IN6_ADDR=in6_addr
PIN6_ADDR=POINTER(in6_addr)
LPIN6_ADDR=POINTER(in6_addr)

class sockaddr_in6(Structure):
    _fields_=[("sin6_family",c_short),
              ("sin6_port",c_ushort),
              ("sin6_flowinfo",c_ulong),
              ("sin6_addr",in6_addr),
              ("sin6_scope_id",c_ulong)]

SOCKADDR_IN6=sockaddr_in6
PSOCKADDR_IN6=POINTER(sockaddr_in6)
LPSOCKADDR_IN6=POINTER(sockaddr_in6)


def iptos(in_):
   return "%d.%d.%d.%d" % (in_.s_b1,in_.s_b2 , in_.s_b3, in_.s_b4)

def ip6tos(in_):
    addr=in_.contents.sin6_addr._S6_un._S6_u16
    vals=[]
    for x in range(0,8):
        vals.append(sk.ntohs(addr[x]))
    host= ("%x:%x:%x:%x:%x:%x:%x:%x" % tuple(vals))
    port=0
    flowinfo=in_.contents.sin6_flowinfo
    scopeid=in_.contents.sin6_scope_id
    flags=sk.NI_NUMERICHOST | sk.NI_NUMERICSERV
    retAddr,retPort=sk.getnameinfo((host, port, flowinfo, scopeid), flags)
    return retAddr