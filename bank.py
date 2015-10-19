#!/usr/bin/python

import os, sys, getopt, re, socket, Crypto, signal, hashlib, select
from Crypto import Random
from Crypto.Cipher import AES

dev_null = open(os.devnull, 'w')
sys.stderr = dev_null

def encrypt(key,data,iv):
    #add padding since random data or any other data doesn't have '|' hence we use '|'
    datahash = hashlib.sha224(data).digest()
    data += '|'*(16 - len(data+datahash)%16)
    data += datahash
    #print >> sys.stderr,  'encrypting',repr(data),'with',repr(key),repr(iv)
    obj = AES.new(key, AES.MODE_CBC, iv)
    data = obj.encrypt(data)
    #print >> sys.stderr,  'encrypted ',repr(data)
    return data

def decrypt(key,data,iv):
    #print >> sys.stderr,  'encrypted ',repr(data)
    obj = AES.new(key, AES.MODE_CBC, iv)
    data = obj.decrypt(data)
    datahash1 = data[-28:]
    data = data[0:-28]
    #remove padding
    data = data.strip('|')
    #print >> sys.stderr,  'decrypted',repr(data),'with',repr(key),repr(iv)
    datahash2 = hashlib.sha224(data).digest()
    if datahash1 == datahash2:
        return data
    else:
        return None

def senddata(conn, data):
    #print >> sys.stderr, 'sending ', repr(data)
    try:
        readyread, readywrite, readyerror = select.select([],[conn],[], 10)
        for s in readywrite:
            s.sendall(data)
        return True
    except:
        print >> sys.stderr,  'Cannot send data to client'
        conn.close()
        return False

def receivedata(conn, bytes=4096):
    try:
        readyread, readywrite, readyerror = select.select([conn],[],[], 10)
        for s in readyread:
            data = s.recv(bytes)
            return data
        #print >> sys.stderr,  'received ', repr(data)
        raise Exception
    except:
        print >> sys.stderr,  'couldn\'t receive data from client'
        conn.close()
        return None

def generaterandom(bytes):
    rndfile = Random.new()
    d = rndfile.read(bytes)
    # | should not be in randomly generated data
    while '|' in d:
        d = rndfile.read(bytes)
    return d

def signal_term_handler(signal, frame):
    #print >> sys.stderr, 'sigterm called quitting!'
    try:
        sock.close()
    except:
        sys.exit(0)
    sys.exit(0)

accounts = {}

def getfilename(arg):
    name_len = len(arg)
    if name_len < 1 or name_len > 255:
        print >> sys.stderr, 'invalid filename length'
        sys.exit(255)
    elif arg in ['.','..']:
        print >> sys.stderr, 'filename cannot be . or ..'
        sys.exit(255)
    elif not re.match("^([_\-\.0-9a-z]+)$", arg):
        print >> sys.stderr, 'invalid characters in filename'
        sys.exit(255)
    return arg

def getnumber(arg):
    if not re.match("^(0|[1-9][0-9]*)$", arg):
        sys.exit(255)    
    return int(arg)

def main(argv):
    signal.signal(signal.SIGTERM, signal_term_handler)
    signal.signal(signal.SIGINT, signal_term_handler)
    authfile = 'bank.auth'
    port = 3000

    try:
        opts, args = getopt.getopt(argv,"p:s:")
    except getopt.GetoptError:
        exit(255)

    # There are no args only options
    if args != []:
        exit(255)

    for opt, arg in opts:
        #auth file
        if opt == '-s':
            authfile = getfilename(arg)
        
        #port
        elif opt == '-p':
            port = getnumber(arg)
            if port < 1024 or port > 65535:
                sys.exit(255)
    
    # see if auth file exists
    f = None
    try:
        f = open(authfile, 'r')
        f.close()
    except:
        try:
            key = generaterandom(32)
            iv = generaterandom(16)
            ivoriginal = iv
            file = open(authfile, 'w')
            file.write(key+'|'+iv)
            file.close()
            print >> sys.stdout, 'created'
            sys.stdout.flush()
            #print >> sys.stderr, key, iv
        except:
            sys.exit(255)

    if f != None:
        sys.exit(255)

    # print >> sys.stderr,  authfile
    # print >> sys.stderr,  port
    # print >> sys.stderr,  "BANK!"
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server = ('0.0.0.0', port)
    try:
        sock.bind(server)
        sock.listen(10)
        print >> sys.stderr,  "waiting for connections"
        while True:
            iv = ivoriginal
            try:
                #wait to accept a connection
                try:
                    conn, addr = sock.accept()
                    print >> sys.stderr,  'connected to '+addr[0]+':'+str(addr[1])
                except socket.error:
                    print >> sys.stderr,  'Cannot accept connections'
                conn.settimeout(10)
                data = receivedata(conn)
                if data == None:
                    print >> sys.stdout, 'protocol_error'
                    sys.stdout.flush()
                    continue
                data = decrypt(key,data,iv)
                if data == None:
                    print >> sys.stdout, 'protocol_error'
                    sys.stdout.flush()
                    continue
                data = data.split('|')
                if(data[1] == 'Hello'):
                    iv = data[0]
                    uid = generaterandom(32)
                    iv2 = generaterandom(16)

                    data = 'Hello'+'|'+uid+'|'+iv2

                    status = senddata(conn, encrypt(key,data,iv))
                    if status == False:
                        print >> sys.stdout, 'protocol_error'
                        sys.stdout.flush()
                        continue

                    data = receivedata(conn)
                    if data == None:
                        print >> sys.stdout, 'protocol_error'
                        sys.stdout.flush()
                        continue
                    data = decrypt(key,data,iv2)
                    if data == None:
                        print >> sys.stdout, 'protocol_error'
                        sys.stdout.flush()
                        continue
                    data = data.split('|')
                    #check uid
                    iv = data[5]
                    iv2 = generaterandom(16)

                    #print >> sys.stderr, repr(data[0]), repr(uid)
                    if data[0] == uid:
                        mode = data[1]
                        account = data[2]
                        amount = float(data[3])
                        card = data[4]

                        #check if account exists
                        if account in accounts.keys():
                            if mode == 'n':
                                data = uid+'|ERROR|BYE|'+iv2
                                
                                status = senddata(conn, encrypt(key,data,iv))
                                if status == False:
                                    print >> sys.stdout, 'protocol_error'
                                    sys.stdout.flush()
                                    continue
                                
                                data = receivedata(conn)
                                if data == None:
                                    print >> sys.stdout, 'protocol_error'
                                    sys.stdout.flush()
                                    continue
                                data = decrypt(key,data,iv2)
                                if data == None:
                                    print >> sys.stdout, 'protocol_error'
                                    sys.stdout.flush()
                                    continue
                                if data[0] == uid+'|BYE':
                                    conn.close()
                                    continue
                                conn.close()

                            #'w|d|g'
                            else:
                                try:
                                    balance = accounts[account][card]
                                    data = uid+'|SUCCESS'
                                    if mode == 'w':
                                        if(balance - amount < 0.0):
                                            print >> sys.stderr, 'insufficient funds'
                                            raise Exception

                                    elif mode == 'g':
                                        data += '|'+"%0.2f" % (balance)

                                    data += '|BYE|'+iv2
                                    
                                    status = senddata(conn, encrypt(key,data,iv))
                                    if status == False:
                                        print >> sys.stdout, 'protocol_error'
                                        sys.stdout.flush()
                                        continue

                                    data = receivedata(conn)
                                    if data == None:
                                        print >> sys.stdout, 'protocol_error'
                                        sys.stdout.flush()
                                        continue

                                    data = decrypt(key,data,iv2)
                                    if data == None:
                                        print >> sys.stdout, 'protocol_error'
                                        sys.stdout.flush()
                                        continue
                                    #confirm transaction
                                    if data == uid+'|BYE':
                                        if mode == 'w':
                                            accounts[account][card] = round(balance - amount, 2)
                                            print >> sys.stdout, '{\"account\":\"'+account+'\",\"withdraw\":'+"%0.2f" % (amount)+'}'
                                            sys.stdout.flush()
                                        elif mode == 'd':
                                            accounts[account][card] = round(balance + amount, 2)
                                            print >> sys.stdout, '{\"account\":\"'+account+'\",\"deposit\":'+"%0.2f" % (amount)+'}'
                                            sys.stdout.flush()
                                        elif mode == 'g':
                                            print >> sys.stdout, '{\"account\":\"'+account+'\",\"balance\":'+"%0.2f" % (balance)+'}'
                                            sys.stdout.flush()
                                    else:
                                        print >> sys.stdout, 'protocol_error'
                                        sys.stdout.flush()
                                        continue
                                    conn.close()

                                #Error
                                except:
                                    data = uid+'|ERROR|BYE|'+iv2
                                    
                                    status = senddata(conn, encrypt(key,data,iv))
                                    if status == False:
                                        print >> sys.stdout, 'protocol_error'
                                        sys.stdout.flush()
                                        continue
                                    data = receivedata(conn)
                                    if data == None:
                                        print >> sys.stdout, 'protocol_error'
                                        sys.stdout.flush()
                                        continue
                                    
                                    data = decrypt(key,data,iv2)
                                    if data == None:
                                        print >> sys.stdout, 'protocol_error'
                                        sys.stdout.flush()
                                        continue
                                    if data == uid+'|BYE':
                                        conn.close()
                                        continue
                                    conn.close()

                        #account doesn't exist (create new account if mode = 'n')
                        else:
                            if mode == 'n':
                                if amount < 10.00:
                                    data = uid+'|ERROR|BYE|'+iv2
                                    status = senddata(conn, encrypt(key,data,iv))
                                    if status == False:
                                        print >> sys.stdout, 'protocol_error'
                                        sys.stdout.flush()
                                        continue
                                    data = receivedata(conn)
                                    if data == None:
                                        print >> sys.stdout, 'protocol_error'
                                        sys.stdout.flush()
                                        continue
                                    data = decrypt(key,data,iv2)
                                    if data == None:
                                        print >> sys.stdout, 'protocol_error'
                                        sys.stdout.flush()
                                        continue
                                    if data == uid+'|BYE':
                                        conn.close()
                                        continue
                                    conn.close()

                                else:
                                    data = uid+'|SUCCESS|BYE|'+iv2
                                    status = senddata(conn, encrypt(key,data,iv))
                                    if status == False:
                                        print >> sys.stdout, 'protocol_error'
                                        sys.stdout.flush()
                                        continue
                                    data = receivedata(conn)
                                    if data == None:
                                        print >> sys.stdout, 'protocol_error'
                                        sys.stdout.flush()
                                        continue
                                    data = decrypt(key,data,iv2)
                                    if data == None:
                                        print >> sys.stdout, 'protocol_error'
                                        sys.stdout.flush()
                                        continue
                                    if(data == uid+'|BYE'):
                                        accounts.setdefault(account,{card:amount})
                                        print '{\"account\":\"'+account+'\",\"initial_balance\":'+"%0.2f" % (amount)+'}'
                                        sys.stdout.flush()
                                    conn.close()
                            else:
                                data = uid+'|ERROR|BYE|'+iv2
                                status = senddata(conn, encrypt(key,data,iv))
                                if status == False:
                                    print >> sys.stdout, 'protocol_error'
                                    sys.stdout.flush()
                                    continue
                                data = receivedata(conn)
                                if data == None:
                                    print >> sys.stdout, 'protocol_error'
                                    sys.stdout.flush()
                                    continue
                                data = decrypt(key,data,iv2)
                                if data == None:
                                    print >> sys.stdout, 'protocol_error'
                                    sys.stdout.flush()
                                    continue
                                if data == uid+'|BYE':
                                    conn.close()
                                    continue
                                conn.close()
                    else:
                        print >> sys.stderr, 'invalid uid'
                        print >> sys.stdout, 'protocol_error'
                        sys.stdout.flush()
                        conn.close()
            
            except socket.error:
                print >> sys.stdout, 'protocol_error'
                print >> sys.stderr, 'socket error'
                sys.stdout.flush()
                continue
            except SystemExit:
                sock.close()
                sys.exit(0)
            except:
                print >> sys.stdout, 'protocol_error'
                sys.stdout.flush()
                print >> sys.stderr, 'Exception'
                continue

    except SystemExit:
        sock.close()
        sys.exit(0)
    except:
        print >> sys.stderr, 'Cannot bind to given port'
        sys.exit(255)
if __name__ == "__main__":
    main(sys.argv[1:])
