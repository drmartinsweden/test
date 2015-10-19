#!/usr/bin/python
import os, sys, getopt, re, socket, Crypto, hashlib, select
from Crypto import Random
from Crypto.Cipher import AES

dev_null = open(os.devnull, 'w')
sys.stderr = dev_null

# def encrypt(key,data,iv):
#     #hash data
#     datahash = hashlib.sha224(data).digest()
#     print >> sys.stderr,  'encrypting:',repr(data),'with',repr(key),repr(iv)
#     print >> sys.stderr,  'datahash:',repr(datahash)
#     #add padding since random data or any other data doesn't have '|' hence we use '|'
#     data += '|'*(16 - len(data+datahash)%16)
#     #append hash
#     data += datahash
#     obj = AES.new(key, AES.MODE_CBC, iv)
#
#     data = obj.encrypt(data)
#     #print >> sys.stderr,  'encrypted ',repr(data)
#     return data
#
# def decrypt(key,data,iv):
#     #print >> sys.stderr,  'encrypted ',repr(data)
#     obj = AES.new(key, AES.MODE_CBC, iv)
#     data = obj.decrypt(data)
#     print >> sys.stderr,  'decrypted:',repr(data),'with',repr(key),repr(iv)
#     #get hash
#     datahash1 = data[-28:]
#     data = data.strip(datahash1)
#     #remove padding
#     data = data.strip('|')
#     #compare hash
#     print >> sys.stderr,  'decrypted:',repr(data),'with',repr(key),repr(iv)
#     datahash2 = hashlib.sha224(data).digest()
#     print >> sys.stderr,  'received datahash:',repr(datahash1)
#     print >> sys.stderr,  'computed datahash:',repr(datahash2)
#     if datahash2 == datahash1:
#         return data
#     else:
#         print >> sys.stderr,  'Hash mismatch!'
#         return None


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

def generaterandom(bytes):
    rndfile = Random.new()
    d = rndfile.read(bytes)
    # | should not be in randomly generated data
    while '|' in d:
        d = rndfile.read(bytes)
    return d

def senddata(sock, data):
    #print >> sys.stderr, 'sending ', repr(data)
    try:
        readyread, readywrite, readyerror = select.select([],[sock],[], 10)
        for s in readywrite:
            s.sendall(data)
        return True
    except:
        print >> sys.stderr,  'Cannot send data to server'
        sock.close()
        return False

def receivedata(sock, bytes=4096):
    try:
        readyread, readywrite, readyerror = select.select([sock],[],[], 10)
        for s in readyread:
            data = s.recv(bytes)
            return data
        #print >> sys.stderr,  'received ', repr(data)
        raise Exception
    except:
        print >> sys.stderr,  'couldn\'t receive data from server'
        sock.close()
        return None

def getamount(arg):
    temp = arg.split('.')
    amount = 0.0
    if len(temp) == 2:
        if not re.match("^(0|[1-9][0-9]*)$", temp[0]):
            print >> sys.stderr, 'invalid amount specified'
            sys.exit(255)
        elif not re.match('^[0-9]{2}$', temp[1]):
            print >> sys.stderr, 'invalid amount specified'
            sys.exit(255)
        amount = float(arg)
        if amount < 0.0 or amount > 4294967295.99:
            print >> sys.stderr, 'invalid amount range'
            sys.exit(255)
        return amount
    else:
        print >> sys.stderr, 'invalid amount specified'
        sys.exit(255)

        
def getnumber(arg):
    if not re.match("^(0|[1-9][0-9]*)$", arg):
        print >> sys.stderr, 'invalid number specified'
        sys.exit(255)    
    return int(arg)
    
    
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


def main(argv):
    authfile = 'bank.auth'
    ipaddr = '127.0.0.1'
    port = 3000
    account = ''
    mode = ''
    cardfile = ''
    amount = 0
    try:
        opts, args = getopt.getopt(argv,"s:i:p:c:a:n:d:w:g")
    except getopt.GetoptError:
        print >> sys.stderr, 'invalid options specified'
        sys.exit(255)

    # There are no args only options
    if args != []:
        print >> sys.stderr, 'invalid arguments'
        sys.exit(255)

    for opt, arg in opts:
        #account name
        if opt == '-a':
            name_len = len(arg)
            if name_len < 1 or name_len > 255:
                print >> sys.stderr, 'invalid account name length'
                sys.exit(255)
            elif re.match("^([_\-\.0-9a-z]+)$",arg):
                account = arg
            else:
                print >> sys.stderr, 'invalid account name characters'
                sys.exit(255)

        #auth file
        elif opt == '-s':
            authfile = getfilename(arg)

        #IPv4 address
        elif opt == '-i':
            addr = arg.split('.')
            if len(addr) == 4:
                for x in addr:
                    num = getnumber(x)
                    if num < 0 or num > 254:
                        print >> sys.stderr, 'invalid ip address'
                        sys.exit(255)
            else:
                print >> sys.stderr, 'invalid ip address'
                sys.exit(255)

            ipaddr = arg
        
        #port
        elif opt == '-p':
            port = getnumber(arg)
            if port < 1024 or port > 65535:
                print >> sys.stderr, 'invalid port specified'
                sys.exit(255)
        
        #card file name
        elif opt == '-c':
            cardfile = getfilename(arg)

        ##modes
        #mode:create new account
        elif opt == '-n':
            # mode already set. multiple modes specified raise error
            if mode != '':
                print >> sys.stderr, 'multiple modes specified?'
                sys.exit(255)
            else:
                mode = 'n'
                amount = getamount(arg)

        #mode:deposit
        elif opt == '-d':
            # mode already set. multiple modes specified raise error
            if mode != '':
                print >> sys.stderr, 'multiple modes specified?'
                sys.exit(255)
            else:
                mode = 'd'
                amount = getamount(arg)

        #mode:withdraw
        elif opt == '-w':
            # mode already set. multiple modes specified raise error
            if mode != '':
                print >> sys.stderr, 'multiple modes specified?'
                sys.exit(255)
            else:
                mode = 'w'
                amount = getamount(arg)

        #mode:get current balance
        elif opt == '-g':
            # mode already set. multiple modes specified raise error
            if mode != '':
                print >> sys.stderr, 'multiple modes specified?'
                sys.exit(255)
            else:
                mode = 'g'
        
        else:
            print >> sys.stderr,  'Invalid parameters'
            sys.exit(255)
    
    # No account specified
    if account == '':
        print >> sys.stderr, 'no account specified'
        sys.exit(255)
    
    #card file not specified
    if cardfile == '':
        cardfile = account+'.card'
    
    
    #########################################
    ########### main ########################
    # try to open auth file
    try:
        f = open(authfile, 'r')
        key = f.read()
        f.close()
        key = key.split('|')
        iv = key[1]
        key = key[0]
        #print >> sys.stderr, key, iv
    except:
        print >> sys.stderr, 'cannot open auth file specified'
        sys.exit(255)

    # No mode specified
    if mode == '':
        print >> sys.stderr, 'invalid mode'
        sys.exit(255)

    # print >> sys.stderr,  authfile
    # print >> sys.stderr,  ipaddr
    # print >> sys.stderr,  port
    # print >> sys.stderr,  account
    # print >> sys.stderr,  mode
    # print >> sys.stderr,  cardfile
    # print >> sys.stderr,  amount
    #
    # print >> sys.stderr,  "ATM!"

    # PRIOR TO SERVER CONNECTION
    card = None
    card_exists_flag = False
    try:
        #get card from file
        f = open(cardfile, 'r')
        card = f.read()
        f.close()
        card_exists_flag = True
    except:
        pass

    #Create new account
    if mode == 'n':
        if amount < 10.00:
            print >> sys.stderr, 'amount should be >= 10.00'
            # sock.close()
            sys.exit(255)

        # if file already exists exit
        if card_exists_flag:
            print >> sys.stderr, 'card file already exists'
            # sock.close()
            sys.exit(255)

        #generate random card file (AES key)
        #print >> sys.stderr,  'Generating card file'
        card = generaterandom(32)
        try:
            f = open(cardfile, 'w')
            f.write(card)
            f.close()
            print >> sys.stderr, 'card file written', cardfile
            card_exists_flag = True
        except:
            print >> sys.stderr, 'cannot write card file'
            # sock.close()
            sys.exit(255)

    #Deposit or withdraw
    elif mode in ['d','w']:
        if amount <= 0.00:
            # sock.close()
            print >> sys.stderr, 'invalid amount specified'
            sys.exit(255)

    # No card by this point, fail
    if card_exists_flag == False:
        print >> sys.stderr, 'can\'t open card file'
        sys.exit(255)

    # SERVER CONNECTION START

    # Hello server
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server = (ipaddr, port)
    sock.settimeout(10)
    try:
        sock.connect(server)
        iv2 = generaterandom(16)
        data = iv2+'|Hello'
        status = senddata(sock, encrypt(key,data,iv))
        if status == False:
            if mode == 'n':
                os.remove(cardfile)
                print >> sys.stderr, 'deleted cardfile'
            sys.exit(63)
    except:
        print >> sys.stderr, 'cannot connect to server'
        if mode == 'n':
            os.remove(cardfile)
            print >> sys.stderr, 'deleted cardfile'
        sys.exit(63)
    
    try:
        # get transaction uid and iv
        ################ ISSUE #############
        data = receivedata(sock)
        if data == None:
                raise Exception
        data = decrypt(key,data,iv2)
        if data == None:
            raise Exception
        data = data.split('|')
        if data[0] == 'Hello':
            uid = data[1]
            iv = data[2]
        else:
            print >> sys.stderr, 'invalid Hello'
            raise Exception
    except:
        print >> sys.stderr, 'cannot recieve data from server'
        if mode == 'n':
            os.remove(cardfile)
            print >> sys.stderr, 'deleted cardfile'
        sock.close()
        sys.exit(63)

    #send card to server along with amount and account
    iv2 = generaterandom(16)
    data = uid+'|'+mode+'|'+account+'|'+str(amount)+'|'+card+'|'+iv2
    
    status = senddata(sock, encrypt(key,data,iv))
    if status == False:
        if mode == 'n':
            os.remove(cardfile)
            print >> sys.stderr, 'deleted cardfile'
        sys.exit(63)
    
    data = receivedata(sock)
    if data == None:
        if mode == 'n':
            os.remove(cardfile)
            print >> sys.stderr, 'deleted cardfile'
        sys.exit(63)

    data = decrypt(key,data,iv2)
    if data == None:
        if mode == 'n':
            os.remove(cardfile)
            print >> sys.stderr, 'deleted cardfile'
        sys.exit(63)
    data = data.split('|')
    if data[0] == uid:
        iv = data[-1]
        if data[1] == 'ERROR':
            if mode == 'n':
                os.remove(cardfile)
                print >> sys.stderr, 'deleted cardfile'
            
            status = senddata(sock, encrypt(key,uid+'|BYE',iv))
            if status == False:
                sys.exit(63)
            sock.close()
            sys.exit(255)

        #recieve ACK, terminate connection and print >> sys.stderr,  JSON
        elif data[1] == 'SUCCESS':
            status = senddata(sock, encrypt(key,uid+'|BYE',iv))
            sock.close()
            if status == False:
                if mode == 'n':
                    os.remove(cardfile)
                    print >> sys.stderr, 'deleted cardfile'
                sys.exit(63)

            if mode == 'n':
                print >> sys.stdout, '{\"account\":\"'+account+'\",\"initial_balance\":'+"%0.2f" % (amount)+'}'
                sys.stdout.flush()
                sys.exit(0)
            elif mode == 'd':
                print >> sys.stdout, '{\"account\":\"'+account+'\",\"deposit\":'+"%0.2f" % (amount)+'}'
                sys.stdout.flush()
                sys.exit(0)
            elif mode == 'w':
                print >> sys.stdout, '{\"account\":\"'+account+'\",\"withdraw\":'+"%0.2f" % (amount)+'}'
                sys.stdout.flush()
                sys.exit(0)
            elif mode == 'g':
                print >> sys.stdout, '{\"account\":\"'+account+'\",\"balance\":'+"%0.2f" % (float(data[2]))+'}'
                sys.stdout.flush()
                sys.exit(0)
    else:
        print >> sys.stderr, 'invalid uid'
        if mode == 'n':
            os.remove(cardfile)
            print >> sys.stderr, 'deleted cardfile'
        sock.close()
        sys.exit(63)

if __name__ == "__main__":
    main(sys.argv[1:])
