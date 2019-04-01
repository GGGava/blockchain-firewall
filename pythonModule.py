import json
import web3
import hashlib
import struct

from web3 import Web3, HTTPProvider

w3 = Web3(HTTPProvider('http://192.168.66.244:8545'))

smartAddress = "0x4ac023e56952099a806b591b8722cc4e49805766"

def pythonFunction():
	#print('pacote aceito no python')
	return "pacote aceito no python"

def getAddress():
    #print(smartAddress)
    return smartAddress


def verify(sourceIP, destIP, sourcePort, destPort, proto):
#def verify():    
	#print(w3.eth.getBlock('latest'))

    print(sourceIP)
    print(destIP)
    print(sourcePort)
    print(destPort)
    print(proto)

    m = hashlib.sha256()
    srcipBytes = struct.pack(">I", sourceIP)
    dstipBytes = struct.pack(">I", destIP)
    srcportBytes = struct.pack(">I", sourcePort)
    dstportBytes = struct.pack(">I", destPort)
    prtBytes = proto.encode("utf8")
    
    m.update(srcipBytes + dstipBytes + srcportBytes + dstportBytes + prtBytes)
    print(srcipBytes + dstipBytes + srcportBytes + dstportBytes + prtBytes)

    # m.update(srcipBytes + dstipBytes + dstportBytes + prtBytes)
    # print(srcipBytes + dstipBytes + dstportBytes + prtBytes)
    
    h = '0x' + m.hexdigest()
    print(h)

    with open('contract.abi', 'r') as abi_definition:
    	abi = json.load(abi_definition)
    #address = w3.toChecksumAddress('0x4c1ee65e4fc3428c1b614353335538ed6d91f406')
    address = w3.toChecksumAddress(smartAddress)
    contract = w3.eth.contract(address=address, abi=abi)
    return(contract.functions.verify(h).call())

	#personal.unlockAccount(personal.listAccounts[0], "tigrex", 99999999)
	#150.162.244.102:8545

if __name__ == '__main__':
    verify()
