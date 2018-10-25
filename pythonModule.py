import json
import web3
import hashlib
import struct

from web3 import Web3, HTTPProvider

w3 = Web3(HTTPProvider('http://150.162.244.102:8545'))

def pythonFunction():
	#print('pacote aceito no python')
	return "pacote aceito no python"


def verify(sourceIP, destIP, sourcePort, destPort, proto):
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
    
    m.update(srcipBytes + dstipBytes + srcportBytes + dstportBytes + prtBytes)  # + destIP + sourcePort + destPort + proto)
    print(srcipBytes + dstipBytes + srcportBytes + dstportBytes + prtBytes)
    
    h = m.hexdigest()
    print(h)

    with open('contract.abi', 'r') as abi_definition:
    	abi = json.load(abi_definition)

    address = w3.toChecksumAddress('0x890dbc7b4f983167939b72c515f9a99972566081')
    contract = w3.eth.contract(address=address, abi=abi)
    return(contract.functions.verify(h).call())

	#personal.unlockAccount(personal.listAccounts[0], "tigrex", 99999999)
	#150.162.244.102:8545


