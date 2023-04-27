import binascii
import json
import random
import sha3
import sys

from asn1crypto import pem, x509
from asn1crypto import keys
from hashlib import sha256
from random import randint
from web3 import Web3, HTTPProvider


# ganache address
blockchain_address = 'http://127.0.0.1:7545'

# Client instance to interact with the blockchain
web3 = Web3(HTTPProvider(blockchain_address))

# get the first account
web3.eth.defaultAccount = web3.eth.accounts[0]

# Path to the compiled contract JSON file
compiled_contract_path = 'build/contracts/X509Parse.json'


# load contract ABI
def load_contract():
    # load contract info as JSON
    with open(compiled_contract_path) as file:
        contract_json = json.load(file)

        # fetch contract's abi - necessary to call its functions
        contract_abi = contract_json['abi']

    # Fetching deployed contract reference
    contract = web3.eth.contract(
        address = deployed_contract_address, abi = contract_abi)

    return contract

# load certificate from file
def load_cert(cert_file):
    with open(cert_file, 'rb') as f:
        der_bytes = f.read()
        if pem.detect(der_bytes):
            type_name, headers, der_bytes = pem.unarmor(der_bytes)

    cert = x509.Certificate.load(der_bytes)

    return cert


def verify_root_cert(contract):
    # load root certificate
    cert = load_cert('tests/certs/rootCert.pem')
    cert_bytes = cert.dump()
    print(cert_bytes.hex())

    # add certificate and get transaction receipt
    tx_hash = contract.functions.addRootCert(cert_bytes).transact()
    tx_receipt = web3.eth.wait_for_transaction_receipt(tx_hash)
    print("Receipt for root certificate:")
    print(tx_receipt)
    print("--------------------")





def verify_report_cert(contract):
    # load intermediate certificate
    cert = load_cert('tests/certs/reportCert.pem')
    cert_bytes = cert.dump()

    # add certificate and get transaction receipt
    tx_hash = contract.functions.addReportCert(cert_bytes).transact()
    tx_receipt = web3.eth.wait_for_transaction_receipt(tx_hash)
    print("Receipt for report certificate:")
    print(tx_receipt)
    print("--------------------")

    # retrieve the intermediate public key
    output = contract.functions.getReportPubKey().call()
    print("report cert public key:")
    print(output)



def verify_decent_contract(contract):
    # decent_cert = load_cert('certs/decentServerCert.pem')
    decent_cert = load_cert('tests/certs/decentServerCert.pem')
    cert_bytes = decent_cert.dump()

    # add certificate and get transaction receipt
    tx_hash = contract.functions.addDecentCert(cert_bytes).transact()
    tx_receipt = web3.eth.wait_for_transaction_receipt(tx_hash)
    print("Receipt for transaction certificate:")
    print(tx_receipt)
    print("--------------------\n\n")

def extract_parameters():
    cert = load_cert('certs/rootCert.pem')
    cert_bytes = cert.dump()
    public_key = cert['tbs_certificate']['subject_public_key_info']
    print(public_key.dump().hex())


    # extracing key components
    # exponent = public_key['public_key']['public_exponent']
    # print("exponent: ", hex(exponent))

    # msg = cert['tbs_certificate'].dump()
    # msh_hash = sha256(msg).hexdigest()
    # print("msg: ", msh_hash)

    # signature = cert['signature_value'].native
    # print("signature: ", signature.hex())


if __name__ == '__main__':
    # check if contract address was provided
    if len(sys.argv) < 2:
        print("Usage: python3 testcontract.py <X509 Parse Contract Address>")
        exit()

    deployed_contract_address = sys.argv[1]

    contract = load_contract()
    verify_root_cert(contract)
    verify_decent_contract(contract)
    # extract_parameters()


