#!/usr/bin/env python3
# -*- coding:utf-8 -*-
###
# Copyright (c) 2024 Haofan Zheng
# Use of this source code is governed by an MIT-style
# license that can be found in the LICENSE file or at
# https://opensource.org/licenses/MIT.
###


import base64
import binascii
import json
import os

from typing import Any, List, Tuple

from cryptography.x509 import (
	load_der_x509_certificate,
	load_pem_x509_certificate,
	Certificate,
	ObjectIdentifier
)
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.types import CertificatePublicKeyTypes
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.hazmat.primitives.serialization import PublicFormat

from eth_utils.crypto import keccak
from eth_utils.address import to_checksum_address

from eth_keys.backends import NativeECCBackend
from eth_keys.datatypes import Signature

from rlp import decode


THIS_DIR = os.path.dirname(os.path.abspath(__file__))
TESTS_DIR = os.path.dirname(THIS_DIR)

IAS_ROOT_PEM_PATH = os.path.join(THIS_DIR, 'CertIASRoot.pem')
IAS_REP_PEM_PATH = os.path.join(THIS_DIR, 'CertIASReport.pem')
DECENT_SVR_PEM_PATH = os.path.join(THIS_DIR, 'CertDecentServer.pem')
DECENT_APP_PEM_PATH = os.path.join(THIS_DIR, 'CertDecentApp.pem')

CERTS_SOL_PATH = os.path.join(TESTS_DIR, 'TestCerts.sol')


class ASN1Parser(object):

	def __init__(self,) -> None:
		super(ASN1Parser, self).__init__()

	def _ParseSeq(self, data: bytes) -> List[Any]:
		res = []
		while len(data) > 0:
			# Parse the next element
			elem, data = self._ParseElement(data)
			res.append(elem)

		return res

	def _ParseInt(self, data: bytes) -> int:
		return int.from_bytes(data, 'big')

	def _ParseElement(self, data: bytes) -> Tuple[Any, bytes]:
		# Get the tag
		tag = data[0]
		data = data[1:]

		# Get the length
		if data[0] & 0x80:
			# Multi-byte length
			numBytes = data[0] & 0x7F
			lenData = data[1:1+numBytes]
			length = int.from_bytes(lenData, 'big')
			value = data[1+numBytes:1+numBytes+length]
			data = data[1+numBytes+length:]
		else:
			# Single byte length
			length = data[0]
			value = data[1:1+length]
			data = data[1+length:]

		# Parse the value
		if tag == 0x02:
			# Integer
			value = self._ParseInt(value)
		elif tag == 0x30:
			# Sequence
			value = self._ParseSeq(value)

		return value, data

	def Parse(self, data: bytes) -> Any:
		obj, data = self._ParseElement(data)

		if len(data) > 0:
			raise ValueError('Extra data after parsing object')

		return obj


def AddIndent(
	lines: List[str],
	indentLevel: int,
	indentChar: str = '    '
) -> List[str]:
	return [
		((indentChar * indentLevel) + line) for line in lines
	]


def FormatHex(
	dataHex: str,
	indentLevel: int,
	indentChar: str = '    '
) -> List[str]:

	# Split into 32 bytes per line
	dataHexLines = [
		('hex"' + dataHex[i:i+64] + '"') for i in range(0, len(dataHex), 64)
	]

	dataHexLines[-1] += ';'

	return AddIndent(dataHexLines, indentLevel, indentChar)


def FormatBytes(
	data: bytes,
	indentLevel: int,
	indentChar: str = '    '
) -> List[str]:
	derHex = data.hex()

	return FormatHex(derHex, indentLevel, indentChar)


def FormatInt(
	num: int,
	indentLevel: int,
	indentChar: str = '    '
) -> str:
	intHex = hex(num)

	# Remove the '0x' prefix
	intHex = intHex[2:]
	# Pad with 0s to make it even length
	if len(intHex) % 2 == 1:
		intHex = '0' + intHex

	return FormatHex(intHex, indentLevel, indentChar)


def WriteRSAKey(
	pkey: CertificatePublicKeyTypes,
	varPrefix: str
) -> List[str]:
	outLines = []

	## Write key DER
	outLines.append(f'    bytes constant {varPrefix}_CERT_KEY_DER =')
	outLines += FormatBytes(
		cert.public_key().public_bytes(
			encoding=Encoding.DER,
			format=PublicFormat.SubjectPublicKeyInfo
		),
		2
	)
	outLines.append('')

	## Write key modulus and exponent
	pubKeyNum = pkey.public_numbers()
	outLines.append(f'    bytes constant {varPrefix}_CERT_KEY_MOD =')
	outLines += FormatInt(pubKeyNum.n, 2)
	outLines.append('')
	eStr, = FormatInt(pubKeyNum.e, 0)
	outLines.append(f'    bytes constant {varPrefix}_CERT_KEY_EXP = {eStr}')
	outLines.append('')

	return outLines


class ECPubKey(object):

	def __init__(
		self,
		pkey: CertificatePublicKeyTypes,
	) -> None:
		super(ECPubKey, self).__init__()

		self.bytes = \
			pkey.public_numbers().x.to_bytes(32, 'big') + \
			pkey.public_numbers().y.to_bytes(32, 'big')
		self.x = pkey.public_numbers().x
		self.y = pkey.public_numbers().y
		self.address = to_checksum_address(keccak(self.bytes)[-20:])


def WriteECKey(
	pkey: CertificatePublicKeyTypes,
	varPrefix: str
) -> List[str]:
	outLines = []

	## Write key der
	outLines.append(f'    bytes constant {varPrefix}_CERT_KEY_DER =')
	outLines += FormatBytes(
		pkey.public_bytes(
			encoding=Encoding.DER,
			format=PublicFormat.SubjectPublicKeyInfo
		),
		2
	)
	outLines.append('')

	ecPubKey = ECPubKey(pkey)

	outLines.append(f'    bytes32 constant {varPrefix}_CERT_KEY_X =')
	outLines += FormatInt(ecPubKey.x, 2)
	outLines.append(f'    bytes32 constant {varPrefix}_CERT_KEY_Y =')
	outLines += FormatInt(ecPubKey.y, 2)
	outLines.append('')

	outLines.append(f'    bytes constant {varPrefix}_CERT_KEY_BYTES =')
	outLines += FormatBytes(ecPubKey.bytes, 2)
	outLines.append('')

	outLines.append(f'    address constant {varPrefix}_CERT_KEY_ADDR =')
	outLines += AddIndent(
		[
			(ecPubKey.address + ';'),
			# ('0x' + (keccak(pkeyBytes)[:20].hex()) + ';'),
		],
		2
	)
	outLines.append('')

	return outLines


def WriteCert(
	cert: Certificate,
	varPrefix: str
) -> List[str]:
	outLines = []

	## Write entire DER encoded certificate
	outLines.append(f'    bytes constant {varPrefix}_CERT_DER =')
	outLines += FormatBytes(cert.public_bytes(Encoding.DER), 2)
	outLines.append('')

	## Write TBS portion of certificate
	outLines.append(f'    bytes constant {varPrefix}_CERT_TBS =')
	outLines += FormatBytes(cert.tbs_certificate_bytes, 2)
	outLines.append('')

	## Write validity period
	notBefore = int(cert.not_valid_before_utc.timestamp())
	notAfter = int(cert.not_valid_after_utc.timestamp())
	outLines.append(f'    uint256 constant {varPrefix}_CERT_NOT_BEFORE = {notBefore};')
	outLines.append(f'    uint256 constant {varPrefix}_CERT_NOT_AFTER  = {notAfter};')
	outLines.append('')

	## Write CN, C, L, ST, O
	subject = cert.subject
	cnObjs = subject.get_attributes_for_oid(NameOID.COMMON_NAME)
	if len(cnObjs) > 0:
		cn = cnObjs[0].value
		outLines.append(f'    string constant {varPrefix}_CERT_NAME_CN = "{cn}";')
	cObjs = subject.get_attributes_for_oid(NameOID.COUNTRY_NAME)
	if len(cObjs) > 0:
		c  = cObjs[0].value
		outLines.append(f'    string constant {varPrefix}_CERT_NAME_C  = "{c}";')
	lObjs = subject.get_attributes_for_oid(NameOID.LOCALITY_NAME)
	if len(lObjs) > 0:
		l  = lObjs[0].value
		outLines.append(f'    string constant {varPrefix}_CERT_NAME_L  = "{l}";')
	stObjs = subject.get_attributes_for_oid(NameOID.STATE_OR_PROVINCE_NAME)
	if len(stObjs) > 0:
		st = stObjs[0].value
		outLines.append(f'    string constant {varPrefix}_CERT_NAME_ST = "{st}";')
	oObjs = subject.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)
	if len(oObjs) > 0:
		o  = oObjs[0].value
		outLines.append(f'    string constant {varPrefix}_CERT_NAME_O  = "{o}";')
	outLines.append('')

	## Write Cert Hash
	digest = hashes.Hash(cert.signature_hash_algorithm)
	digest.update(cert.tbs_certificate_bytes)
	tbsHash = digest.finalize()
	outLines.append(f'    bytes32 constant {varPrefix}_CERT_HASH =')
	outLines += FormatBytes(tbsHash, 2)
	outLines.append('')

	## Write Cert Signature
	outLines.append(f'    bytes constant {varPrefix}_CERT_SIGN =')
	outLines += FormatBytes(cert.signature, 2)
	outLines.append('')

	return outLines


def WriteCertWithRSAKey(
	cert: Certificate,
	varPrefix: str
) -> List[str]:
	outLines = []

	## Write common certificate fields
	outLines += WriteCert(cert, varPrefix)

	## Write key
	outLines += WriteRSAKey(cert.public_key(), varPrefix)

	return outLines


def GuessVValue(
	hashVal: bytes,
	rVal: int,
	sVal: int,
	pubKey: ECPubKey,
) -> int:
	possibleVVals = [0, 1]
	for vVal in possibleVVals:
		pkey = NativeECCBackend().ecdsa_recover(
			hashVal,
			Signature(vrs=(vVal, rVal, sVal))
		)
		# print(pubKey.address.lower(), pkey.to_address().lower())
		if pubKey.address.lower() == pkey.to_address().lower():
			return vVal + 27

	raise ValueError('Could not guess v value')


def WriteCertWithECKey(
	cert: Certificate,
	varPrefix: str,
	issuerPubKey: ECPubKey,
) -> List[str]:
	outLines = []

	## Write common certificate fields
	outLines += WriteCert(cert, varPrefix)

	ecNumbers = ASN1Parser().Parse(cert.signature)

	## Guess the v value
	digest = hashes.Hash(cert.signature_hash_algorithm)
	digest.update(cert.tbs_certificate_bytes)
	tbsHash = digest.finalize()
	vVal = GuessVValue(
		hashVal=tbsHash,
		rVal=ecNumbers[0],
		sVal=ecNumbers[1],
		pubKey=issuerPubKey,
	)

	## Write Cert Signature EC Numbers
	outLines.append(f'    uint8   constant {varPrefix}_CERT_SIGN_V = {vVal};')
	outLines.append(f'    bytes32 constant {varPrefix}_CERT_SIGN_R =')
	outLines += FormatInt(ecNumbers[0], 2)
	outLines.append(f'    bytes32 constant {varPrefix}_CERT_SIGN_S =')
	outLines += FormatInt(ecNumbers[1], 2)
	outLines.append('')

	## Write key
	outLines += WriteECKey(cert.public_key(), varPrefix)

	return outLines


DECENT_CERT_VER_OID          = ObjectIdentifier('1.3.6.1.4.1.62021.1.1.1')
DECENT_CERT_TYPE_OID         = ObjectIdentifier('1.3.6.1.4.1.62021.1.1.2')
DECENT_CERT_KEYRING_HASH_OID = ObjectIdentifier('1.3.6.1.4.1.62021.1.1.4')
DECENT_CERT_APP_HASH_OID     = ObjectIdentifier('1.3.6.1.4.1.62021.1.1.5')
DECENT_CERT_AUTH_LIST_OID    = ObjectIdentifier('1.3.6.1.4.1.62021.1.1.6')
DECENT_CERT_PLAT_ID_OID      = ObjectIdentifier('1.3.6.1.4.1.62021.1.1.7')

DECENT_CERT_SGX_STD_REP_DATA = ObjectIdentifier('1.3.6.1.4.1.62021.1.1.3.1.1')
DECENT_CERT_SGX_REP_RLP      = ObjectIdentifier('1.3.6.1.4.1.62021.1.1.3.1.2')


def WriteDecentSvrCert(
	cert: Certificate,
	varPrefix: str
) -> List[str]:
	outLines = []

	ecPubKey = ECPubKey(cert.public_key())

	## Write common certificate fields
	outLines += WriteCertWithECKey(cert, varPrefix, issuerPubKey=ecPubKey)

	## Write Decent Certificate Fields
	### Version
	decentVer = cert.extensions.get_extension_for_oid(DECENT_CERT_VER_OID).value
	decentVer = decentVer.public_bytes().decode()
	outLines.append(f'    string constant {varPrefix}_CERT_VERSION = "{decentVer}";')
	outLines.append('')
	### Type
	decentType = cert.extensions.get_extension_for_oid(DECENT_CERT_TYPE_OID).value
	decentType = decentType.public_bytes().decode()
	outLines.append(f'    string constant {varPrefix}_CERT_TYPE = "{decentType}";')
	outLines.append('')
	### Keyring Hash
	decentKeyringHash = cert.extensions.get_extension_for_oid(DECENT_CERT_KEYRING_HASH_OID).value
	decentKeyringHash = decentKeyringHash.public_bytes()
	outLines.append(f'    bytes constant {varPrefix}_CERT_KEYRING =')
	outLines += FormatBytes(decentKeyringHash, 2)
	outLines.append('')
	### Platform ID
	decentPlatId = cert.extensions.get_extension_for_oid(DECENT_CERT_PLAT_ID_OID).value
	decentPlatId = decentPlatId.public_bytes()
	outLines.append(f'    bytes32 constant {varPrefix}_CERT_PLAT_ID =')
	outLines += FormatBytes(decentPlatId, 2)
	outLines.append('')
	### SGX specific fields
	#### SGX Standard Report Data
	decentSgxStdRepData = cert.extensions.get_extension_for_oid(DECENT_CERT_SGX_STD_REP_DATA).value
	decentSgxStdRepData = decentSgxStdRepData.public_bytes()
	outLines.append(f'    bytes constant {varPrefix}_CERT_STD_REP_DATA =')
	outLines += FormatBytes(decentSgxStdRepData, 2)
	outLines.append('')
	#### SGX Report RLP
	decentSgxRepRLP = cert.extensions.get_extension_for_oid(DECENT_CERT_SGX_REP_RLP).value
	decentSgxRepRLP = decentSgxRepRLP.public_bytes()
	outLines.append(f'    bytes constant {varPrefix}_CERT_ATT_REP_RLP =')
	outLines += FormatBytes(decentSgxRepRLP, 2)
	outLines.append('')

	parsedRep = decode(decentSgxRepRLP)
	repSignerCert: bytes = parsedRep[0][0]
	repJson: bytes = parsedRep[1]
	repSign: bytes = parsedRep[2]

	##### Report Signer Certificate
	outLines.append(f'    bytes constant {varPrefix}_CERT_ATT_REP_CERT =')
	outLines += FormatBytes(repSignerCert, 2)
	outLines.append('')
	##### Report JSON
	outLines.append(f'    bytes constant {varPrefix}_CERT_ATT_REP_JSON =')
	outLines += FormatBytes(repJson, 2)
	outLines.append('')
	##### Report Signature
	outLines.append(f'    bytes constant {varPrefix}_CERT_ATT_REP_SIGN =')
	outLines += FormatBytes(repSign, 2)
	outLines.append('')

	###### Enclave Hash
	rep = json.loads(repJson.decode())
	quoteStatus = rep['isvEnclaveQuoteStatus']
	quoteBody = rep['isvEnclaveQuoteBody']
	quoteBody = base64.b64decode(quoteBody)
	enclaveHash = quoteBody[112:112+32]
	repDataField = quoteBody[368:368+64]
	outLines.append(f'    string  constant {varPrefix}_CERT_QUOTE_ST  = "{quoteStatus}";')
	outLines.append('')
	outLines.append(f'    bytes32 constant {varPrefix}_CERT_ENCL_HASH =')
	outLines += FormatBytes(enclaveHash, 2)
	outLines.append('')
	outLines.append(f'    bytes constant {varPrefix}_CERT_REP_DATA =')
	outLines += FormatBytes(repDataField, 2)
	outLines.append('')

	return outLines


def WriteDecentAppCert(
	cert: Certificate,
	varPrefix: str,
	serverPubKey: ECPubKey,
) -> List[str]:
	outLines = []

	## Write common certificate fields
	outLines += WriteCertWithECKey(cert, varPrefix, issuerPubKey=serverPubKey)

	## Write Decent Certificate Fields
	### Version
	decentVer = cert.extensions.get_extension_for_oid(DECENT_CERT_VER_OID).value
	decentVer = decentVer.public_bytes().decode()
	outLines.append(f'    string constant {varPrefix}_CERT_VERSION = "{decentVer}";')
	outLines.append('')
	### Type
	decentType = cert.extensions.get_extension_for_oid(DECENT_CERT_TYPE_OID).value
	decentType = decentType.public_bytes().decode()
	outLines.append(f'    string constant {varPrefix}_CERT_TYPE = "{decentType}";')
	outLines.append('')
	### App Hash
	decentAppHash = cert.extensions.get_extension_for_oid(DECENT_CERT_APP_HASH_OID).value
	decentAppHash = decentAppHash.public_bytes()
	outLines.append(f'    bytes32 constant {varPrefix}_CERT_ENCL_HASH =')
	outLines += FormatBytes(decentAppHash, 2)
	outLines.append('')
	### Auth List
	decentAuthList = cert.extensions.get_extension_for_oid(DECENT_CERT_AUTH_LIST_OID).value
	decentAuthList = decentAuthList.public_bytes()
	outLines.append(f'    bytes constant {varPrefix}_CERT_AUTHLIST =')
	outLines += FormatBytes(decentAuthList, 2)
	outLines.append('')

	return outLines


# set up the output lines with constant lines
outLines = [
	# license line
	'// SPDX-License-Identifier: MIT',
	# version pragma
	'pragma solidity >=0.4.17 <0.9.0;',
	'',
	'library TestCerts {',
	'',
]

# IAS Root Certificate
outLines.append('    //===== IAS Root Certificate =====')
outLines.append('')
with open(IAS_ROOT_PEM_PATH, 'rb') as f:
	cert = load_pem_x509_certificate(f.read())
	outLines += WriteCertWithRSAKey(cert, 'IAS_ROOT')
outLines.append('')

# IAS Report Certificate
outLines.append('    //===== IAS Report Certificate =====')
outLines.append('')
with open(IAS_REP_PEM_PATH, 'rb') as f:
	cert = load_pem_x509_certificate(f.read())
	outLines += WriteCertWithRSAKey(cert, 'IAS_REPORT')
outLines.append('')

# IAS Report Certificate
outLines.append('    //===== Decent Server Certificate =====')
outLines.append('')
with open(DECENT_SVR_PEM_PATH, 'rb') as f:
	cert = load_pem_x509_certificate(f.read())
	# der = binascii.unhexlify('')
	# cert = load_der_x509_certificate(der)
	outLines += WriteDecentSvrCert(cert, 'DECENT_SVR')
	serverPubKey = ECPubKey(cert.public_key())
outLines.append('')

# IAS Report Certificate
outLines.append('    //===== Decent App Certificate =====')
outLines.append('')
with open(DECENT_APP_PEM_PATH, 'rb') as f:
	cert = load_pem_x509_certificate(f.read())
	# der = binascii.unhexlify('')
	# cert = load_der_x509_certificate(der)
	outLines += WriteDecentAppCert(cert, 'DECENT_APP', serverPubKey=serverPubKey)
outLines.append('')

# Add ending bracket
outLines.append('}')

with open(CERTS_SOL_PATH, 'w') as f:
	for line in outLines:
		f.write(line + '\n')

