#!/usr/bin/env python3
# -*- coding:utf-8 -*-
###
# Copyright (c) 2024 Haofan Zheng
# Use of this source code is governed by an MIT-style
# license that can be found in the LICENSE file or at
# https://opensource.org/licenses/MIT.
###


import argparse
import base64
import logging
import os
import time

from web3 import Web3
from PyEthHelper import EthContractHelper
from PyEthHelper import GanacheAccounts


BASE_DIR_PATH       = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BUILD_DIR_PATH      = os.path.join(BASE_DIR_PATH, 'build')
UTILS_DIR_PATH      = os.path.join(BASE_DIR_PATH, 'utils')
TESTS_DIR           = os.path.join(BASE_DIR_PATH, 'tests')
CERTS_DIR           = os.path.join(TESTS_DIR, 'certs')
PROJECT_CONFIG_PATH = os.path.join(UTILS_DIR_PATH, 'project_conf.json')


LOGGER = logging.getLogger('NetworkCompatibility')


def _PemToDerCert(certPem: str) -> bytes:
	# PEM to DER
	certPem = certPem.strip()
	certPem = certPem.removeprefix('-----BEGIN CERTIFICATE-----')
	certPem = certPem.removesuffix('-----END CERTIFICATE-----')

	certPem = certPem.replace('\n', '')
	certPem = certPem.replace('\r', '')
	der = base64.b64decode(certPem)

	return der


def LoadIASRootCertDer() -> bytes:
	with open(os.path.join(CERTS_DIR, 'CertIASRoot.pem'), 'r') as f:
		certPem = f.read()

	return _PemToDerCert(certPem)


def LoadIASReportCertDer() -> bytes:
	with open(os.path.join(CERTS_DIR, 'CertIASReport.pem'), 'r') as f:
		certPem = f.read()

	return _PemToDerCert(certPem)


def LoadDecentServerCertDer() -> bytes:
	with open(os.path.join(CERTS_DIR, 'CertDecentServer.pem'), 'r') as f:
		certPem = f.read()

	return _PemToDerCert(certPem)


def LoadDecentAppCertDer() -> bytes:
	with open(os.path.join(CERTS_DIR, 'CertDecentApp.pem'), 'r') as f:
		certPem = f.read()

	return _PemToDerCert(certPem)


def RunTests(apiUrl: str, keyfile: os.PathLike) -> dict:
	# connect to endpoint
	w3 = Web3(Web3.HTTPProvider(apiUrl))
	while not w3.is_connected():
		LOGGER.info('Attempting to connect to endpoint...')
		time.sleep(1)
	LOGGER.info('Connected to endpoint')

	# checksum keys
	GanacheAccounts.ChecksumGanacheKeysFile(
		keyfile,
		keyfile
	)

	# setup account
	privKey = EthContractHelper.SetupSendingAccount(
		w3=w3,
		account=0,
		keyJson=keyfile
	)


	# deploy IASRootCertMgr contract
	LOGGER.info('Deploying IASRootCertMgr contract...')
	iasRootContract = EthContractHelper.LoadContract(
		w3=w3,
		projConf=PROJECT_CONFIG_PATH,
		contractName='IASRootCertMgr',
		release=None, # use locally built contract
		address=None, # deploy new contract
	)
	iasRootReceipt = EthContractHelper.DeployContract(
		w3=w3,
		contract=iasRootContract,
		arguments=[ LoadIASRootCertDer() ],
		privKey=privKey,
		gas=None, # let web3 estimate
		value=0,
		confirmPrompt=False # don't prompt for confirmation
	)
	iasRootAddr = iasRootReceipt.contractAddress
	LOGGER.info('IASRootCertMgr contract deployed at {}'.format(iasRootAddr))


	# deploy IASReportCertMgr contract
	LOGGER.info('Deploying IASReportCertMgr contract...')
	iasReportContract = EthContractHelper.LoadContract(
		w3=w3,
		projConf=PROJECT_CONFIG_PATH,
		contractName='IASReportCertMgr',
		release=None, # use locally built contract
		address=None, # deploy new contract
	)
	iasReportReceipt = EthContractHelper.DeployContract(
		w3=w3,
		contract=iasReportContract,
		arguments=[ iasRootAddr ],
		privKey=privKey,
		gas=None, # let web3 estimate
		value=0,
		confirmPrompt=False # don't prompt for confirmation
	)
	iasReportAddr = iasReportReceipt.contractAddress
	LOGGER.info('IASReportCertMgr contract deployed at {}'.format(iasReportAddr))
	iasReportContract = EthContractHelper.LoadContract(
		w3=w3,
		projConf=PROJECT_CONFIG_PATH,
		contractName='IASReportCertMgr',
		release=None, # use locally built contract
		address=iasReportAddr
	)

	# verify IAS report certificate
	LOGGER.info('Verifying IAS report certificate...')
	verifyReceipt = EthContractHelper.CallContractFunc(
		w3=w3,
		contract=iasReportContract,
		funcName='verifyCert',
		arguments=[ LoadIASReportCertDer() ],
		privKey=privKey,
		gas=None, # let web3 estimate
		value=0,
		confirmPrompt=False # don't prompt for confirmation
	)


	# deploy DecentServerCertMgr contract
	LOGGER.info('Deploying DecentServerCertMgr contract...')
	decentSvrContract = EthContractHelper.LoadContract(
		w3=w3,
		projConf=PROJECT_CONFIG_PATH,
		contractName='DecentServerCertMgr',
		release=None, # use locally built contract
		address=None, # deploy new contract
	)
	decentSvrReceipt = EthContractHelper.DeployContract(
		w3=w3,
		contract=decentSvrContract,
		arguments=[ iasReportAddr ],
		privKey=privKey,
		gas=None, # let web3 estimate
		value=0,
		confirmPrompt=False # don't prompt for confirmation
	)
	decentSvrAddr = decentSvrReceipt.contractAddress
	LOGGER.info('DecentServerCertMgr contract deployed at {}'.format(decentSvrAddr))
	decentSvrContract = EthContractHelper.LoadContract(
		w3=w3,
		projConf=PROJECT_CONFIG_PATH,
		contractName='DecentServerCertMgr',
		release=None, # use locally built contract
		address=decentSvrAddr
	)

	# verify Decent server certificate
	LOGGER.info('Verifying Decent Server certificate...')
	verifyReceipt = EthContractHelper.CallContractFunc(
		w3=w3,
		contract=decentSvrContract,
		funcName='verifyCert',
		arguments=[ LoadDecentServerCertDer() ],
		privKey=privKey,
		gas=None, # let web3 estimate
		value=0,
		confirmPrompt=False # don't prompt for confirmation
	)


	# deploy HelloWorldApp contract
	LOGGER.info('Deploying HelloWorldApp contract...')
	decentAppContract = EthContractHelper.LoadContract(
		w3=w3,
		projConf=PROJECT_CONFIG_PATH,
		contractName='HelloWorldApp',
		release=None, # use locally built contract
		address=None, # deploy new contract
	)
	decentAppReceipt = EthContractHelper.DeployContract(
		w3=w3,
		contract=decentAppContract,
		arguments=[ decentSvrAddr ],
		privKey=privKey,
		gas=None, # let web3 estimate
		value=0,
		confirmPrompt=False # don't prompt for confirmation
	)
	decentAppAddr = decentAppReceipt.contractAddress
	LOGGER.info('HelloWorldApp contract deployed at {}'.format(decentAppAddr))
	decentAppContract = EthContractHelper.LoadContract(
		w3=w3,
		projConf=PROJECT_CONFIG_PATH,
		contractName='HelloWorldApp',
		release=None, # use locally built contract
		address=decentAppAddr
	)

	# verify Decent app certificate
	LOGGER.info('Verifying Decent App certificate...')
	verifyReceipt = EthContractHelper.CallContractFunc(
		w3=w3,
		contract=decentAppContract,
		funcName='loadAppCert',
		arguments=[
			'0xd11169Fe26A678dFb634C67aC85C05ccd796dAEd',
			LoadDecentAppCertDer()
		],
		privKey=privKey,
		gas=None, # let web3 estimate
		value=0,
		confirmPrompt=False # don't prompt for confirmation
	)


def main():
	argParser = argparse.ArgumentParser(
		description='Run tests to check compatibility with a given network'
	)
	argParser.add_argument(
		'--api-url', '-u',
		type=str, required=True,
		help='URL to the JSON-RPC over HTTP API of the network'
	)
	argParser.add_argument(
		'--key-file', '-k',
		type=str, required=True,
		help='Path to the file containing the private keys for the accounts'
	)
	argParser.add_argument(
		'--log-path', '-l',
		type=str, required=False,
		help='Path to the directory where the log file will be stored'
	)
	args = argParser.parse_args()

	logFormatter = logging.Formatter('[%(asctime)s | %(levelname)s] [%(name)s] %(message)s')
	logLevel = logging.INFO
	rootLogger = logging.root

	rootLogger.setLevel(logLevel)

	consoleHandler = logging.StreamHandler()
	consoleHandler.setFormatter(logFormatter)
	consoleHandler.setLevel(logLevel)
	rootLogger.addHandler(consoleHandler)

	if args.log_path is not None:
		fileHandler = logging.FileHandler(args.log_path)
		fileHandler.setFormatter(logFormatter)
		fileHandler.setLevel(logLevel)
		rootLogger.addHandler(fileHandler)


	RunTests(apiUrl=args.api_url, keyfile=args.key_file)


if __name__ == '__main__':
	exit(main())

