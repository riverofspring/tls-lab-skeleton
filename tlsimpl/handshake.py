"""
The TLS v1.3 handshake implementation.
"""

from __future__ import annotations

import secrets
from typing import Any

from tlsimpl import client, cryptoimpl, util
from tlsimpl.consts import *


def send_client_hello(sock, key_exchange_pubkey: bytes) -> None:
    """
    Performs the TLS v1.3 client hello.

    `key_exchange_pubkey` is the Ed25519 public key used for key exchange.

    Specified in RFC8446 section 4.1.2.
    """
    packet = []
    # TODO: construct the packet data
    client_version = b"\x03\x03"
    packet.append(client_version)
    client_random = secrets.token_bytes(32)
    packet.append(client_random)
    len_session_id = b"\x01"
    packet.append(len_session_id)
    session_id = b"\x00"
    packet.append(session_id)
    len_cipher_suites = b"\x02"
    packet.append(len_cipher_suites)
    cipher_suites = b"\x13\x02"
    packet.append(cipher_suites)
    comp_methods = b"\x01\x00"
    packet.append(comp_methods)

    ext = []

    keyshare_identifier = b"\x00\x33"
    ext.append(keyshare_identifier)
    ki_len_data_1 = b"\x00\x26"
    ext.append(ki_len_data_1)
    ki_len_data_2 = b"\x00\x24"
    ext.append(ki_len_data_2)
    protocol = b"\x00\x1d"
    ext.append(protocol)
    len_pubkey = b"\x00\x20"
    ext.append(len_pubkey)
    ext.append(key_exchange_pubkey)

    supported_groups = b"\x00\x0a"
    ext.append(supported_groups)
    sg_len_data_1 = b"\x00\x04"
    ext.append(sg_len_data_1)
    sg_len_data_2 = b"\x00\x02"
    ext.append(sg_len_data_2)
    identifiers = b"\x00\x1d"
    ext.append(identifiers)

    supported_versions = b"\x00\x2b"
    ext.append(supported_versions)
    sv_len_data_1 = b"\x00\x03"
    ext.append(sv_len_data_1)
    sv_len_data_2 = b"\x02"
    ext.append(sv_len_data_2)
    sv = b"\x03\x04"
    ext.append(sv)

    sig_algos = b"\x00\x0d"
    ext.append(sig_algos)
    sa_len_data_1 = b"\x00\x04"
    ext.append(sa_len_data_1)
    sa_len_data_2 = b"\x00\x02"
    ext.append(sa_len_data_2)
    algos = b"\x08\x04"
    ext.append(algos)

    len_ext = len(b"".join(ext)).to_bytes(2, "big")
    packet.append(len_ext)
    for e in ext:
        packet.append(e)

    sock.send_handshake_record(HandshakeType.CLIENT_HELLO, b"".join(packet))


def recv_server_hello(sock: client.TLSSocket) -> Any:
    # TODO: parse the server hello data
    pass


def perform_handshake(sock: client.TLSSocket) -> None:
    key_exchange_keypair = cryptoimpl.generate_ed25519_keypair()
    send_client_hello(sock, key_exchange_keypair[1])
    server_info = recv_server_hello(sock)
