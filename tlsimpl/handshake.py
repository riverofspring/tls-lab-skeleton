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
    base_packet = b""
    # TODO: construct the packet data
    client_version = b"\x03\x03"
    base_packet += client_version
    client_random = secrets.token_bytes(32)
    base_packet += client_random
    session_id = b"\x00"
    base_packet += util.pack_varlen(session_id, 1)
    cipher_suites = util.pack(CipherSuite.TLS_AES_256_GCM_SHA384,2)
    base_packet += util.pack_varlen(cipher_suites)
    comp_methods = b"\x01\x00"
    base_packet += comp_methods

    ext = b""

    ks = b""
    protocol = util.pack(NamedGroup.X25519,2)
    ks += protocol
    ks += util.pack_varlen(key_exchange_pubkey)
    ext += util.pack_extension(ExtensionType.KEY_SHARE, util.pack_varlen(ks))

    identifier = util.pack(NamedGroup.X25519,2)
    ext += util.pack_extension(ExtensionType.SUPPORTED_GROUPS, util.pack_varlen(identifier))

    tls13 = b"\x03\x04"
    k = util.pack_extension(ExtensionType.SUPPORTED_VERSIONS, util.pack_varlen(tls13,1))
    ext += k

    print(hex(int.from_bytes(util.pack_extension(ExtensionType.SIGNATURE_ALGORITHMS, util.pack_varlen(util.pack_varlen(util.pack(SignatureScheme.RSA_PSS_RSAE_SHA256,2)))),"big")))
    ext += util.pack_extension(ExtensionType.SIGNATURE_ALGORITHMS, util.pack_varlen(util.pack(SignatureScheme.RSA_PSS_RSAE_SHA256,2)))

    base_packet += util.pack_varlen(ext)
    packet = base_packet


    sock.send_handshake_record(HandshakeType.CLIENT_HELLO, packet)


def recv_server_hello(sock: client.TLSSocket) -> Any:
    # TODO: parse the server hello data
    pass


def perform_handshake(sock: client.TLSSocket) -> None:
    key_exchange_keypair = cryptoimpl.generate_ed25519_keypair()
    send_client_hello(sock, key_exchange_keypair[1])
    server_info = recv_server_hello(sock)
