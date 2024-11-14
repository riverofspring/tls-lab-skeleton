"""
The TLS v1.3 handshake implementation.
"""

from __future__ import annotations

import secrets

from tlsimpl import client, cryptoimpl, util
from tlsimpl.consts import *


def send_client_hello(sock, key_exchange_pubkey: bytes) -> None:
    """
    Performs the TLS v1.3 client hello.

    `key_exchange_pubkey` is the X25519 public key used for key exchange.

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

    ext += util.pack_extension(ExtensionType.SIGNATURE_ALGORITHMS, util.pack_varlen(util.pack(SignatureScheme.RSA_PSS_RSAE_SHA256,2)))

    base_packet += util.pack_varlen(ext)
    packet = base_packet


    sock.send_handshake_record(HandshakeType.CLIENT_HELLO, packet)


def recv_server_hello(sock: client.TLSSocket) -> bytes:
    """
    Parses the TLS v1.3 server hello.

    Returns the pubkey of the server.

    Specified in RFC8446 section 4.1.3.
    """
    (ty, data) = sock.recv_handshake_record()
    assert ty == HandshakeType.SERVER_HELLO
    # TODO: parse server hello and find server pubkey
    data = data[6:]
    random = data[:32]
    data = data[32:]
    session_id_len = data[0]
    data = data[3+session_id_len:]
    extensiondata = {}
    while (data != b""):
        ext_type, contents, data = util.unpack_extension(data)
        extensiondata[ext_type] = contents
    

    peer_pubkey = extensiondata[ExtensionType.KEY_SHARE]
    peer_pubkey = peer_pubkey[4:]
    return peer_pubkey


def recv_server_info(sock: client.TLSSocket) -> None:
    """
    Receives the server's encrypted extensions, certificate, and certificate verification.

    Also verifies the certificate's validity.
    """
    ty, data = sock.recv_record()
    # print(ty)
    # print(data[0])
    data = data[1:]
    ext_length = util.unpack(data[:3])
    data = data[3:]
    ext = data
    ty, data = sock.recv_record()
    # if data[0] != 0x0b:
    #     print("what")
    #     print(data[0])
    data = data[1:]
    ext_length = util.unpack(data[:3])
    data = data[3:]
    ext = data
    ty, data = sock.recv_handshake_record()
    # print(ty)
    # print(data[0])
    data = data[1:]
    certificates_length = util.unpack(data[:3])
    # print(certificates_length)
    data = data[3:]
    certificate_single_length = util.unpack(data[:3])
    cert = data[:certificate_single_length]
    data = data[certificate_single_length:]
    cert_ext_len = data[:2]
    ty, data2 = sock.recv_handshake_record()
    # we are not verifying i guess
    # TODO: implement


def finish_handshake(sock: client.TLSSocket, handshake_secret: bytes) -> None:
    """
    Receives the server finish, sends the client finish, and derives the application keys.

    Takes in the shared secret from key exchange.
    """
    ty, data = sock.recv_handshake_record()
    
    print(ty)
    # TODO: implement


def perform_handshake(sock: client.TLSSocket) -> None:
    key_exchange_keypair = cryptoimpl.generate_x25519_keypair()
    send_client_hello(sock, key_exchange_keypair[1])
    peer_pubkey = recv_server_hello(sock)
    shared_secret = cryptoimpl.derive_shared_x25519_key(
        key_exchange_keypair[0], peer_pubkey
    )
    transcript_hash = sock.transcript_hash.digest()
    (handshake_secret, sock.client_params, sock.server_params) = (
        cryptoimpl.derive_handshake_params(shared_secret, transcript_hash)
    )
    recv_server_info(sock)
    finish_handshake(sock, handshake_secret)
    # receive an encrypted record to make sure everything works
    print(sock.recv_record())
