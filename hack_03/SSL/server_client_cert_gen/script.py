#!/usr/bin/env python3
"""
script.py

Usage:
  python3 script.py gen_certs [--outdir DIR] [--days DAYS] [--client-cn CN] [--server-cn CN]

Genera:
 - ca_key.pem, ca_cert.pem
 - server_key.pem, server_cert.pem
 - client_key.pem, client_csr.pem, client_cert.pem

Dipendenza: cryptography
  pip3 install cryptography
"""

import os
import stat
import argparse
from datetime import datetime, timedelta
from cryptography import x509
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import NoEncryption, BestAvailableEncryption
from cryptography.x509.oid import ExtendedKeyUsageOID

def write_file(path, data, mode=0o644):
    with open(path, "wb") as f:
        f.write(data)
    os.chmod(path, mode)

def gen_key(bits=4096):
    return rsa.generate_private_key(public_exponent=65537, key_size=bits)

def name_for(common_name, org="MyOrg", country="IT", state="RM", locality="Roma"):
    return x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, country),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, state),
        x509.NameAttribute(NameOID.LOCALITY_NAME, locality),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, org),
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
    ])

def gen_ca(key, subject, days):
    now = datetime.utcnow()
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=days))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    return cert

def gen_cert_signed(key, subject, issuer_cert, issuer_key, days, is_server=False):
    now = datetime.utcnow()
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=days))
    )
    # usages
    eku = [ExtendedKeyUsageOID.SERVER_AUTH] if is_server else [ExtendedKeyUsageOID.CLIENT_AUTH]
    builder = builder.add_extension(x509.ExtendedKeyUsage(eku), critical=False)
    # optional: subjectAltName for server (localhost and common name)
    if is_server:
        san = x509.SubjectAlternativeName([x509.DNSName("localhost"), x509.DNSName(subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value)])
        builder = builder.add_extension(san, critical=False)
    cert = builder.sign(private_key=issuer_key, algorithm=hashes.SHA256())
    return cert

def main():
    parser = argparse.ArgumentParser(description="Genera CA/server/client certs")
    parser.add_argument("cmd", choices=["gen_certs"], help="Comando")
    parser.add_argument("--outdir", default="certs_out", help="Directory di output")
    parser.add_argument("--days", type=int, default=365, help="Giorni di validità")
    parser.add_argument("--client-cn", default="client.local", help="Common Name client")
    parser.add_argument("--server-cn", default="server.local", help="Common Name server")
    parser.add_argument("--encrypt-key", action="store_true", help="Proteggi le chiavi con passphrase (chiederà passphrase)")
    args = parser.parse_args()

    if args.cmd == "gen_certs":
        out = os.path.abspath(args.outdir)
        os.makedirs(out, exist_ok=True)

        # 1) CA
        ca_key = gen_key(bits=4096)
        ca_name = name_for("MyTestCA")
        ca_cert = gen_ca(ca_key, ca_name, args.days)

        # write CA key & cert
        ca_key_pem = ca_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=NoEncryption() if not args.encrypt_key else BestAvailableEncryption(b"changeit")
        )
        ca_cert_pem = ca_cert.public_bytes(serialization.Encoding.PEM)
        write_file(os.path.join(out, "ca_key.pem"), ca_key_pem, mode=0o600)
        write_file(os.path.join(out, "ca_cert.pem"), ca_cert_pem, mode=0o644)

        # 2) Server key & cert
        srv_key = gen_key(3072)
        srv_name = name_for(args.server_cn)
        srv_cert = gen_cert_signed(srv_key, srv_name, ca_cert, ca_key, args.days, is_server=True)
        write_file(os.path.join(out, "server_key.pem"), srv_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=NoEncryption()
        ), mode=0o600)
        write_file(os.path.join(out, "server_cert.pem"), srv_cert.public_bytes(serialization.Encoding.PEM), mode=0o644)

        # 3) Client key, CSR, cert
        client_key = gen_key(3072)
        client_name = name_for(args.client_cn)
        # csr (not strictly necessary to save, but helpful)
        csr = x509.CertificateSigningRequestBuilder().subject_name(client_name).sign(client_key, hashes.SHA256())
        client_cert = gen_cert_signed(client_key, client_name, ca_cert, ca_key, args.days, is_server=False)
        write_file(os.path.join(out, "client_key.pem"), client_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=NoEncryption()
        ), mode=0o600)
        write_file(os.path.join(out, "client_csr.pem"), csr.public_bytes(serialization.Encoding.PEM), mode=0o644)
        write_file(os.path.join(out, "client_cert.pem"), client_cert.public_bytes(serialization.Encoding.PEM), mode=0o644)

        print("Certificati generati in:", out)
        print("Files creati:")
        print(" - ca_key.pem (600)")
        print(" - ca_cert.pem")
        print(" - server_key.pem (600)")
        print(" - server_cert.pem")
        print(" - client_key.pem (600)")
        print(" - client_csr.pem")
        print(" - client_cert.pem")
        print("\nConsiglio: sposta i file client* sul client in modo sicuro (scp/rsync/usb).")

if __name__ == "__main__":
    main()
