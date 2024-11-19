import os
import socket
import shared.crypto_utils as cu
from shared.crypto_utils import DHParams, Keyring
from shared.socket_utils import Connection

# Constants and environment variables
PRIME_BITS = int(os.environ.get('PRIME_NUMBER_BITS', 8))
KEY_BITS = int(os.environ.get('KEY_BITS', 8))
VERBOSE = bool(int(os.environ.get('VERBOSE', 0)))
ATTACH = bool(int(os.environ.get('ATTACH', 0)))

# Functions
verboseprint = print if VERBOSE else lambda *a, **k: None
inputattach = input if ATTACH else lambda *a, **k: None

def DHinit(conn):
    if conn is None:
        raise ValueError('Connection object must be provided')

    # Bob receives Diffie-Hellman parameters (p, g) from Alice
    p = int(conn.read())
    g = int(conn.read())
    verboseprint('Bob received p: {} and g: {} from Alice'.format(p, g))

    return p, g

def DHexchange(conn, phase_name = "", p = None, g = None):
    if conn is None:
        raise ValueError('Connection object must be provided')

    if p is None or g is None:
        raise ValueError('p and g must be provided')

    # Bob generates his private and public keys
    bob_private_key, bob_public_key = cu.generate_keys(p, g, KEY_BITS)

    verboseprint('{} Bob generated:\n\tprivate key: {}\n\tpublic key: {}'.format(phase_name, bob_private_key, bob_public_key))

    verboseprint('{} Bob is waiting for Alice\'s public key...'.format(phase_name))

    # Bob receives Alice's public key
    alice_public_key = int(conn.read())
    verboseprint('{} Bob received Alice\'s public key: {}'.format(phase_name, alice_public_key))

    inputattach("Press ENTER to send Bob's public key to Alice...")

    # Bob sends his public key to Alice
    conn.send(bob_public_key)
    verboseprint('{} Bob sent his public key to Alice'.format(phase_name))

    return (
        DHParams(p, g, bob_private_key, bob_public_key),
        DHParams(p, g, None, alice_public_key)
    )

def main():
    inputattach("Press ENTER to start Bob...")
    verboseprint('Bob started up with vars:\n\tPRIME_BITS={},\n\tKEY_BITS={},\n\tVERBOSE={},\n\tATTACH={}'.format(PRIME_BITS, KEY_BITS, VERBOSE, ATTACH))

    # Create a TCP/IP socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Bind the socket to the port
    server_address = ('bob', 1234)
    print('starting up on %s port %s' % server_address)
    sock.bind(server_address)

    # Listen for incoming connections
    sock.listen(1)

    # Ideally there should be a loop here to handle multiple connections
    # while True:

    # Wait for a connection
    print('waiting for a connection')
    sock_connection, client_address = sock.accept()

    # Create a Connection object
    conn = Connection(sock_connection)

    try:
        print('connection from', client_address)

        # Send READY to Alice
        conn.send('READY')
        print('Bob sent READY to Alice')

        # DH initialization (DH params)
        p, g = DHinit(conn)

        # Keyring initialization
        keyring = Keyring()

        # LDH generation and exchange (in a real scenario this IS NOT done for every message)
        verboseprint('Bob is starting the LDH phase')
        LDH_B, LDH_A = DHexchange(conn, '[LDH]', p, g)
        verboseprint('Bob has finished the LDH phase')

        # EDH generation and exchange (in a real scenario this IS done for every message)
        verboseprint('Bob is starting the EDH phase')
        EDH_B, EDH_A = DHexchange(conn, '[EDH]', p, g)
        verboseprint('Bob has finished the EDH phase')

        # Bob computes the shared keys
        keyring.SH_K1 = cu.compute_shared_key(LDH_B.private_key, EDH_A.public_key, p)
        keyring.SH_K2 = cu.compute_shared_key(EDH_B.private_key, EDH_A.public_key, p)
        keyring.SH_K3 = cu.compute_shared_key(EDH_B.private_key, LDH_A.public_key, p)
        verboseprint('Bob computed the shared keys:\n\tSH-K1: {}\n\tSH-K2: {}\n\tSH-K3: {}'.format(keyring.SH_K1, keyring.SH_K2, keyring.SH_K3))

        # Bob destroys his ephemeral keys
        inputattach("Hey Bob! Don't forget to destroy your ephemeral keys! Press ENTER to destroy them...")
        EDH_B.private_key = None
        EDH_B.public_key = None
        verboseprint('Bob destroyed his ephemeral keys')

        # Bob derives the shared secret
        shared_secret = cu.kdf(keyring)
        verboseprint('Bob derived the shared secret: {}'.format(shared_secret))

        # Bob receives the encrypted message from Alice
        cipher_text = conn.read()
        print('Bob received the encrypted message from Alice')

        inputattach("Press ENTER to decrypt the message from Alice...")
        # Bob decrypts the message
        decrypted_message = cu.decrypt_message(cipher_text, shared_secret)
        print('Bob decrypted the message from Alice: {}'.format(decrypted_message))

    finally:
        # Clean up the connection
        conn.close()

if __name__ == '__main__':
    main()
