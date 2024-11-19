import os
import socket
import shared.crypto_utils as cu
from shared.crypto_utils import DHParams, Keyring
from shared.socket_utils import Connection

# Constants and environment variables
PRIME_BITS = int(os.environ.get('PRIME_NUMBER_BITS', 8))
KEY_BITS = int(os.environ.get('KEY_BITS', 8))
MESSAGE_TO_SEND = os.environ.get('MESSAGE_TO_SEND', 'Hello world')
VERBOSE = bool(int(os.environ.get('VERBOSE', 0)))
ATTACH = bool(int(os.environ.get('ATTACH', 0)))

# Functions
verboseprint = print if VERBOSE else lambda *a, **k: None
inputattach = input if ATTACH else lambda *a, **k: None

def DHinit(conn = None):
    if conn is None:
        raise ValueError('Connection object must be provided')

    # Alice generates Diffie-Hellman parameters (p, g)
    p, g = cu.generate_dh_params(PRIME_BITS)
    verboseprint('Alice generated p: {} and g: {}'.format(p, g))

    # Alice sends p and g to Bob
    conn.send(p)
    conn.send(g)
    verboseprint('Alice sent p and g to Bob')

    return p, g

def DHexchange(conn = None, phase_name = "", p = None, g = None):
    if conn is None:
        raise ValueError('Connection object must be provided')

    if p is None or g is None:
        raise ValueError('p and g must be provided')

    # Alice generates her private and public keys
    alice_private_key, alice_public_key = cu.generate_keys(p, g, KEY_BITS)

    verboseprint('{} Alice generated:\n\tprivate key: {}\n\tpublic key: {}'.format(phase_name, alice_private_key, alice_public_key))

    inputattach("Press ENTER to send Alice's public key to Bob...")

    # Alice sends her public key to Bob
    conn.send(alice_public_key)
    verboseprint('{} Alice sent her public key to Bob'.format(phase_name))

    verboseprint('{} Alice is waiting for Bob\'s public key...'.format(phase_name))

    # Alice receives Bob's public key
    bob_public_key = int(conn.read())
    verboseprint('{} Alice received Bob\'s public key: {}'.format(phase_name, bob_public_key))

    return (
        DHParams(p, g, alice_private_key, alice_public_key),
        DHParams(p, g, None, bob_public_key)
    )


def main():
    inputattach("Press ENTER to start Alice...")
    verboseprint('Alice started up with vars:\n\tPRIME_BITS={},\n\tKEY_BITS={},\n\tVERBOSE={},\n\tATTACH={}'.format(PRIME_BITS, KEY_BITS, VERBOSE, ATTACH))

    # Create a TCP/IP socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Connect the socket to the port where the server is listening
    server_address = ('172.28.0.3', 1234)
    print('connecting to %s port %s' % server_address)
    sock.connect(server_address)

    # Create a Connection object which has a buffer and read/send methods
    conn = Connection(sock)

    # Alice receives READY from Bob
    ready = conn.read()

    if ready != 'READY':
        print('Bob did not send READY')
        conn.close()
        exit()
    else:
        print('Alice received READY from Bob')

    inputattach("Press ENTER to generate and send Diffie-Hellman parameters...")

    # DH initialization (DH params)
    p, g = DHinit(conn)

    # Keyring initialization
    keyring = Keyring()

    # LDH generation and exchange (in a real scenario this IS NOT done for every message)
    inputattach("Press ENTER to start LDH keys negotiation with Bob...")

    verboseprint('Alice is starting the LDH phase')
    LDH_A, LDH_B = DHexchange(conn, '[LDH]', p, g)
    verboseprint('Alice finished the LDH phase')

    # EDH generation and exchange (in a real scenario this IS done for every message)
    inputattach("Press ENTER to start EDH keys negotiation with Bob...")

    verboseprint('Alice is starting the EDH phase')
    EDH_A, EDH_B = DHexchange(conn, '[EDH]', LDH_A.p, LDH_A.g)
    verboseprint('Alice finished the EDH phase')

    # Alice computes the shared keys
    keyring.SH_K1 = cu.compute_shared_key(EDH_A.private_key, LDH_B.public_key, LDH_A.p)
    keyring.SH_K2 = cu.compute_shared_key(EDH_A.private_key, EDH_B.public_key, LDH_A.p)
    keyring.SH_K3 = cu.compute_shared_key(LDH_A.private_key, EDH_B.public_key, LDH_A.p)
    verboseprint('Alice computed the shared keys: \n\tSH-K1: {}\n\tSH-K2: {}\n\tSH-K3: {}'.format(keyring.SH_K1, keyring.SH_K2, keyring.SH_K3))

    # Alice destroys her ephemeral keys
    inputattach("Hey Alice! Don't forget to destroy your ephemeral keys! Press ENTER to destroy them...")
    EDH_A.private_key = None
    EDH_A.public_key = None
    verboseprint('Alice destroyed her ephemeral keys')

    # Alice derives the shared secret
    shared_secret = cu.kdf(keyring)
    verboseprint('Alice derived the shared secret: {}'.format(shared_secret))

    # Alice encrypts the message and sends it to Bob
    inputattach("Press ENTER to send the encrypted message to Bob...")
    cipher_text = cu.encrypt_message(MESSAGE_TO_SEND, shared_secret)
    conn.send(cipher_text)
    print('Alice sent the encrypted message to Bob (plaintext: {})'.format(MESSAGE_TO_SEND))

    # Close the connection
    conn.close()

if __name__ == '__main__':
    main()
