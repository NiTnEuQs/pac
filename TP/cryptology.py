from subprocess import Popen, PIPE
from base64 import b64decode, b64encode

# en cas de problème, cette exception est déclenchée
class OpensslError(Exception):
    pass


def encrypt(plaintext, passphrase, cipher='aes-128-cbc'):
    pass_arg = 'pass:{0}'.format(passphrase)
    args = ['openssl', 'enc', '-' + cipher, '-base64', '-pass', pass_arg]

    if isinstance(plaintext, str):
        plaintext = plaintext.encode('utf-8')

    pipeline = Popen(args, stdin=PIPE, stdout=PIPE, stderr=PIPE)

    stdout, stderr = pipeline.communicate(plaintext)

    error_message = stderr.decode()
    if error_message != '':
        raise OpensslError(error_message)

    return stdout.decode()

def encryptNo64(plaintext, passphrase, cipher='aes-128-cbc'):
    pass_arg = 'pass:{0}'.format(passphrase)
    args = ['openssl', 'enc', '-' + cipher, '-pass', pass_arg]

    if isinstance(plaintext, str):
        plaintext = plaintext.encode('utf-8')

    pipeline = Popen(args, stdin=PIPE, stdout=PIPE, stderr=PIPE)

    stdout, stderr = pipeline.communicate(plaintext)

    error_message = stderr.decode()
    if error_message != '':
        raise OpensslError(error_message)

    return stdout.decode()

def decrypt(plaintext, passphrase, cipher='aes-128-cbc'):
    pass_arg = 'pass:{0}'.format(passphrase)
    args = ['openssl', 'enc', '-d', '-' + cipher, '-base64', '-pass', pass_arg]

    if isinstance(plaintext, str):
        plaintext = plaintext.encode('utf-8')

    pipeline = Popen(args, stdin=PIPE, stdout=PIPE, stderr=PIPE)

    stdout, stderr = pipeline.communicate(plaintext)

    error_message = stderr.decode()
    if error_message != '':
        #raise OpensslError(error_message)
        return "openssl error: " + error_message

    try:
        return stdout.decode()
    except UnicodeError:
        return "unicode error"

def decryptNo64(plaintext, passphrase, cipher='aes-128-cbc'):
    pass_arg = 'pass:{0}'.format(passphrase)
    args = ['openssl', 'enc', '-d', '-' + cipher, '-pass', pass_arg]
    
    if isinstance(plaintext, str):
        plaintext = plaintext.encode('utf-8')

    pipeline = Popen(args, stdin=PIPE, stdout=PIPE, stderr=PIPE)

    stdout, stderr = pipeline.communicate(plaintext)

    error_message = stderr.decode()
    if error_message != '':
        raise OpensslError(error_message)

    try:
        return stdout.decode()
    except UnicodeError:
        return "unicode error"


def encryptPkey(plaintext, publickey):
    """invoke the OpenSSL library (though the openssl executable which must be
    present on your system) to encrypt content using a symmetric cipher.
    The passphrase is an str object (a unicode string)
    The plaintext is str() or bytes()
    The output is bytes()
    # encryption use
    >>> message = "texte avec caractères accentués"
    >>> c = encrypt(message, 'foobar')
    """
    args = ['openssl', 'pkeyutl','-encrypt','-pubin','-inkey', publickey]

    if isinstance(plaintext, str):
        plaintext = plaintext.encode('utf-8')

    pipeline = Popen(args, stdin=PIPE, stdout=PIPE, stderr=PIPE)

    stdout, stderr = pipeline.communicate(plaintext)

    error_message = stderr.decode()
    if error_message != '':
        raise OpensslError(error_message)

    return (b64encode(stdout).decode())

def decryptPkey(plaintext, privatekey):
    args = ['openssl', 'pkeyutl' , '-decrypt' , '-inkey' , privatekey]
    if isinstance(plaintext, str):
        plaintext = plaintext.encode('utf-8')
    pipeline = Popen(args, stdin=PIPE, stdout=PIPE, stderr=PIPE)
    stdout, stderr = pipeline.communicate(plaintext)
    error_message = stderr.decode()
    if error_message != '':
        raise OpensslError(error_message)
    return stdout.decode()


def signature(plaintext,privatekey):
    args = ['openssl', 'dgst' ,'-sha256','-sign',privatekey]
    if isinstance(plaintext, str):
        plaintext = plaintext.encode('utf-8')
    pipeline = Popen(args, stdin=PIPE, stdout=PIPE, stderr=PIPE)
    stdout, stderr = pipeline.communicate(plaintext)
    error_message = stderr.decode()
    if error_message != '':
        raise OpensslError(error_message)
    return (b64encode(stdout).decode())


def checkSignature(plaintext, pkey , signature):
    args = ['openssl', 'dgst' , '-sha256', '-verify' , pkey , '-signature' , signature]
    if isinstance(plaintext, str):
        plaintext = plaintext.encode('utf-8')
    pipeline = Popen(args, stdin=PIPE, stdout=PIPE, stderr=PIPE)
    stdout, stderr = pipeline.communicate(plaintext)
    error_message = stderr.decode()
    if error_message != '':
        raise OpensslError(error_message)
    return stdout.decode()

def verify():
    args = ['openssl', 'verify' , '-trusted' , 'bankCA' , '-untrusted' , 'Cbank' , 'Ccard']
    pipeline = Popen(args, stdin=None, stdout=PIPE, stderr=PIPE)
    stdout, stderr = pipeline.communicate()
    error_message = stderr.decode()
    if error_message != '':
        return False
    message = stdout.decode()
    if "error" in message:
        return False
    return True

def certificateKey():
    args = ['openssl', 'x509' , '-pubkey' , '-noout' , '-in' , 'Ccard']
    pipeline = Popen(args, stdin=None, stdout=PIPE, stderr=PIPE)
    stdout, stderr = pipeline.communicate()
    error_message = stderr.decode()
    if error_message != '':
        raise OpensslError(error_message)
    return stdout.decode()

def certificateText(certificate):
    args = ['openssl', 'x509' , '-text' , '-noout' , '-in' , certificate]
    pipeline = Popen(args, stdin=None, stdout=PIPE, stderr=PIPE)
    stdout, stderr = pipeline.communicate()
    error_message = stderr.decode()
    if error_message != '':
        raise OpensslError(error_message)
    return stdout.decode()

