from subprocess import Popen, PIPE, check_output
from base64 import b64decode, b64encode

# en cas de problème, cette exception est déclenchée
class OpensslError(Exception):
    pass

def encrypt(plaintext, passphrase, cipher='aes-128-cbc'):
    """invoke the OpenSSL library (though the openssl executable which must be
       present on your system) to encrypt content using a symmetric cipher.

       The passphrase is an str object (a unicode string)
       The plaintext is str() or bytes()
       The output is bytes()

       # encryption use
       >>> message = "texte avec caractères accentués"
       >>> c = encrypt(message, 'foobar')
       
    """
    # prépare les arguments à envoyer à openssl
    pass_arg = 'pass:{0}'.format(passphrase)
    args = ['openssl', 'enc', '-' + cipher, '-base64', '-pass', pass_arg]
    
    # si le message clair est une chaine unicode, on est obligé de
    # l'encoder en bytes() pour pouvoir l'envoyer dans le pipeline vers 
    # openssl
    if isinstance(plaintext, str):
        plaintext = plaintext.encode('utf-8')
    
    # ouvre le pipeline vers openssl. Redirige stdin, stdout et stderr
    #    affiche la commande invoquée
    #    print('debug : {0}'.format(' '.join(args)))
    pipeline = Popen(args, stdin=PIPE, stdout=PIPE, stderr=PIPE)

    # envoie plaintext sur le stdin de openssl, récupère stdout et stderr
    stdout, stderr = pipeline.communicate(plaintext)

    # si un message d'erreur est présent sur stderr, on arrête tout
    # attention, sur stderr on récupère des bytes(), donc on convertit
    error_message = stderr.decode()
    if error_message != '':
        raise OpensslError(error_message)

    # OK, openssl a envoyé le chiffré sur stdout, en base64.
    # On récupère des bytes, donc on en fait une chaine unicode
    return stdout.decode()

def decrypt(plaintext, passphrase, cipher='aes-128-cbc'):
    # prépare les arguments à envoyer à openssl
    pass_arg = 'pass:{0}'.format(passphrase)
    #args = ['openssl', 'enc', '-' + cipher, '-base64', '-pass', pass_arg, '-d', '-p']
    args = ['openssl', 'enc', '-d', '-' + cipher, '-base64', '-pass', pass_arg]
    
    # si le message clair est une chaine unicode, on est obligé de
    # l'encoder en bytes() pour pouvoir l'envoyer dans le pipeline vers 
    # openssl
    if isinstance(plaintext, str):
        plaintext = plaintext.encode('utf-8')
    
    # ouvre le pipeline vers openssl. Redirige stdin, stdout et stderr
    #    affiche la commande invoquée
    #    print('debug : {0}'.format(' '.join(args)))
    pipeline = Popen(args, stdin=PIPE, stdout=PIPE, stderr=PIPE)

    # envoie plaintext sur le stdin de openssl, récupère stdout et stderr
    stdout, stderr = pipeline.communicate(plaintext)

    # si un message d'erreur est présent sur stderr, on arrête tout
    # attention, sur stderr on récupère des bytes(), donc on convertit
    error_message = stderr.decode()
    if error_message != '':
        raise OpensslError(error_message)

    # OK, openssl a envoyé le chiffré sur stdout, en base64.
    # On récupère des bytes, donc on en fait une chaine unicode
    return stdout.decode()

def decryptFile(filename, passphrase, cipher='aes-128-cbc'):
    # prépare les arguments à envoyer à openssl
    pass_arg = 'pass:{0}'.format(passphrase)
    args = ['openssl', 'enc', '-' + cipher, '-base64', '-pass', pass_arg, '-d', '-p', '-in', filename]
    
    stdout = check_output(args, stdin=PIPE, stderr=PIPE)

    # OK, openssl a envoyé le chiffré sur stdout, en base64.
    # On récupère des bytes, donc on en fait une chaine unicode
    return stdout.decode()

def decryptPkey(plaintext, privatekey):
    args = ['openssl', 'pkeyutl', '-decrypt', '-inkey', privatekey]

    if isinstance(plaintext, str):
        plaintext = plaintext.encode('utf-8')

    pipeline = Popen(args, stdin=PIPE, stdout=PIPE, stderr=PIPE)

    stdout, stderr = pipeline.communicate(plaintext)

    error_message = stderr.decode()
    if error_message != '':
        raise OpensslError(error_message)

    return (b64encode(stdout).decode())

def encryptPkey(plaintext, publickey):
    args = ['openssl', 'pkeyutl','-encrypt','-pubin', '-inkey', publickey]
    
    if isinstance(plaintext, str):
        plaintext = plaintext.encode('utf-8')
    
    pipeline = Popen(args, stdin=PIPE, stdout=PIPE, stderr=PIPE)

    stdout, stderr = pipeline.communicate(plaintext)

    error_message = stderr.decode()
    if error_message != '':
        raise OpensslError(error_message)

    return (b64encode(stdout).decode())
