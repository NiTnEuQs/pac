import sys
import json
import getopt
from subprocess import call
from client import *
from cryptology import *

c = Connection("http://pac.fil.cool/uglix")
prompt = '> '
user = "alyssa65"
passwd = "$2E#Q+Jysw"

def inbox():
    return c.get('/home/' + user + '/INBOX')

def read_inbox():
    print(inbox())

def mail(num_mail):
    return c.get('/home/' + user + '/INBOX/' + str(num_mail))

def mail_sender(num_mail):
    return c.get('/home/' + user + '/INBOX/' + str(num_mail) + "/sender")

def mail_body(num_mail):
    return c.get('/home/' + user + '/INBOX/' + str(num_mail) + "/body")

def read_mail(num_mail):
    print(mail(num_mail))

def unread_mail():
    return c.get('/home/' + user + '/INBOX/unread')

def opened_ticket():
    return c.get('/bin/crypto_helpdesk/opened')

def closed_ticket():
    return c.get('/bin/crypto_helpdesk/closed')

def ticket(num_ticket):
    return c.get('/bin/crypto_helpdesk/ticket/' + str(num_ticket))

def read_ticket(num_ticket):
    print('----------Ticket ' + str(num_ticket) + '----------\n' + ticket(num_ticket) + '\n')

def close_ticket(num_ticket):
    return c.post('/bin/crypto_helpdesk/ticket/' + str(num_ticket) + '/close', confirm=True)

def reopen_ticket(num_ticket):
    return c.post('/bin/crypto_helpdesk/ticket/' + str(num_ticket) + '/reopen', confirm=True)

def send_mail(m_to, m_subject, m_content):
    c.post('/bin/sendmail', to=m_to, subject=m_subject, content=m_content)

def police_hq():
    return c.get('/bin/police_hq')

def read_police_hq():
    print(police_hq())

def opened_police_ticket():
    return c.get('/bin/police_hq/opened')

def closed_police_ticket():
    return c.get('/bin/police_hq/closed')

def police_ticket(num_ticket):
    return c.get('/bin/police_hq/ticket/' + str(num_ticket))

def read_police_ticket(num_ticket):
    print('----------Police Ticket ' + str(num_ticket) + '----------\n' + police_ticket(num_ticket) + '\n')

def close_polce_ticket(num_ticket):
    return c.post('/bin/police_hq/ticket/' + str(num_ticket) + '/close', confirm=True)

def reopen_police_ticket(num_ticket):
    return c.post('/bin/police_hq/ticket/' + str(num_ticket) + '/reopen', confirm=True)

def prompt_mail():
    print(unread_mail())
    mail = input('mail' + prompt)
    while(mail != '' and mail != 'q'):
        read_mail(mail)
        print(unread_mail())
        mail = input('mail' + prompt)

    if (mail == 'q'): sys.exit("Fin du programme")

def prompt_ticket():
    print(opened_ticket())
    ticket = input('ticket' + prompt)
    while(ticket != '' and ticket != 'q'):
        read_ticket(ticket)
        print(opened_ticket())
        ticket = input('ticket' + prompt)

    if (ticket == 'q'): sys.exit("Fin du programme")

def prompt_police_ticket():
    print(opened_police_ticket())
    ticket = input('ticket' + prompt)
    while(ticket != '' and ticket != 'q'):
        read_police_ticket(ticket)
        print(opened_police_ticket())
        ticket = input('ticket' + prompt)

    if (ticket == 'q'): sys.exit("Fin du programme")

def upload_public_key(pkey):
    c.post('/bin/key-management/upload-pk', public_key=pkey, confirm=True)

def get_infos(name):
    return c.get('/bin/key-management/' + name)

def get_public_key(name):
    return c.get('/bin/key-management/' + name + '/pk')

def main():
    """
    user = "guest"
    passwd = "guest"
    
    print(c.post('/bin/login', user=user, password=passwd))
    
    print(c.get('/home/' + user))
    print(c.get('/home/' + user + '/INBOX/2/body'))
    print(c.post('/bin/sendmail', to="majordomo@vger.kernel.org", subject="Unsubscribe", content="unsubscribe linux-kernel"))
    """"""
    print(c.post('/bin/login', user=user, password=passwd))
    """"""
    print(c.get('/home/' + user))
    
    print(c.get('/home/' + user + '/INBOX/15321/body'))
    
    print(decryptFile('NASA.bin', 'PAC'))
    """
    challenge = c.get('/bin/login/CHAP')
    challenge = challenge['challenge']
    plaintext = user + '-' + challenge
    new_pass = encrypt(plaintext, passwd)
    c.post('/bin/login/CHAP', user=user, response=new_pass)

    prompt_mail()
    #prompt_ticket()
    prompt_police_ticket()
    
    try:
        """
        #read_ticket(1997)
        client = c.get('/bin/crypto_helpdesk/ticket/1997/attachment/client')
        fetch_me_ticket1997 = c.get('/bin/crypto_helpdesk/ticket/1997/attachment/fetch-me')
        content= {'foo': fetch_me_ticket1997,'bar': 42}
        c.post('/bin/sendmail', to="cschmidt", subject="reponse", content=content)
        print(close_ticket(1997))
        
        #read_ticket(1998)
        client = c.get('/bin/crypto_helpdesk/ticket/1998/attachment/client')
        passw = c.get('/bin/crypto_helpdesk/ticket/1998/attachment/password')
        file_ticket1998 = c.get('/bin/crypto_helpdesk/ticket/1998/attachment/file')
        enc_file_ticket1998 = encrypt(file_ticket1998, passw)
        send_mail(client['email'], "reponse", enc_file_ticket1998)
        print(close_ticket(2018))
        
        #read_ticket(1999)
        client = c.get('/bin/crypto_helpdesk/ticket/1999/attachment/client')
        file_ticket1999 = c.get('/bin/crypto_helpdesk/ticket/1999/attachment/ciphertext')
        cipher = c.get('/bin/crypto_helpdesk/ticket/1999/attachment/cipher')
        passw = c.get('/bin/crypto_helpdesk/ticket/1999/attachment/password')
        dec_file_ticket1999 = decrypt(file_ticket1999, passw, cipher)
        print(dec_file_ticket1999)
        #key = dec_file_ticket1999[dec_file_ticket1999.index('key=') + 4:(dec_file_ticket1999.index('key=') + 4 + 32)]
        send_mail(client['email'], "reponse", dec_file_ticket1999)
        print(close_ticket(1999))
        
        #read_ticket(2018)
        client = c.get('/bin/crypto_helpdesk/ticket/2018/attachment/client')
        file_ticket2018 = c.get('/bin/crypto_helpdesk/ticket/2018/attachment/message')
        pkey = c.get('/bin/crypto_helpdesk/ticket/2018/attachment/public-key')
        pkey_ticket2018 = open('pkey_ticket2018.pem', 'r+')
        pkey_ticket2018.write(pkey)
        enc_file_ticket2018 = encryptPkey(file_ticket2018, pkey_ticket2018.name)
        pkey_ticket2018.close()
        send_mail(client['email'], "reponse", enc_file_ticket2018)
        print(close_ticket(2018))
        """"""
        #read_ticket(2019) #PAS FINI !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
        my_pkey_file = open("publickey.ssl", "r")
        my_pkey = my_pkey_file.read()
        upload_public_key(my_pkey)
        client = c.get('/bin/crypto_helpdesk/ticket/2019/attachment/client')
        contact = c.get('/bin/crypto_helpdesk/ticket/2019/attachment/contact')
        pkey_contact2019 = get_public_key(contact)
        pkey_contact_ticket2019 = open('pkey_contact_ticket2019.pem', 'r+')
        pkey_contact_ticket2019.write(pkey_contact2019)
        enc_message_ticket2019 = encryptPkey("informations sensibles", "pkey_contact_ticket2019.pem")
        pkey_contact_ticket2019.close()
        send_mail(contact, "informations sensibles", enc_message_ticket2019)
        """"""
        enc_file_ticket2019 = c.post('/bin/sendmail', to=contact, subject="reponse", content=enc_message_ticket2019)
        pkey_client = get_public_key(contact)
        dec_file_ticket2019 = decryptPkey(base64.b64decode(), pkey_client)
        send_mail(client['email'], "reponse", dec_file_ticket_2019)
        c.post('/bin/sendmail', to=client['email'], subject="reponse", content=enc_file_ticket2019)
        print(close_ticket(2019))
        
        #read_ticket(2020)
        client = c.get('/bin/crypto_helpdesk/ticket/2020/attachment/client')
        contact = c.get('/bin/crypto_helpdesk/ticket/2020/attachment/contact')
        pkey_contact2020 = get_public_key(contact)
        pkey_contact_ticket2020 = open('pkey_contact_ticket2020.ssl', 'r+')
        pkey_contact_ticket2020.write(pkey_contact2020)
        file_ticket2020 = c.get('/bin/crypto_helpdesk/ticket/2020/attachment/reciprocity')
        enc_message_ticket2020 = encrypt(file_ticket2020, 'MotDePasseTresLong123')
        enc2_message_ticket2020 = encryptPkey('MotDePasseTresLong123', 'pkey_contact_ticket2020.ssl')
        pkey_contact_ticket2020.close()
        dico2020 = {'skey': enc2_message_ticket2020, 'document': enc_message_ticket2020}
        send_mail(contact, "reponse", dico2020)
        print(close_ticket(2020))
        
        #read_mail(17482)
        #read_mail(17483)
        print(mail_sender(17483))
        signature_mail17483 = signature(mail_body(17483), "privatekey.ssl")
        send_mail(mail_sender(17483), 'signature', signature_mail17483)
        """
        client = c.get('/bin/police_hq/ticket/2362/attachment/client')
        username = c.get('/bin/police_hq/ticket/2362/attachment/username')
        trace = c.get('/bin/police_hq/ticket/2362/attachment/trace')
        
        challenge = '9fec39650c6d486cbe7a17c757282596'
        response = 'U2FsdGVkX1+abBKB5ZR0E520B56rZR62sueGzqAIbRPHgNjAc5w9AKJx1kXqeqMz\nrgREINfsznLjbLI8Ja6fqA==\n'
        
        #plaintext = username + '-' + challenge
        #password = decrypt(response, plaintext)
        #print(password)
        #print(trace)
        
        dico = open('words', 'r')
        f = open('pwd_tiffanywelch', 'r+')
        for line in dico:
            if (line != ''):
                new_pass = decrypt(response, str(line))
                if (new_pass.split('-')[0] == str(user)):
                    print("MDP: " + str(line))
                #f.write(new_pass)
                #print(c.post('/bin/login/CHAP', user=username, response=new_pass))
        f.close()

        #Vérifier /sbin/failsafe

    except ServerError as e:
        print('Code: ' + str(e.code) + '\nError: ' + str(e.msg) + '\n')
    
    prompt_mail()
    
    c.close_session()

if __name__ == "__main__": main()
