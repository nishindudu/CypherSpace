import socket
import threading
import eel
import sys
import logging
import os.path
import json
import configparser
import subprocess
import time
import queue
from requests import get
import platform
import rsa
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from getpass import getpass

class er():
    is_error1 = False

# error logger
logger = logging.getLogger(__name__)
logging.basicConfig(filename='errors.log', filemode='a', level=logging.WARNING)
def handle_errors(exc_type, exc_value, exc_traceback):
    if issubclass(exc_type, KeyboardInterrupt):
        sys.__excepthook__(exc_type, exc_value, exc_traceback)
        return
    logger.critical("Unhandled exception: ", exc_info=(exc_type, exc_value, exc_traceback))
    er.is_error1 = True
sys.excepthook = handle_errors



config = configparser.ConfigParser()
class start():
    executed_before = False
    fernet_key = ''
    def load_configs():
        if not os.path.exists('./config/configfile.ini'):
            # print('config file does not exist')
            logger.debug('Config file does not exist \nCreating config file.')
            config.add_section('app')
            config.set('app', 'executed_before', 'False')
            start.executed_before = False
            try:
                os.mkdir('./config')
            except Exception:
                logger.error('mkdir failed or folder exists')
            public_key, private_key = encrypt.generate_keys()
            password = getpass('Create a password: ')
            salt = os.urandom(16)
            start.fernet_key = encrypt.derive_fernet_key(password, salt)
            encrypted_private_key = encrypt.encrypt_private_key(private_key, start.fernet_key)
            encrypted_private_key = base64.b64encode(encrypted_private_key).decode('utf-8')
            fernet_key = base64.b64encode(start.fernet_key).decode('utf-8')
            public_key = base64.b64encode(public_key).decode('utf-8')
            salt = base64.b64encode(salt).decode('utf-8')
            config.set('app', 'private_key', encrypted_private_key)
            config.set('app', 'public_key', public_key)
            config.set('app', 'salt', salt)
            del private_key
            del salt
            with open(r"./config/configfile.ini", 'w') as configfile:
                config.write(configfile)
        else:
            config.read("./config/configfile.ini")
            password = getpass('Enter your password: ')
            salt = config['app']['salt']
            salt = base64.b64decode(salt)
            start.fernet_key = encrypt.derive_fernet_key(password, salt)
            encrypted_private_key = config['app']['private_key']
            encrypted_private_key = base64.b64decode(encrypted_private_key)
            if encrypt.decrypt_private_key(encrypted_private_key, start.fernet_key) == 'Invalid Password2563;':
                print('Invalid password')
                input('Press any key to exit')
                sys.exit('Incorrect Password')
            start.executed_before = True
    
    def add_config(section, key, value):
        config.read("./config/configfile.ini")
        if config.has_section(section):
            section1 = config[section]
            if config.has_option(section, key):
                section1[key] = value
            else:
                config.set(section, key, value)
        else:
            config.add_section(section)
            config.set(section, key, value)
        with open(r"./config/configfile.ini", 'w') as configfile:
            config.write(configfile)
    
    def get_config(section, key):
        config.read("./config/configfile.ini")
        if config.has_section(section):
            if config.has_option(section, key):
                dbread = config[section]
                value = dbread[key]
                return value
        else:
            raise Exception('Does not exist in configuration file')
    
    def add_user_to_db(user_name, ip, public_key):
        if os.path.exists(r'./config/userdb.json'):
            with open(r'./config/userdb.json') as db:
                json_object = json.load(db)
                for dict in json_object:
                    if dict['userid'] == user_name:
                        # print('user exists')
                        return 'User Exists'
            dictionary = [{
                "userid": f'{user_name}',
                "ip": f'{ip}',
                'key': f'{public_key}'
            }]
            json_object.extend(dictionary)
            with open(r"./config/userdb.json", 'w') as outfile:
                json.dump(json_object, outfile)
        else:
            dictionary = [{
                "userid": f'{user_name}',
                "ip": f'{ip}'
            }]
            with open(r"./config/userdb.json", 'w') as outfile:
                json.dump(dictionary, outfile)
    
    def get_user_list():
        if os.path.exists(r'./config/userdb.json'):
            with open(r'./config/userdb.json') as db:
                json_object = json.load(db)
                user_list = []
                for dict in json_object:
                    usr = [dict['userid'], dict['ip']]
                    user_list.append(usr)
                return user_list
    
    def ping(ip):
        param = '-n' if platform.system().lower() == 'windows' else '-c'
        command = ['ping', param, '1', ip]
        return subprocess.call(command) == 0



class encrypt():
    def generate_keys(keysize=2048):
        logger.debug('Generating keys')
        (public_key, private_key) = rsa.newkeys(keysize)
        public_key = public_key.save_pkcs1('PEM')
        private_key = private_key.save_pkcs1('PEM')
        return public_key, private_key

    def encrypt(message, public_key):
        logger.debug('encrypt.encrypt() - Encrypting message')
        ciphertext = rsa.encrypt(message.encode('utf-8'), public_key)
        return ciphertext

    def decrypt(ciphertext, private_key):
        logger.debug('Decrypting')
        try:
            message = rsa.decrypt(ciphertext, private_key).decode('utf-8')
            return message
        except:
            logger.error('Decryption failed')
            return 'Failed2563;'
    
    def derive_fernet_key(password, salt):
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=390000
        )
        key = base64.urlsafe_b64encode(kdf.derive(password.encode('utf-8')))
        return key

    def encrypt_private_key(key, password):
        logger.debug('Encrypting key')
        fernet = Fernet(password)
        # key_bytes = key.save_pkcs1('PEM')
        encrypted_private_key = fernet.encrypt(key)
        return encrypted_private_key
    
    def decrypt_private_key(key, password):
        logger.debug('Decrypting key')
        fernet = Fernet(password)
        try:
            private_key_bytes = fernet.decrypt(key)
            private_key = rsa.PrivateKey.load_pkcs1(private_key_bytes)
            return private_key
        except:
            logger.error('Invalid Password')
            return 'Invalid Password2563;'



start.load_configs()


# print(start.get_user_list()[0][0])

class p2p():
    def App_snd(argu, call_func=''):
        # my_ip = str(input("enter your IP:"))
        my_ip = '127.0.0.1'
        print(my_ip)
        port = 2563

        host_name, a, my_address = socket.gethostbyaddr(my_ip)
        print(host_name)

        server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_sock.bind((host_name, port))
        server_sock.listen(1)
        conn, addr = server_sock.accept()
        print(f'Connected to {addr}')

        def meow():
            print('mewo')
        def send_msg(msg):
            conn.send(msg)
            return True
        
        def recv_msg():
            while True:
                recvd_msg = conn.recv(1024)
                if recvd_msg == 'user_id_req':
                    my_userid = start.get_config('app', 'user')
                    send_msg(my_userid)
                else:
                    return recvd_msg

        thread = threading.Thread(target=recv_msg)
        thread.start()

        if call_func=='meow':
            meow()
        elif call_func=='send_msg':
            send_msg(argu)
     

    def add_new():
        pass

class peer():
    # data_queue_user_id = queue.Queue()
    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.connections = []
    def connect(self, peer_host, peer_port):
        connection = socket.create_connection((peer_host, peer_port))

        self.connections.append(connection)
        # print(f'connected to {peer_host}')
        logger.debug(f'peer class - connect connected to {peer_host}')
    
    def listen(self):
        self.socket.bind((self.host, self.port))
        self.socket.listen(10)
        logger.debug(f'peer class - listen listening on {self.host}:{self.port}')

        while True:
            connnection, address = self.socket.accept()
            self.connections.append(connnection)
            logger.debug('accepted connection from %s', address)
            threading.Thread(target=self.handle_client, args=(connnection, address)).start()
    
    def send_data(self, data):
        for connection in self.connections:
            try:
                if not isinstance(data, bytes):
                    connection.sendall(data.encode())
                else:
                    connection.sendall(data)
            except Exception as e:
                logger.error('Failed to send data in send_data. Error : %s', e)
                self.connections.remove(connection)
    
    def handle_client(self, connection, address):
        temp_user_id_addr = '0'
        while True:
            try:
                data = connection.recv(1024)
                if not data:
                    break
                logger.debug('Recveived data from %s', address)
                decoded_data = data.decode()
                # print(f"Received data from {address}: {decoded_data}")

                if decoded_data == 'user_id_req':
                    user_id = start.get_config('app', 'user')
                    public_key = start.get_config('app', 'public_key')
                    user_id = 'user_id:'+ user_id + ',' + public_key
                    connection.sendall(user_id.encode())
                    # print(f'sending respose to {address} : {user_id}')
                    if temp_user_id_addr != str(address):
                        time.sleep(1)
                        connection.sendall('user_id_req')
                        temp_user_id_addr = str(address)
                    break
                if 'user_id:' in decoded_data:
                    user_id_recvd = decoded_data.split(':')[1]
                    user_id_recvd0 = user_id_recvd.split(',')[0]
                    public_key_recvd = user_id_recvd.split(',')[1]
                    # print(user_id_recvd)
                    start.add_user_to_db(user_id_recvd0, str(address[0]), public_key_recvd)
                    # self.data_queue_user_id.put(user_id_recvd)
                    break
                else:
                    uii.recv_msg(decoded_data, address)
                break

            except Exception as e:
                logger.error('error in handle_client %s', e)
        logger.debug('connection from %s closed', address)
        self.connections.remove(connection)
        connection.close()
    
    def start(self):
        listen_thread = threading.Thread(target=self.listen)
        listen_thread.daemon = True
        listen_thread.start()


class uii():
    user_msgs = {}

    eel.init("web")

    @eel.expose
    def ui():
        return 'hello'
    
    @eel.expose
    def is_new_user():
        executed_before = start.get_config('app', 'executed_before')
        # print(executed_before)
        if executed_before == 'True':
            return False
        if executed_before == 'False':
            return True
    
    @eel.expose
    def new_user(userid):
        start.add_config('app', 'user', userid)
        start.add_config('app', 'executed_before', 'True')
        return True
    
    @eel.expose
    def open_license():
        subprocess.Popen(["notepad.exe", 'LICENSE'])
    
    @eel.expose
    def is_error():
        if not er.is_error1:
            return False
        else:
            return True
    
    @eel.expose
    def get_user_list():
        logger.debug('uii.get_user_list() called by js')
        user_list = start.get_user_list()
        return user_list
    
    @eel.expose
    def get_user_msg_list(user):
        try:
            logger.debug('get_user_msg_list called by js')
            msgs = uii.user_msgs
            req_user = msgs[user]
            # print(req_user[0][0], req_user[0][1])
            for i in req_user:
                # print(i)
                if i[0] == 'sent':
                    eel.add_new_msg(str(i[1]), True)
                if i[0] == 'recvd':
                    eel.add_new_msg(str(i[1]), False)
        except KeyError as e:
            logger.info('Key not found in dict %s', e)
            return False


    @eel.expose
    def add_new_user(ip):
        ip = str(ip)
        node1 = peer('0.0.0.0', 585)
        node1.connect( ip, 585)
        node1.send_data('user_id_req')
        # user_name = peer.data_queue_user_id.get(timeout=5)
        # start.add_user_to_db(user_name=user_name, ip=ip)
        # print('success!')
        logger.debug('added new user')
        return True
    
    @eel.expose
    def send_msg(msg, user):
        user_list = start.get_user_list()
        eel.add_new_msg(msg, True)
        # print(user_list)
        for i in user_list:
            for j in i:
                if j == user:
                    user_ip = i[1]
                    user_public_key = i[2]
                    # print(user_ip)
        msg = encrypt.encrypt(msg, user_public_key)
        node1 = peer('0.0.0.0', 585)
        node1.connect(user_ip, 585)
        node1.send_data(msg)
        logger.debug('message sent from send_msg')
        if user in uii.user_msgs:
            uii.user_msgs[user].append(('sent', msg))
            return
        new_dict = {str(user): [('sent', msg)]}
        uii.user_msgs.update(new_dict)
        eel.get_msg_list()
        return True
    
    def recv_msg(msg, ip):
        user_list = start.get_user_list()
        user_name = ''
        logger.debug('message receive function')
        private_key = start.get_config('app', 'private_key')
        private_key = encrypt.decrypt_private_key(private_key, start.fernet_key)
        for i in user_list:
            if i[1] == ip:
                user_name = str(i[0])
        msg = encrypt.decrypt(msg, private_key)
        if user_name in uii.user_msgs:
            uii.user_msgs[user_name].append(('recvd', msg))
            if eel.user_in_view == user_name:
                eel.add_new_msg(msg, False)
            return
        new_dict = {str(user_name): [('recvd', msg)]}
        uii.user_msgs.update(new_dict)
        if eel.user_in_view == user_name:
            eel.add_new_msg(msg, False)
    
    @eel.expose
    def get_my_ip():
        ip = get('https://api.ipify.org').content.decode('utf-8')
        return str(ip)
    
    @eel.expose
    def is_user_online(user):
        user_list = start.get_user_list()
        for i in user_list:
            if i[0] == user:
                user_ip = i[1]
        is_online = start.ping(user_ip)
        return is_online
    
    @eel.expose
    def close_event():
        sys.exit(0)




node1 = peer('0.0.0.0', 585)
node1.start()


eel.start('index.html')

uii.close_event()