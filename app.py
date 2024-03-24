import socket
import threading
import eel
import sys
import logging
import os.path
import json
import configparser
import subprocess

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
    def load_configs():
        if not os.path.exists('./config/configfile.ini'):
            print('config file does not exist')
            config.add_section('app')
            config.set('app', 'executed_before', 'False')
            start.executed_before = False
            with open(r"./config/configfile.ini", 'w') as configfile:
                config.write(configfile)
        else:
            config.read("./config/configfile.ini")
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
    
    def add_user_to_db(user_name, ip):
        if os.path.exists(r'./config/userdb.json'):
            with open(r'./config/userdb.json') as db:
                json_object = json.load(db)
                for dict in json_object:
                    if dict['userid'] == user_name:
                        # print('user exists')
                        return 'User Exists'
            dictionary = [{
                "userid": f'{user_name}',
                "ip": f'{ip}'
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

start.load_configs()


start.add_user_to_db('meow', '127.0.0.1')
start.add_user_to_db('cat', '192.168.1.1')
start.add_user_to_db('test', '0.0.0.1')

print(start.get_user_list()[0][0])

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
            logger.debug(f'accepted connection from {address}')
            threading.Thread(target=self.handle_client, args=(connnection, address)).start()
    
    def send_data(self, data):
        for connection in self.connections:
            try:
                connection.sendall(data.encode())
            except socket.error as e:
                logger.error(f'Failed to send data. Error : {e}')
                self.connections.remove(connection)
    
    def handle_client(self, connection, address):
        while True:
            try:
                data = connection.recv(1024)
                if not data:
                    break
                logger.debug(f'recveived data from {address}')
                decoded_data = data.decode()
                print(f"Received data from {address}: {decoded_data}")

                if decoded_data == 'user_id_req':
                    user_id = start.get_config('app', 'user')
                    connection.sendall(user_id.encode())
                    print(user_id)
                    print(f'sending respose to {address} : {user_id}')
                    break

            except socket.error as e:
                logger.error(f'error : {e}')
        logger.debug(f'connection from {address} closed')
        self.connections.remove(connection)
        connection.close()
    
    def start(self):
        listen_thread = threading.Thread(target=self.listen)
        listen_thread.start()


class uii():
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
        if er.is_error1 == False:
            return False
        else:
            return True
    
    @eel.expose
    def get_user_list():
        pass

    @eel.expose
    def add_new_user(ip):
        # print(ip)
        ip = str(ip)
        user_name = 0
        start.add_user_to_db(user_name=user_name, ip=ip)


# eel.start('index.html')

'''
node1 = peer('0.0.0.0', 8523)
node1.start()


node2 = peer('0.0.0.0', 8464)
node2.start()

import time
time.sleep(2)
node2.connect('127.0.0.1', 8523)
time.sleep(1)
node2.send_data("user_id_req")
'''

#strt()
#decentralized messaging app
'''
messaging app using python sockets
decentalized naming system for user id storage
link ip to user id
'''