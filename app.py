import socket
import threading
import eel
import sys
import logging
import os.path
import json
import configparser

# error logger
logger = logging.getLogger(__name__)
logging.basicConfig(filename='errors.log', filemode='a', level=logging.WARNING)
def handle_errors(exc_type, exc_value, exc_traceback):
    if issubclass(exc_type, KeyboardInterrupt):
        sys.__excepthook__(exc_type, exc_value, exc_traceback)
        return
    logger.critical("Unhandled exception: ", exc_info=(exc_type, exc_value, exc_traceback))
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
                if json_object['userid'] == str(user_name):
                    pass
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
                json.dump(json_object, outfile)

start.load_configs()




class p2p():
    def App_snd(argu, call_func=''):
        my_ip = '103.161.55.172'
        port = 2563

        host_name, a, my_address = socket.gethostbyaddr('103.161.55.172')
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
    def add_new_user(ip):
        print(ip)
        ip = str(ip)


eel.start('index.html')



#strt()
#decentralized messaging app
'''
messaging app using python sockets
decentalized naming system for user id storage
link ip to user id
'''