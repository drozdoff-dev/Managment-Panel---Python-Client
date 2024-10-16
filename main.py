import hashlib
import sys
import urllib.request, json
from tracemalloc import start
import requests
from getpass import getpass
from pyfiglet import Figlet, fonts, FigletFont
from colorama import init, Fore, Back, Style

servers_select = 'index' # основной сервер управления(распределительный, начальный)
host_to_server = "http://localhost:8081" # хост основного сервера управления

hash_to_web_public = "fwnAtvDZXXkYxYXaErzToqKfrFNHhKiklgspjMWvltWzeWARodBXcHtStqKeHhmJiFxhdpXpsGXOSyuTJUSINcfKPYBkRMWQNrPyhhiCycbZgjcdMBohZyChJGGTujmZ"
hash_to_web_private = "wlTYdxGTZIudHsgBSkTSlaDJlyiPaMiHqPOkBjNfgNxVJfHtfUnrQmoPkThieqBVxQtuTsECBVQZiGNTabofaBHBHotVNKbPndICPFJIOwfvIxmSuOQphlGpsWzlxowq"
key_to_long = "lNHZUVxjxoVpSqkfAVHST94IpB3Cu97BBUMNBY5fw02vNzcX3VTzjAhMOha6cH0xpzjmms3vLOCuKxpdkcQpxCRxd2qyyDsQ1txOpGJeocqLTBDp0SLarDpwbm1ok9a8pp4XE0YzUvVfulcNIOF362rR9qwdHmkCeMyzQKTTm7hoRE8rMUSmHHioWbP7m5L317MqTZKB4KRqp0EEK4YnSAW8BXT9IDgckxmKOGDdGBMFBLzMbMDNp1pTcLzfcFNvjkU3fiNnIentnaWSboS7V9HPGijWkcdHQ37zlM7kfFb0A53fYgnYLTIFhs5PumdrO54k7jTghdZ8GQP0ubx4EhwW9uSlJBT5KIsJroyLp3ieKaD7YigWAFpL0wNbO4CXlHUulhFZp63Pw17PT8Kmy8NByATtrPhuhWHfRzM49AjXipdFMU1VdRSnNeuC3wye8aflHqgLFq2KAdoiXFPr6XnCd1qo9StKKZ4ohPcS14V83O7EJCzG8oLQ4YYXg1L3"

def check_job_server(host):
    print("[Проверка...] Подключение к серверу...")
    try:
        requests.post(host)
        print("[Подключено] Сервер Управления успешно подключён.")
        auth()
    except requests.exceptions.ConnectionError:
        print("[Ошибка] Сервер Управления выключен.")
        return 0

def hashing(password,command):
    hash_private_md5 = hashlib.md5(hash_to_web_private.encode('utf-8'))
    hash_private_md5_result = hash_private_md5.hexdigest()
    hash_private_sha512 = hashlib.sha512(hash_private_md5_result.encode('utf-8'))
    hash_private = hash_private_sha512.hexdigest()

    hash_objects_pass_sha = hashlib.sha512(password.encode('utf-8'))
    hex_digs_sha = hash_objects_pass_sha.hexdigest()
    hash_objects_pass_md5 = hashlib.md5(hex_digs_sha.encode('utf-8'))
    hash_pass_md5 = hash_objects_pass_md5.hexdigest()
    hash_objects_pass_md5_sha = hashlib.sha512(hash_pass_md5.encode('utf-8'))
    hash_pass = hash_objects_pass_md5_sha.hexdigest()

    hash_to_web_public_sha512 = hashlib.sha512(hash_to_web_public.encode('utf-8'))
    hash_to_web_public_sha512_result = hash_to_web_public_sha512.hexdigest()

    hash_to_web_public_sha256 = hashlib.sha256(hash_to_web_public.encode('utf-8'))
    hash_to_web_public_sha256_result = hash_to_web_public_sha256.hexdigest()

    password_check = hash_private + hash_pass + hash_to_web_public_sha512_result

    hash_command_sha512 = hashlib.sha512(command.encode('utf-8'))
    hash_command_input = hash_command_sha512.hexdigest()

    hash_command_input1 = hash_command_input + hash_private
    
    return [password_check, hash_to_web_public_sha256_result, hash_command_input1]

def auth():
    print("\nАвторизация")
    login = input('Login: ')
    if(login != "#" and login != "." and login != "?" and login[0] != "/" and login.find("/", 1) == -1 and login[1] != " "):
        password = getpass('Password: ')
        pass_md5 = hashlib.md5(password.encode('utf-8'))
        password_md5 = pass_md5.hexdigest()
        
        password_check = hashing(password_md5,"none_command")[0]
        hash_to_web_public_sha256_result = hashing(password_md5,"none_command")[1]

        print('[Обмен информацией с сервером]...')
        url = f'{host_to_server}/managment/auth/{servers_select}/{login}/{password_check}/{hash_to_web_public_sha256_result}/{key_to_long}'
        response = requests.post(url).json()
        if(response[0]['authentication'][0]['login'] == login and response[0]['authentication'][0]['api'] == 'auth' and response[0]['authentication'][0]['status'] == 'success'):
            print('Добро пожаловать в панель управления, Уважаемый [' + response[0]['authentication'][0]['rang'] + '] ' + response[0]['authentication'][0]['name'] + '.')
            return managment(login,password_check,hash_to_web_public_sha256_result,servers_select,host_to_server)
        elif(response[0]['authentication'][0]['login'] == login and response[0]['authentication'][0]['api'] == 'auth' and response[0]['authentication'][0]['status'] == 'invalid password'):
            print('Вы ввели неправильный пароль.')
        elif(response[0]['authentication'][0]['login'] == login and response[0]['authentication'][0]['api'] == 'auth' and response[0]['authentication'][0]['status'] == 'invalid login'):
            print('Вы ввели неправильный логин.')
        elif(response[0]['authentication'][0]['login'] == login and response[0]['authentication'][0]['api'] == 'auth' and response[0]['authentication'][0]['status'] == 'invalid public_key'):
            print('Неверный публичный ключ доступа.')
        elif(response[0]['authentication'][0]['login'] == login and response[0]['authentication'][0]['api'] == 'auth' and response[0]['authentication'][0]['status'] == 'invalid api'):
            print('Неизвестный индефикатор API.')
        else:
            print('Произошла непредвиденная ошибка во время авторизации.')
    else:
        print('Команда содержит недопустимые знаки.')
        return auth()

def managment(login,password_check,hash_to_web_public_sha256_result,server_select,host_server):
    command = 0
    command = input(f"[{server_select}]>>> ")
    if(command != 0 and command and command != '/'):
        if(command[0] == "/" and command.find("/", 1) == -1 and command[1] != " "):
            command_str = command.replace("/", "")
            args = command_str.split(maxsplit=1)

            command_private_key_sha512 = hashing("none_password",command_str)[2]
            
            if(" " in command_str):
                if(args[0] != "#" and args[1] != "#" and args[0] != "." and args[1] != "." and args[0] != "?" and args[1] != "?"):
                    url = f'{host_server}/managment/commands/{login}/{password_check}/{server_select}/{args[0]}/{args[1]}/{command_private_key_sha512}/{hash_to_web_public_sha256_result}/{key_to_long}'
                else:
                    print('Команда содержит недопустимые знаки.')
                    return managment(login,password_check,hash_to_web_public_sha256_result,server_select,host_server)
            else:
                if(command_str != "#" and command_str != "." and command_str != "?"):
                    url = f'{host_server}/managment/commands/{login}/{password_check}/{server_select}/{command_str}/args_none/{command_private_key_sha512}/{hash_to_web_public_sha256_result}/{key_to_long}'
                else:
                    print('Команда содержит недопустимые знаки.')
                    return managment(login,password_check,hash_to_web_public_sha256_result,server_select,host_server)
            response = requests.post(url).json()

            #переменные ответов от сервера
            answer = response[0]['commands'][0]['answer']
            command_request = response[0]['commands'][0]['command']
            server_select_request = response[0]['commands'][0]['server_select']
            server_to_request = response[0]['commands'][0]['server_to']
            status_request = response[0]['commands'][0]['status']
            server_host = response[0]['commands'][0]['server_host']
            #переменные ответов от сервера

            #print(f"Ответ от сервера:\n{answer}\n\nОтправляемая команда: {command_request}\n\nВозвращаемый сервер: {server_select_request}\n\nОтправляемый сервер: {server_to_request}.")
            print(answer)
            if(command_request == "/leave" or command_request == "/quit" or command_request == "/q" and status_request == "quit"):
                return sys.exit()
            elif(status_request == "closed"):
                return sys.exit()
            else:
                return managment(login,password_check,hash_to_web_public_sha256_result,server_select_request,server_host)
        else:
            print('Команда должна начинаться со "/", и не иметь впоследующем в строке данного знака "/". А так же после "/" не должно присутствовать пробела')
            return managment(login,password_check,hash_to_web_public_sha256_result,server_select,host_server)
    else:
        print('Вы отправили пустое поле. Используется /help для просмотра доступных команд.')
        return managment(login,password_check,hash_to_web_public_sha256_result,server_select,host_server)


if __name__ == '__main__':
    check_job_server(host_to_server)