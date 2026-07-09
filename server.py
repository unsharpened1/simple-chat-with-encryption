import socket
import threading
import json
from core import protocol  # Твой пуленепробиваемый модуль работы с сокетами

host, port = 'localhost', 40000

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.bind((host, port))

active_users = {}
clients_lock = threading.Lock()

def register_client(sock):
    try:
        print("[СЕРВЕР ДИАГНОСТИКА 1]: Жду пакет от сокета...")
        raw_data = protocol.receive_packet(sock)
        print(f"[СЕРВЕР ДИАГНОСТИКА 2]: Получил байты: {raw_data}")
        
        if not raw_data:
            print("[СЕРВЕР ДИАГНОСТИКА]: Пакет пустой!")
            return None
            
        client_json = json.loads(raw_data.decode('utf-8'))
        
        if client_json.get("type") != "REGISTER":
            return None
            
        username = client_json['payload']

        with clients_lock:
            if username in active_users:
                server_json = {"type": "ERROR", "payload": "this username already exists"}
                protocol.send_packet(sock, json.dumps(server_json).encode('utf-8'))
                return None
            else:
                active_users[username] = sock
                welcome_json = {"type": "OK", "payload": "Successfully registered"}
                protocol.send_packet(sock, json.dumps(welcome_json).encode('utf-8'))
                return username
    except Exception as e:
        print(f"ERROR: [ Ошибка при регистрации: {e} ]")
        return None

def client_handler(sock, addr):
    """Главный поток для работы с конкретным клиентом после его подключения"""
    username = register_client(sock)
    if not username:
        sock.close()
        return

    print(f"INFO: [ Пользователь {username} успешно вошел в сеть. IP: {addr} ]")

    try:
        while True:
            raw_data = protocol.receive_packet(sock)
            if not raw_data:  # Клиент отключился
                break

            # Декодируем входящий пакет
            packet = json.loads(raw_data.decode('utf-8'))
            
            # Вшиваем имя отправителя, чтобы получатель знал, от кого пакет
            packet["from_user"] = username
            target_user = packet.get("to_user") 

            with clients_lock:
                target_socket = active_users.get(target_user)

            if target_socket:
                # !!! ИСПРАВЛЕНО: Перепаковываем измененный JSON обратно в байты
                forward_data = json.dumps(packet).encode('utf-8')
                protocol.send_packet(target_socket, forward_data)
            else:
                error_json = {"type": "ERROR", "payload": f"User {target_user} is offline"}
                protocol.send_packet(sock, json.dumps(error_json).encode('utf-8'))

    except Exception as e:
        print(f"ERROR: [ Ошибка в сессии пользователя {username}: {e} ]")
        
    finally:
        with clients_lock:
            if username in active_users:
                active_users.pop(username)
        
        sock.close()
        print(f"INFO: [ Пользователь {username} покинул сеть. IP: {addr} ]")

s.listen()
print(f"INFO: [ Сервер запущен и слушает порт {port}... ]")

while True:
    client_socket, client_address = s.accept()
    t = threading.Thread(target=client_handler, args=(client_socket, client_address))
    t.start()