import socket
import threading
import json
import base64
from core import protocol, crypto  # Твои крипто-модули

# Глобальное состояние сессий клиента
current_peer = None
my_nickname = ""

# !!! ИСПРАВЛЕНО: Объявляем структуры для сессий и потокобезопасности
active_sessions = {}
sessions_lock = threading.Lock()

# Ключи RSA текущего клиента
my_private_key = None
my_public_key = None

def receive_loop(sock):
    while True:
        try:
            # Читаем пакет от сервера
            raw_data = protocol.receive_packet(sock)
            if not raw_data:
                print("\n[-] Соединение с сервером потеряно.")
                break

            # Парсим JSON
            packet = json.loads(raw_data.decode('utf-8'))
            packet_type = packet.get("type")
            sender = packet.get("from_user") # Сервер заполнит, от кого это

            # --- 1. ОБРАБОТКА ОШИБОК ОТ СЕРВЕРА ---
            if packet_type == "ERROR":
                print(f"\n[Система]: {packet.get('payload')}")
                continue

            # --- 2. НАМ ПРИСЛАЛИ RSA-КЛЮЧ (Инициация чата) ---
            if packet_type == "HANDSHAKE_RSA":
                peer_pem = packet.get("payload")
                peer_public_key = crypto.deserialize(peer_pem.encode('utf-8'))

                # В ответ отправляем свой RSA-ключ, чтобы собеседник тоже мог зашифровать AES
                my_pem = crypto.serialize(my_public_key).decode('utf-8')
                reply_packet = {
                    "to_user": sender,
                    "type": "HANDSHAKE_RSA_REPLY",
                    "payload": my_pem
                }
                protocol.send_packet(sock, json.dumps(reply_packet).encode('utf-8'))
                
                # Запоминаем публичный ключ инициатора, он нам сейчас пригодится
                # (Хранить его долго не нужно, так как скоро у нас будет общий AES)
                print(f"\n[*] Получен запрос на защищенный чат от {sender}. Отправлен ответный RSA-ключ...")
                continue

            # --- 3. НАМ ОТВЕТИЛИ НА НАШ RSA-КЛЮЧ ---
            elif packet_type == "HANDSHAKE_RSA_REPLY":
                peer_pem = packet.get("payload")
                peer_public_key = crypto.deserialize(peer_pem.encode('utf-8'))

                # Мы были инициаторами, значит, МЫ генерируем секретный AES-ключ
                new_aes_key = crypto.gen_session_key()

                # Сохраняем его в наши активные сессии
                with sessions_lock:
                    active_sessions[sender] = new_aes_key

                # Шифруем этот AES-ключ ПУБЛИЧНЫМ ключом собеседника
                encrypted_aes = crypto.encrypt(new_aes_key, peer_public_key)
                base64_aes = base64.b64encode(encrypted_aes).decode('utf-8')

                # Отправляем зашифрованный AES-ключ собеседнику
                aes_packet = {
                    "to_user": sender,
                    "type": "HANDSHAKE_AES",
                    "payload": base64_aes
                }
                protocol.send_packet(sock, json.dumps(aes_packet).encode('utf-8'))
                print(f"\n[+] Безопасный канал с {sender} успешно установлен (AES ключ отправлен)!")
                continue

            # --- 4. НАМ ПРИСЛАЛИ ЗАШИФРОВАННЫЙ AES-КЛЮЧ ---
            elif packet_type == "HANDSHAKE_AES":
                base64_aes = packet.get("payload")
                encrypted_aes = base64.b64decode(base64_aes)

                # Расшифровываем СВОИМ приватным RSA-ключом
                decrypted_aes_key = crypto.decrypt(encrypted_aes, my_private_key)

                # Сохраняем в активные сессии
                with sessions_lock:
                    active_sessions[sender] = decrypted_aes_key

                print(f"\n[+] Безопасный канал с {sender} успешно установлен (AES ключ получен)!")
                continue

            # --- 5. ОБЫЧНОЕ ТЕКСТОВОЕ СООБЩЕНИЕ ---
            elif packet_type == "TEXT_MSG":
                base64_payload = packet.get("payload")
                encrypted_bytes = base64.b64decode(base64_payload)

                # Проверяем, есть ли у нас ключ для этого человека
                with sessions_lock:
                    aes_key = active_sessions.get(sender)

                if aes_key is None:
                    # Если сообщения шлют без хендшейка — игнорируем из соображений безопасности
                    continue

                # Расшифровываем AES
                decrypted_bytes = crypto.decrypt_aes(encrypted_bytes, aes_key)
                clean_text = decrypted_bytes.decode('utf-8')

                # Выводим сообщение в консоль
                print(f"\n[{sender}]: {clean_text}")

        except Exception as e:
            print(f"\n[!] Ошибка в потоке чтения: {e}")
            break


def send_loop(sock):
    global current_peer
    
    print("\n=== Доступные команды ===")
    print("/chat [имя] - переключиться на беседу с пользователем")
    print("/exit       - выйти из чата\n")

    while True:
        try:
            user_input = input().strip()
            if not user_input:
                continue

            # --- БЛОК ОБРАБОТКИ КОМАНД ---
            if user_input.startswith('/'):
                parts = user_input.split(maxsplit=1)
                command = parts[0].lower()

                if command == '/exit':
                    print("[*] Выход из программы...")
                    break

                elif command == '/chat':
                    if len(parts) < 2:
                        print("[!] Ошибка: укажите имя пользователя. Пример: /chat Alice")
                        continue
                    
                    new_peer = parts[1].strip()
                    if new_peer == my_nickname:
                        print("[!] Нельзя начать чат с самим собой!")
                        continue

                    current_peer = new_peer
                    print(f"[+] Переключено на чат с [{current_peer}].")
                    
                    with sessions_lock:
                        has_session = current_peer in active_sessions

                    if not has_session:
                        print(f"[*] Безопасное соединение с {current_peer} еще не установлено.")
                        print(f"[*] Отправляю запрос на хендшейк...")
                        
                        my_pem = crypto.serialize(my_public_key).decode('utf-8')
                        handshake_packet = {
                            "to_user": current_peer,
                            "type": "HANDSHAKE_RSA",
                            "payload": my_pem
                        }
                        protocol.send_packet(sock, json.dumps(handshake_packet).encode('utf-8'))
                    continue
                
                else:
                    print("[!] Неизвестная команда. Используйте /chat или /exit")
                    continue

            # --- БЛОК ОТПРАВКИ ОБЫЧНЫХ СООБЩЕНИЙ ---
            if current_peer is None:
                print("[!] Ошибка: вы не выбрали собеседника. Используйте команду: /chat [имя]")
                continue

            with sessions_lock:
                aes_key = active_sessions.get(current_peer)

            if aes_key is None:
                print(f"[!] Подождите, защищенный канал с {current_peer} еще устанавливается...")
                continue

            raw_bytes = user_input.encode('utf-8')
            encrypted_bytes = crypto.encrypt_aes(raw_bytes, aes_key)
            base64_payload = base64.b64encode(encrypted_bytes).decode('utf-8')

            packet = {
                "to_user": current_peer,
                "type": "TEXT_MSG",
                "payload": base64_payload
            }

            protocol.send_packet(sock, json.dumps(packet).encode('utf-8'))
            print(f"[Вы -> {current_peer}]: {user_input}")

        except Exception as e:
            print(f"[!] Ошибка при отправке сообщения: {e}")
            break


def main():
    global my_private_key, my_public_key, my_nickname
    
    # !!! ИСПРАВЛЕНО: Генерируем RSA ключи клиента при старте приложения
    print("[*] Генерация пары криптографических ключей RSA...")
    my_private_key, my_public_key = crypto.genkey()

    HOST = 'localhost'
    PORT = 40000
    
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.connect((HOST, PORT))
        print("[+] Успешное подключение к серверу.")
    except Exception as e:
        print(f"[!] Не удалось подключиться к серверу: {e}")
        return

    my_nickname = input("Введите ваш никнейм: ").strip()
    
    reg_packet = {"type": "REGISTER", "payload": my_nickname}
    protocol.send_packet(sock, json.dumps(reg_packet).encode('utf-8'))
    
    auth_response = protocol.receive_packet(sock)
    auth_data = json.loads(auth_response.decode('utf-8'))
    
    if auth_data.get("type") == "ERROR":
        print(f"[!] Ошибка регистрации: {auth_data.get('payload')}")
        sock.close()
        return
        
    print("[+] Регистрация завершена успешно!")

    # Запуск фонового прослушивания сети
    reader_thread = threading.Thread(target=receive_loop, args=(sock,), daemon=True)
    reader_thread.start()
    
    # Запуск интерактивного ввода команд
    send_loop(sock)
    
    sock.close()
    print("[*] Сессия закрыта. Пока!")

if __name__ == "__main__":
    main()