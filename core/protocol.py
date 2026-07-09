import struct

def send_packet(sock, data_bytes):
    # 1. Считаем длину тела (кол-во байт)
    length = len(data_bytes)
    # 2. Пакуем длину в 4 байта (символ '>' обязателен и там, и там!)
    header = struct.pack('>I', length)
    # 3. Отправляем заголовок, а затем данные
    sock.sendall(header + data_bytes)

def receive_packet(sock):
    # Читаем заголовок (4 байта)
    header = b''
    bytes_left = 4
    while bytes_left > 0:
        chunk = sock.recv(bytes_left)
        if chunk == b'':
            return None
        header += chunk
        bytes_left -= len(chunk)
        
    # Распаковываем длину тела
    length = struct.unpack('>I', header)[0]
    
    # Читаем само тело сообщения
    buffer = b''
    bytes_left = length
    while bytes_left > 0:
        chunk = sock.recv(bytes_left)
        if chunk == b'':
            return None
        buffer += chunk
        bytes_left -= len(chunk)
        
    return buffer