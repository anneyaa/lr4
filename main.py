import socket
import threading
import urllib.parse

HOST = '127.0.0.1'
PORT = 8888
BUFFER_SIZE = 8192
BLACKLIST_FILE = 'blacklist.txt'

print_lock = threading.Lock()


def log(msg):
    with print_lock:
        print(msg)


def load_blacklist():
    try:
        with open(BLACKLIST_FILE, 'r') as f:
            return [line.strip().lower() for line in f if line.strip()]
    except:
        return []


def read_request(sock):
    data = b''
    while b'\r\n\r\n' not in data:
        chunk = sock.recv(BUFFER_SIZE)
        if not chunk:
            break
        data += chunk
    return data


def handle_client(client_socket):
    try:
        request = read_request(client_socket)
        if not request:
            return

        first_line = request.split(b'\r\n')[0].decode(errors='ignore')
        parts = first_line.split()

        if len(parts) < 3:
            return

        method, url, version = parts

        if method == "CONNECT":
            client_socket.sendall(b"HTTP/1.1 405 Method Not Allowed\r\n\r\n")
            return

        parsed = urllib.parse.urlparse(url)
        host = parsed.hostname
        port = parsed.port or 80
        path = parsed.path or "/"
        if parsed.query:
            path += "?" + parsed.query

        if not host:
            return

        blacklist = load_blacklist()

        #чс
        if any(b in host.lower() for b in blacklist):
            log(f"{url} - 403 Forbidden")
            response = (
                "HTTP/1.1 403 Forbidden\r\n"
                "Content-Type: text/html\r\n\r\n"
                "<h1>Access Denied</h1>"
            )
            client_socket.sendall(response.encode())
            return

        lines = request.decode(errors='ignore').split('\r\n')
        new_request = f"{method} {path} {version}\r\n"

        for line in lines[1:]:
            if line.lower().startswith("proxy-connection"):
                continue
            new_request += line + "\r\n"

        new_request += "\r\n"

        #соединение с сервером
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.connect((host, port))
        server_socket.sendall(new_request.encode())

        status_code = "Unknown"
        status_text = ""
        logged = False

        while True:
            data = server_socket.recv(BUFFER_SIZE)
            if not data:
                break

            if not logged:
                try:
                    status_line = data.split(b'\r\n')[0].decode()
                    parts = status_line.split()
                    status_code = parts[1]
                    status_text = ' '.join(parts[2:])

                    skip_patterns = ["detectportal.firefox.com", "favicon.ico"]
                    should_log = not any(p in url for p in skip_patterns)

                    if should_log:
                        log(f"{url} - {status_code} {status_text}")
                except:
                    pass
                logged = True

            client_socket.sendall(data)

        server_socket.close()

    except (ConnectionResetError, BrokenPipeError, OSError):
        pass
    except Exception as e:
        log(f"Error: {e}")
    finally:
        client_socket.close()


def start_proxy():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((HOST, PORT))
    server.listen(50)

    print(f"Прокси-сервер запущен {HOST}:{PORT}\n")

    while True:
        client_socket, _ = server.accept()
        threading.Thread(
            target=handle_client,
            args=(client_socket,),
            daemon=True
        ).start()


if __name__ == "__main__":
    start_proxy()