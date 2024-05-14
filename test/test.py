import importlib
import os
import sys
import subprocess
import threading
from types import SimpleNamespace
from http.server import BaseHTTPRequestHandler, HTTPServer


def run_http_server():
    port = 1234
    data = os.urandom(1024 * 1024)

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200)
            self.end_headers()
            self.wfile.write(data)

    server = HTTPServer(('', port), Handler)

    def serve():
        try:
            server.serve_forever()
        except Exception as e:
            print(e)

    thread = threading.Thread(target=serve)
    thread.start()

    def stop():
        server.shutdown()

    return SimpleNamespace(port=port, data=data, stop=stop)


def run_cmd(cmd):
    child = subprocess.run(
        cmd, capture_output=True,
        shell=True, executable='/bin/bash')

    def output():
        if child.stdout:
            print(child.stdout.decode())

        if child.stderr:
            print(child.stderr.decode())

    child.output = output
    return child


def test_echo_encode(app):
    data = bytes([i for i in range(0x100)])
    cmd = app.echo_encode(data)
    assert run_cmd(cmd).stdout == data


def test_executor(server, arch):
    url = f'127.0.0.1:{server.port}/hello'
    exe = f'test/get.{arch}'
    cmd = f'./wget-asm.py {url} --arch {arch} --exe {exe}'
    child = run_cmd(cmd)
    assert not child.returncode, child.output()

    if arch == 'x86':
        child = run_cmd(exe)
    else:
        child = run_cmd(f'qemu-{arch} {exe}')

    assert not child.returncode, child.output()
    assert child.stdout == server.data


def main():
    sys.path.append('.')
    app = importlib.import_module('wget-asm')
    test_echo_encode(app)

    server = run_http_server()
    try:
        test_executor(server, 'x86')
        test_executor(server, 'arm')
        test_executor(server, 'armeb')
        test_executor(server, 'mips')
        test_executor(server, 'mipsel')
    finally:
        server.stop()

    print('test passed!')


if __name__ == '__main__':
    main()
