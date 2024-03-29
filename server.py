import http.server
import socketserver

PORT = 8000

class CustomHandler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        if self.path.endswith(".html"):
            try:
                with open(self.path[1:], "rb") as f:
                    content = f.read()
                    self.send_response(200)
                    self.send_header("Content-type", "text/html")
                    self.end_headers()
                    self.wfile.write(content)
            except FileNotFoundError:
                self.send_error(404, "File not found")
        else:
            super().do_GET()

with socketserver.TCPServer(("", PORT), CustomHandler) as httpd:
    print(f"Serving at port {PORT}")
    httpd.serve_forever()
