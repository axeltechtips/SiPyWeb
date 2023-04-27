# Import the modules
import http.server
import socketserver

# Define the port number
PORT = 8000

# Create a custom handler class that inherits from SimpleHTTPRequestHandler
class CustomHandler(http.server.SimpleHTTPRequestHandler):

    # Override the do_GET method to serve custom html files
    def do_GET(self):
        # Check if the requested path is a valid html file
        if self.path.endswith(".html"):
            # Try to open the file and read its contents
            try:
                # Open the file in binary mode
                with open(self.path[1:], "rb") as f:
                    # Read the file contents
                    content = f.read()
                    # Send a 200 OK response
                    self.send_response(200)
                    # Send the content type header
                    self.send_header("Content-type", "text/html")
                    # End the headers
                    self.end_headers()
                    # Write the file contents to the response body
                    self.wfile.write(content)
            # Handle any exceptions
            except Exception as e:
                # Print the error message
                print(e)
                # Send a 404 Not Found response
                self.send_error(404, "File not found")
        # Otherwise, use the default behavior of SimpleHTTPRequestHandler
        else:
            # Call the parent class method
            http.server.SimpleHTTPRequestHandler.do_GET(self)

# Create a socket server object
with socketserver.TCPServer(("", PORT), CustomHandler) as httpd:
    # Print a message to indicate the server is running
    print(f"Serving at port {PORT}")
    # Serve requests until interrupted
    httpd.serve_forever()