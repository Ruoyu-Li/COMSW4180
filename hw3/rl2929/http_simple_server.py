#!/usr/bin/env python

# the following is a simple HTTP server in python. It does not support all http functionality 
# for example, the HEAD method is not supported.
# run as 
# python http_simple_server.py <port_number>
# example: python http_simple_server.py 9010
# if no port number is given, port 9000 is used
# a simpler example supporting only the GET method is available at https://www.acmesystems.it/python_http

import string,cgi,time,random,threading;
from os import curdir,sep;
from BaseHTTPServer import BaseHTTPRequestHandler, HTTPServer
import sys
import socket

class MyHandler(BaseHTTPRequestHandler):
   
   # GET - send 200 response indicating file type
   def do_GET(self):
      print("GET")
      print(self.path)
      args = self.path.split("?");
      try:
         # use index.html if no file name
         if(self.path == "/"):
            self.path = "index.html";
            # if html or txt file
            if(self.path.endswith(".html") or self.path.endswith(".txt")  ):
               f = open(curdir + sep + self.path);
               self.send_response(200);
               self.send_header('Content-type', 'text/html');
               self.send_header('Access-Control-Allow-Origin','*');
               self.end_headers();
               self.wfile.write(f.read()); 
               return;
            # if css
            elif(self.path.endswith(".css")):
               f = open(curdir + sep + self.path);
               self.send_response(200);
               self.send_header('Content-type', 'text/css');
               self.end_headers();
               self.wfile.write(f.read()); 
               return;
            # if javascript
            elif(self.path.endswith(".js") ):	
               f = open(curdir + sep + self.path);
               self.send_response(200);
               self.send_header('Content-type', 'text/js');
               self.send_header('Access-Control-Allow-Origin','*');
               self.end_headers();
               self.wfile.write(f.read()); 
               return;
            # if png image
            elif(self.path.endswith(".png") or self.path.endswith(".jpg") ):		
               f = open(curdir + sep + self.path,'rb');
               self.send_response(200);
               self.send_header('Content-type', 'image/png');
               self.end_headers();
               self.wfile.write(f.read()); 
               return;
            # if jpg image
            elif(self.path.endswith(".jpg") ):
               f = open(curdir + sep + self.path,'rb');
               self.send_response(200);
               self.send_header('Content-type', 'image/jpg');
               self.end_headers();
               self.wfile.write(f.read()); 
               return;
      # 404 error		
      except IOError:
         self.send_error(404, 'File Not Found: %s'%(self.path));
   # POST
   def do_POST(self):
      try:
         self.send_response(301);
         self.end_headers();
         self.wfile.write("POST OK");
      except :
         pass;
			
   # OPTIONS
   def do_OPTIONS(self):
      self.do_GET();

# main function
def main():
   try:
   # if no port number is provided on the command line, use 9000
      port = 9000;
      if len(sys.argv) > 1:
          port = int(sys.argv[1])
          server = HTTPServer((socket.gethostbyname(socket.gethostname()),port), MyHandler);
          print("Started HTTP Server")
          server.serve_forever();
   except KeyboardInterrupt:
      print('^C received, shutting down')
      server.socket.close();

if __name__ == '__main__':
    main();
		   
			
