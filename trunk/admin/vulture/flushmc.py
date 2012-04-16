import socket as S
class Client:
	def __init__(self,host,port):
		self.con = S.socket(S.AF_INET,S.SOCK_STREAM)
		self.con.connect((host,port))
		
	def delete(self,key):
		self.con.send("delete "+key+"\r\n")
	
	def close(self):
		self.con.close()

