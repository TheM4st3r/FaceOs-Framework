#!/usr/bin/python

try:
	import webbrowser
	import requests
	import socket
	import platform
	import re
	import sys
	import os

	def faceosframework():

			banner = """
			$$$$$$$$\         $$$$$$\  $$$$$$$$\ 
			$$  _____|       $$  __$$\ $$  _____|
			$$ |    $$$$$$$\ $$ /  \__|$$ |      
			$$$$$\ $$  _____|\$$$$$$\  $$$$$\    
			$$  __|$$ /       \____$$\ $$  __|   
			$$ |   $$ |      $$\   $$ |$$ |      
			$$ |   \$$$$$$$\ \$$$$$$  |$$ |      
			\__|    \_______| \______/ \__|      
                                     
            Information Gathering Framework
            Desenvolvido por Derick Santos                       
                                     
							"""
			print(banner)

			options = (str(raw_input("FcSF: ")))

			if options == "show modules":
				fun = """
						  ==================================================================
						  ===     FaceOs Framework - Information Gathering Tool Main     ===
						  ===															 ===
						  ===															 ===
						  === FcSF: dork - Funcao para busca de dorks no google          ===
						  === FcSF: mail - Funcao para busca de emails 					 ===
						  === FcSF: dir - Funcao para busca de diretorios                ===
						  === FcSF: os - Funcao para detectar o Sistema Operacional      ===
						  === FcSF: port - Escanear portas 								 ===
						  ===             											     ===
						  ===                                                            ===
						  ================================================================== """
				print(fun)

			if options == "dork":
				web = "https://www.google.com/search?q="
				dork = raw_input("Dork: ")
				sr = (web+dork)
				print "Target => %s"%sr
				r = requests.get(web)
			
				if r.status_code == 200:
					print "//! - Abrindo site..."
					w = webbrowser.open(web+dork)
				else:
					print "//* - Url invalida!"

			if options == "mail":
				web = (str(raw_input("Site: ")))

				print "Target => %s"%web
				r = requests.get("http://"+web)
				html = r.text
				email = re.findall(r'[\w_]+[\w.]+[\w-]@[\w_]+[\w.]+[\w-]', html)
				for m in email:
					print "//$ - E-mails => %s"%m

			if options == "dir":
				web = raw_input("Site: ")
				abrir = open("lista.txt","r");

				while True:
					ls = abrir.readline()
					r = requests.get("http://"+web)

					if r.status_code == 200:
						link = ("http://"+web+"/"+ls)
						r3 = requests.get(link)
						
						if r3.status_code == 200:
							print "\n//$ - Diretorio valido:"
						else:
							print "\n//$ - Diretorio invalido:"

						print link
					else:
						print "Url invalida!"
			if options == "so":
				ip = raw_input("Ip: ")
				sis = platform.system()

				if sis == "Windows":
					ping = "ping "+ip
					
					rj = "".join(os.popen(ping).readlines())
					
					if re.search("TTL=64", rj):
						print "//$ - Sistema Operacional => Linux"
					if re.search("TTL=128", rj):
						print "//$ - Sistema Operacional => Windows"
				else:
					ping = "ping -c4 "+ip
					
					r = "".join(os.popen(ping).readlines())
					
					if re.search("TTL=64", rj):
						print "//$ - Sistema Operacional => Linux"
					if re.search("TTL=128", rj):
						print "//$ - Sistema Operacional => Windows"

			if options == "port":
				host = raw_input("Site: ")
				s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
				ip = socket.gethostbyname(host)

				for port in range(1,3306):
					sc = s.connect_ex((ip,port))
					if sc == 0:
						print "//$ - Porta aberta => %s"%port
					else:
						print "//$ - Porta fechada => %s"%port
					s.close

	faceosframework()
except KeyboardInterrupt: 
	print("\nFcSF - By Derick Santos")