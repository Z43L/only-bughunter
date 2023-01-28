from bs4 import BeautifulSoup
import dns.zone
import dns.resolver as resolver
import socket
import argparse
import requests
import whois
import termcolor
import shodan
import os
import time


parse = argparse.ArgumentParser(description="herramienta echa para bughunters")
parse.add_argument("-d", "--domain", help="dominio a investigar", required=True)
parse.add_argument("-i","--ip", help="descubrir ip", action="store_true")
parse.add_argument("-s","--subdomain", help="escanear subdominios", action="store_true")
parse.add_argument("-t", "--timeout", help="tiempo de espera", type=int, default=10)
parse.add_argument("-W","--wayback", help="usar wayback machine", action="store_true")
parse.add_argument("-w","--whois", help="usar whois", action="store_true")
parse.add_argument("-A","--all", help="todas las opciones")
parse.add_argument("-dns","--dns",help="dns info")
parse.add_argument("-te","--tecnologia", help="tecnologia", action="store_true")
parse.add_argument("-sh", "--shodan", help="shodan", action="store_true")
parse.add_argument("-as", "--activesubdomain", help="activesubdomain", action="store_true") 
parse.add_argument("filename",metavar="archivo",type=str, help="nombre del archivo")
args = parse.parse_args()



#obtener ip
def obtener_ip(domain):
    try:
        ip = socket.gethostbyname(domain)
        print(termcolor.colored("[+] la ip es >>>> "+ ip, "green"))
    except socket.gaierror as e:
        if e.errno == socket.EAI_NONAME:
            raise ValueError("El nombre de dominio no es válido")
        else:
            raise
    finally:
        socket.close(0)
#obtener informacion del dns
def obtener_dns(domain):
    try:
        print("[+] Obteniendo la informacion del dns...")
        dnso =resolver.query(domain, "SOA")
        if dnso:
            print("[+] la informacion del dns es >>>> ")
            for data in dnso:
                print(data)
            return dnso
        else:
            print("[-] No se pudo obtener la informacion del dns")
    except:
        print("[-] No se pudo obtener la informacion del dns")
        return None



#enumeracion activa de subdominios
      
def enumerar_subdominios(domain):
  

  subdominios = []

  for subdominio in subdominios:
    try:
        answers = dns.resolver.query(subdominio + "." + domain, "A")
        for rdata in answers:
            print(subdominio + "." + domain, "tiene la dirección IP", rdata.address)
        time.sleep(5)
    except:
        pass







#obtener informacion de tecnologias
def tecnologias(domain):
   url ="https://"+domain+"/api/v1/ip-info"
   try:
     response = requests.get(url)
     headers = response.headers

     print("Server:", headers.get("Server"))
     print("Language:", headers.get("Content-Language"))

   except:
     print("[-] No se pudo obtener la informacion de tecnologias")
     return None

  
#whois
def obtener_whois(domain):
  try:
      print("[+] Obteniendo informacion ...")
      info = whois.whois(domain)

      print(termcolor.colored("Información sobre " + domain, "green"))
      print("------------------------------")
      print(termcolor.colored("Registrador:", "green"), info.registrar)
      print(termcolor.colored("Fecha de vencimiento:", "green"), info.expiration_date)
      print(termcolor.colored("Nombre de domicilio:", "green"), info.domain_name)
      print(termcolor.colored("Dirección IP:", "green"), info.ip_address)
      print(termcolor.colored("Dirección Pública:", "green"), info.public_domain)
      print(termcolor.colored("Emails:", "green"), info.emails)
      print(termcolor.colored("Name server:", "green"), info.nameservers)
      print(termcolor.colored("TLD:", "green"), info.tld)
      print(termcolor.colored("Registro de dominios:", "green"), info.registrant_name)
      print(termcolor.colored("Status:", "green"), info.status)
  except Exception as e:
      print(termcolor.colored("Error: " + str(e), "red"))



  

#subdominios pasivo
def find_subdomains(url):
    subdomains = []
    page = requests.get(url)
    soup = BeautifulSoup(page.content, 'html.parser')
    for link in soup.find_all('a'):
        href = link.get('href')
        if href.startswith('http'):
            subdomain = href.split('.')[0]
            if subdomain not in subdomains:
                subdomains.append(subdomain)
    return subdomains





def get_api_key_from_user():
    """
    Obtiene la clave de API de Shodan de un archivo de configuración o directamente del usuario
    """
    api_key = None
    config_file = os.path.expanduser("~/.shodan")

    # Verifica si el archivo de configuración existe
    if os.path.exists(config_file):
        # Lee la clave de API del archivo
        with open(config_file, "r") as f:
            api_key = f.read().strip()
    else:
        # Pide la clave de API al usuario
        api_key = input("Ingrese su clave de API de Shodan: ")

        # Guarda la clave de API en el archivo de configuración
        with open(config_file, "w") as f:
            f.write(api_key)

    return api_key


  
#busqueda shodan
def shodan_search(domain,api_key):
  try:
      print("[+] Busqueda en shodan...")
      
      api = shodan.Shodan(api_key)

        # Realizar una búsqueda
      results = api.search(domain)
    
        # Mostrar los resultados
      for result in results['matches']:
          print(f'IP: {result["ip_str"]}')
          print(f'Puerto: {result["port"]}')
          print(f'Organización: {result["org"]}')
         
         
           
        
  
 
  except shodan.APIError as e: 
    print(f'Error: {e}')

def banner():
  print("""
 ____  _      _    ___  _                               
/  _ \/ \  /|/ \   \  \//                               
| / \|| |\ ||| |    \  /                                
| \_/|| | \||| |_/\ / /                                 
\____/\_/  \|\____//_/                                  
                                                        
 ____  _     _____ _     _     _      _____  _____ ____ 
/  __\/ \ /\/  __// \ /|/ \ /\/ \  /|/__ __\/  __//  __\
| | //| | ||| |  _| |_||| | ||| |\ ||  / \  |  \  |  \/|
| |_\\| \_/|| |_//| | ||| \_/|| | \||  | |  |  /_ |    /
\____/\____/\____\\_/ \|\____/\_/  \|  \_/  \____\\_/\_\
                                                        """)

  


#inicio aplicacion
def main(args):
  banner()
  api_key = "GENHLluTRCbrNPRias6DI06xGZ0L3VYJ"

  get_api_key_from_user()
  domain = args.domain
  url = "http://"+domain
  print("[+] Iniciando aplicacion...")
  if args.domain:
    
    if args.ip:
      obtener_ip(domain)
    
      
    if args.whois:
      obtener_whois(domain)
    

    
    if args.tecnologia:
        tecnologias(domain)
    

    if args.subdomain:
      subdomains = find_subdomains(url)
      print(termcolor.colored("[+] Obteniendo informacion de subdominios...","red"))
      for ssubdomain in subdomains:
        print(termcolor.colored("[+] Subdominio: ", "green") + ssubdomain)




  
      
    if args.dns:
      obtener_dns(domain)
    

    if args.shodan:
        shodan_search(domain,api_key)
   
    if args.activesubdomain:
        try:
            url="https://"+domain
            with open(args.filename, "r") as f:
                for line in f:
                    domain = line.strip()
              #print(termcolor.colored("[+] Obteniendo informacion de subdominios...","red"))
                    subdomains = find_subdomains(url)
                    for ssubdomain in subdomains:
                        print(termcolor.colored("[+] Subdominio: ", "green") + ssubdomain)
        except KeyboardInterrupt:
             print("Ctrl+C pressed, exiting program...") 

#print(termcolor.colored("[+] Obteniendo informacion de dominios...","red"))
#   
#          domains = find_
#      subdominios = diccionario
#
#      for subdominio in subdominios:
#        try:
#          answers = dns.resolver.query(subdominio + "." + domain, "A")
#          for rdata in answers:
#            print(subdominio + "." + domain, "tiene la dirección IP", rdata.address)
#          time.sleep(5)
#        except:
#          pass








  


      
if __name__ == "__main__":
  main(args)

















