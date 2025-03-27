import os
import subprocess
import sys
import re

class SimpleFirewall:
    def __init__(self):
        self.allowed_ports = set()
        self.blocked_ports = set()
        self.rules_file = "/etc/firewall_rules.txt"
        self._load_rules()

    def add_allow_rule(self, port):
        if self._validate_port(port):
            self.allowed_ports.add(port)
            self._apply_rules()
        else:
            print("Porta inválida. Insira um número entre 1 e 65535.")

    def add_block_rule(self, port):
        if self._validate_port(port):
            self.blocked_ports.add(port)
            self._apply_rules()
        else:
            print("Porta inválida. Insira um número entre 1 e 65535.")

    def _apply_rules(self):
        rules = ["*filter"]
        rules.append(":INPUT ACCEPT [0:0]")
        rules.append(":FORWARD ACCEPT [0:0]")
        rules.append(":OUTPUT ACCEPT [0:0]")
        
        # Proteção contra ataques DoS (SYN Flood)
        rules.append("-A INPUT -p tcp --syn -m limit --limit 1/s --limit-burst 3 -j ACCEPT")
        
        # Proteção contra Ping Flood
        rules.append("-A INPUT -p icmp --icmp-type echo-request -m limit --limit 1/s --limit-burst 1 -j ACCEPT")
        
        # Bloqueio de pacotes malformados
        rules.append("-A INPUT -p tcp --tcp-flags ALL NONE -j DROP")
        rules.append("-A INPUT -p tcp --tcp-flags ALL ALL -j DROP")
        
        # Bloquear tráfego de IPs reservados
        rules.append("-A INPUT -s 10.0.0.0/8 -j DROP")
        rules.append("-A INPUT -s 172.16.0.0/12 -j DROP")
        rules.append("-A INPUT -s 192.168.0.0/16 -j DROP")
        
        # Bloquear scanners de porta
        rules.append("-A INPUT -p tcp --tcp-flags SYN,ACK,FIN,RST RST -m limit --limit 1/s -j DROP")
        
        # Bloquear ataques de brute force SSH
        rules.append("-A INPUT -p tcp --dport 22 -m recent --set --name SSH")
        rules.append("-A INPUT -p tcp --dport 22 -m recent --update --seconds 60 --hitcount 4 --name SSH -j DROP")
        
        # Bloquear tráfego vindo da porta 0
        rules.append("-A INPUT -p tcp --sport 0 -j DROP")
        rules.append("-A INPUT -p udp --sport 0 -j DROP")
        
        # Proteção contra spoofing de localhost
        rules.append("-A INPUT -s 127.0.0.0/8 ! -i lo -j DROP")
        
        # Permitir conexões estabelecidas
        rules.append("-A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT")
        
        # Aplicar regras de permissão
        for port in self.allowed_ports:
            rules.append(f"-A INPUT -p tcp --dport {port} -j ACCEPT")
            rules.append(f"-A INPUT -p udp --dport {port} -j ACCEPT")
        
        # Aplicar regras de bloqueio
        for port in self.blocked_ports:
            rules.append(f"-A INPUT -p tcp --dport {port} -j DROP")
            rules.append(f"-A INPUT -p udp --dport {port} -j DROP")
        
        # Bloquear tudo o que não foi explicitamente permitido
        rules.append("-A INPUT -j DROP")
        rules.append("COMMIT")
        
        rules_str = "\n".join(rules)
        
        with open(self.rules_file, "w") as f:
            f.write(rules_str)
        
        subprocess.call(["iptables-restore", self.rules_file])
        print("Regras do firewall aplicadas com sucesso!")
        self._save_rules()

    def _validate_port(self, port):
        return re.match(r"^\d+$", str(port)) and 1 <= int(port) <= 65535
    
    def _save_rules(self):
        with open("/etc/firewall_saved_rules", "w") as f:
            subprocess.call(["iptables-save"], stdout=f)

    def _load_rules(self):
        if os.path.exists("/etc/firewall_saved_rules"):
            subprocess.call(["iptables-restore", "<", "/etc/firewall_saved_rules"], shell=True)
            print("Regras do firewall restauradas!")

def main():
    if os.geteuid() != 0:
        print("Este script deve ser executado como root!")
        sys.exit(1)
    
    firewall = SimpleFirewall()

    while True:
        print("\n1. Permitir porta")
        print("2. Bloquear porta")
        print("3. Sair")
        choice = input("Escolha uma opção: ")

        if choice == '1':
            port = input("Digite a porta para permitir: ")
            firewall.add_allow_rule(port)
        elif choice == '2':
            port = input("Digite a porta para bloquear: ")
            firewall.add_block_rule(port)
        elif choice == '3':
            print("Saindo...")
            break
        else:
            print("Opção inválida.")

if __name__ == "__main__":
    main()
