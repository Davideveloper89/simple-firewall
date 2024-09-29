import os
import subprocess
import sys

class SimpleFirewall:
    def __init__(self):
        self.allowed_ports = []
        self.blocked_ports = []

    def add_allow_rule(self, port):
        self.allowed_ports.append(port)
        self._apply_rules()

    def add_block_rule(self, port):
        self.blocked_ports.append(port)
        self._apply_rules()

    def _apply_rules(self):
        # Limpa as regras existentes
        subprocess.call(['iptables', '-F'])

        # Adiciona regras de permitir
        for port in self.allowed_ports:
            subprocess.call(['iptables', '-A', 'INPUT', '-p', 'tcp', '--dport', str(port), '-j', 'ACCEPT'])
            subprocess.call(['iptables', '-A', 'INPUT', '-p', 'udp', '--dport', str(port), '-j', 'ACCEPT'])

        # Adiciona regras de bloquear
        for port in self.blocked_ports:
            subprocess.call(['iptables', '-A', 'INPUT', '-p', 'tcp', '--dport', str(port), '-j', 'DROP'])
            subprocess.call(['iptables', '-A', 'INPUT', '-p', 'udp', '--dport', str(port), '-j', 'DROP'])

        # Permite tráfego já estabelecido
        subprocess.call(['iptables', '-A', 'INPUT', '-m', 'state', '--state', 'ESTABLISHED,RELATED', '-j', 'ACCEPT'])

        # Bloqueia todo o resto
        subprocess.call(['iptables', '-A', 'INPUT', '-j', 'DROP'])

def main():
    firewall = SimpleFirewall()

    while True:
        print("1. Permitir porta")
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

