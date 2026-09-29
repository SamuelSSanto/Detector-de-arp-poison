#!/usr/bin/env python3

import argparse
import subprocess
import sys
import time
import signal
import os
import threading
from collections import defaultdict
from scapy.all import ARP, Ether, sniff, sendp, get_if_list, conf
from colorama import Fore, Style, init

conf.verb = 0
init(autoreset=True)


# Verifica se está rodando no Mininet (OVS disponível) ou em Linux real
def detectar_ambiente():
    try:
        res = subprocess.run(
            ["ovs-vsctl", "list-br"],
            capture_output=True, text=True, timeout=3
        )
        if res.returncode == 0 and res.stdout.strip():
            return "mininet", res.stdout.strip().splitlines()
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass
    return "linux", []


# Descobre em qual bridge OVS a interface do IDS está conectada
def detectar_bridge_da_interface(interface, bridges):
    for bridge in bridges:
        try:
            res = subprocess.run(
                ["ovs-vsctl", "list-ports", bridge],
                capture_output=True, text=True
            )
            if interface in res.stdout.strip().splitlines():
                return bridge
        except Exception:
            pass
    return bridges[0] if bridges else None


# Tenta descobrir a interface de rede padrão automaticamente
def detectar_interface():
    try:
        res = subprocess.run(
            ["ip", "route", "get", "1.1.1.1"],
            capture_output=True, text=True
        )
        tokens = res.stdout.split()
        if "dev" in tokens:
            return tokens[tokens.index("dev") + 1]
    except Exception:
        pass
    for iface in get_if_list():
        if iface != "lo":
            return iface
    return None


# Bloqueia o MAC no OVS inserindo um flow de prioridade máxima com action=drop
def bloquear_ovs(bridge, mac_suspeito):
    try:
        subprocess.run(
            ["ovs-ofctl", "add-flow", bridge,
             f"priority=65535,dl_src={mac_suspeito},actions=drop"],
            check=True, capture_output=True
        )
        print(f"{Fore.GREEN}[NAC-OVS] Flow DROP inserido em '{bridge}' para {mac_suspeito}")
        return True
    except subprocess.CalledProcessError as e:
        print(f"{Fore.RED}[ERRO] ovs-ofctl falhou: {e}")
        return False


def desbloquear_ovs(bridge, mac_suspeito):
    try:
        subprocess.run(
            ["ovs-ofctl", "del-flows", bridge, f"dl_src={mac_suspeito}"],
            capture_output=True
        )
    except Exception:
        pass


# Bloqueia via ebtables (camada 2) em Linux real
def bloquear_ebtables(mac_suspeito):
    try:
        subprocess.run(["ebtables", "-A", "INPUT",   "--src", mac_suspeito, "-j", "DROP"], check=True, capture_output=True)
        subprocess.run(["ebtables", "-A", "FORWARD", "--src", mac_suspeito, "-j", "DROP"], check=True, capture_output=True)
        print(f"{Fore.GREEN}[NAC-EBT] Bloqueio ebtables para {mac_suspeito}")
        return True
    except (subprocess.CalledProcessError, FileNotFoundError):
        return False


def bloquear_arptables(mac_suspeito):
    try:
        subprocess.run(
            ["arptables", "-A", "INPUT", "--src-mac", mac_suspeito, "-j", "DROP"],
            check=True, capture_output=True
        )
        print(f"{Fore.GREEN}[NAC-ARP] Bloqueio arptables para {mac_suspeito}")
        return True
    except (subprocess.CalledProcessError, FileNotFoundError):
        return False


def desbloquear_ebtables(mac_suspeito):
    for cmd in [
        ["ebtables",  "-D", "INPUT",   "--src",     mac_suspeito, "-j", "DROP"],
        ["ebtables",  "-D", "FORWARD", "--src",     mac_suspeito, "-j", "DROP"],
        ["arptables", "-D", "INPUT",   "--src-mac", mac_suspeito, "-j", "DROP"],
    ]:
        try:
            subprocess.run(cmd, capture_output=True)
        except Exception:
            pass


class ARPDetector:
    def __init__(self, interfaces, auto_bloquear, tempo_aprendizado,
                 safe_macs=None, bridge=None, bridge_por_iface=None, debug=False):

        # Aceita tanto uma lista de interfaces (uso novo: múltiplos switches
        # espelhados para o mesmo processo) quanto uma string única (uso
        # original documentado no Capítulo 3 — mantido 100% compatível).
        if isinstance(interfaces, str):
            interfaces = [interfaces]
        self.interfaces        = interfaces
        self.interface         = interfaces[0]  # mantido para mensagens/compatibilidade
        self.auto_bloquear     = auto_bloquear
        self.tempo_aprendizado = tempo_aprendizado
        self.safe_macs         = set(m.lower() for m in (safe_macs or []))
        self.bridge            = bridge
        # Mapa {interface: bridge} usado para decidir, PACOTE A PACOTE, em
        # qual bridge aplicar o bloqueio — necessário quando o mesmo processo
        # escuta o espelhamento de MAIS DE UM switch simultaneamente (ver
        # Seção 5.3): cada interface corresponde ao espelho local de um
        # switch diferente, então o bloqueio precisa ir para a bridge certa,
        # não sempre para a mesma.
        self.bridge_por_iface  = dict(bridge_por_iface or {})
        self.debug             = debug
        self.inicio            = time.time()
        self.fase_aprendizado  = True
        self.tabela_confiavel  = {}   # IP -> MAC legítimo aprendido
        self.macs_bloqueados_map = {}  # MAC do atacante -> bridge onde foi bloqueado
        self.total_alertas     = 0
        self._contagem         = defaultdict(int)
        self.MIN_APARICOES     = 2    # confirmações antes de confiar num par IP/MAC
        self._lock             = threading.Lock()
        self._timer            = None

        self.ambiente, bridges_enc = detectar_ambiente()
        if self.ambiente == "mininet":
            for iface in self.interfaces:
                if iface not in self.bridge_por_iface:
                    detectada = self.bridge or detectar_bridge_da_interface(iface, bridges_enc)
                    if detectada:
                        self.bridge_por_iface[iface] = detectada
            if not self.bridge and self.interface in self.bridge_por_iface:
                self.bridge = self.bridge_por_iface[self.interface]

    def bridge_para_pacote(self, pkt):
        """Decide em qual bridge bloquear, com base em QUAL INTERFACE o
        pacote foi capturado (pkt.sniffed_on, preenchido pelo scapy quando
        sniff() escuta mais de uma interface). Cai para self.bridge se a
        interface não estiver mapeada (uso de interface única, modo
        original)."""
        iface_origem = getattr(pkt, "sniffed_on", None)
        return self.bridge_por_iface.get(iface_origem, self.bridge)

    # Reenvia ARPs legítimos para corrigir caches envenenados nos hosts
    def restaurar_rede(self):
        if not self.tabela_confiavel:
            return
        print(f"{Fore.CYAN}[HEAL] Enviando ARPs corretivos para {len(self.tabela_confiavel)} host(s)...")
        for ip, mac in self.tabela_confiavel.items():
            pkt = (
                Ether(src=mac, dst="ff:ff:ff:ff:ff:ff")
                / ARP(op=2, hwsrc=mac, psrc=ip, hwdst="ff:ff:ff:ff:ff:ff", pdst=ip)
            )
            for iface in self.interfaces:
                try:
                    sendp(pkt, iface=iface, count=5, inter=0.05, verbose=False)
                except Exception:
                    pass

    # Encerra a fase de aprendizado por TEMPO REAL (timer), e não por
    # "próximo pacote que chegar". Corrige o bug em que, se nenhum ARP
    # novo circula durante a janela de aprendizado (ex: cache já resolvido
    # por um pingAll anterior), a fase só terminava quando chegava o
    # PRIMEIRO pacote do ataque — fazendo o próprio ataque virar a
    # "linha de base confiável".
    def finalizar_aprendizado(self):
        with self._lock:
            if not self.fase_aprendizado:
                return
            self.fase_aprendizado = False
            print(f"\n{Fore.GREEN}[INFO] Aprendizado concluído. "
                  f"{len(self.tabela_confiavel)} host(s) mapeado(s). Monitorando...\n")
            for ip, mac in sorted(self.tabela_confiavel.items()):
                print(f"{Fore.BLUE}         {ip:>16}  ->  {mac}")
            print()

    def alertar(self, src_mac, src_ip, mac_real, bridge_alvo):
        self.total_alertas += 1
        print(f"\n{Fore.RED}{Style.BRIGHT}{'='*60}")
        print(f"  ALERTA #{self.total_alertas} — ARP SPOOFING DETECTADO")
        print(f"{'='*60}")
        print(f"  IP  falsificado : {src_ip}")
        print(f"  MAC legítimo    : {mac_real}")
        print(f"  MAC atacante    : {src_mac}  <-- FALSO")
        print(f"  Bridge alvo     : {bridge_alvo}")
        print(f"  Ambiente        : {self.ambiente.upper()}")
        print(f"{'='*60}{Style.RESET_ALL}\n")

    def bloquear(self, mac_suspeito, ip_falsificado, bridge_alvo=None):
        bridge_alvo = bridge_alvo or self.bridge

        if mac_suspeito.lower() in self.safe_macs:
            print(f"{Fore.YELLOW}[SKIP] {mac_suspeito} está na lista segura.")
            return

        # Ignora se esse MAC já foi alertado/bloqueado — evita spam no terminal
        if mac_suspeito in self.macs_bloqueados_map:
            return

        mac_real = self.tabela_confiavel.get(ip_falsificado, "?")
        self.alertar(mac_suspeito, ip_falsificado, mac_real, bridge_alvo)

        if not self.auto_bloquear:
            print(f"{Fore.YELLOW}[INFO] Modo passivo — use --nac para bloqueio automático.")
            self.macs_bloqueados_map[mac_suspeito] = bridge_alvo
            return

        print(f"{Fore.RED}[NAC] Bloqueando {mac_suspeito} na bridge {bridge_alvo} "
              f"(modo: {self.ambiente})...")

        bloqueado = False
        if self.ambiente == "mininet":
            if bridge_alvo:
                bloqueado = bloquear_ovs(bridge_alvo, mac_suspeito)
            else:
                print(f"{Fore.RED}[ERRO] Bridge não encontrada. Use --bridge ou --bridge-map.")
        else:
            bloqueado = bloquear_ebtables(mac_suspeito) or bloquear_arptables(mac_suspeito)
            if not bloqueado:
                print(f"{Fore.YELLOW}[AVISO] Nenhuma ferramenta de bloqueio disponível.")

        if bloqueado:
            self.macs_bloqueados_map[mac_suspeito] = bridge_alvo
            self.restaurar_rede()

    def processar_pacote(self, pkt):
        if not pkt.haslayer(ARP):
            return

        src_ip  = pkt[ARP].psrc
        src_mac = pkt[ARP].hwsrc.lower()
        op      = pkt[ARP].op

        if not src_ip or src_ip == "0.0.0.0":
            return

        if self.debug:
            tipo = "REQUEST" if op == 1 else "REPLY  "
            fase = "LEARN" if self.fase_aprendizado else "DETECT"
            print(f"{Fore.WHITE}[DBG-{fase}] ARP {tipo}  {src_ip:>16} -> {src_mac}")

        agora = time.time()
        bridge_alvo = self.bridge_para_pacote(pkt)

        with self._lock:
            if self.fase_aprendizado:
                if src_ip in self.tabela_confiavel:
                    mac_confiavel = self.tabela_confiavel[src_ip]
                    if src_mac != mac_confiavel:
                        # MAC diferente durante aprendizado — descarta e mantém o primeiro visto
                        print(f"\n{Fore.RED}[WARN] Conflito no aprendizado!")
                        print(f"       {src_ip}: registrado={mac_confiavel}, recebido={src_mac}")
                        print(f"       MAC {src_mac} DESCARTADO (mantém o primeiro visto).\n")
                    return

                # Só confia num par IP/MAC após MIN_APARICOES confirmações
                chave = (src_ip, src_mac)
                self._contagem[chave] += 1

                if self._contagem[chave] == 1:
                    print(f"{Fore.BLUE}[LEARN?] {src_ip:>16}  ->  {src_mac}  (aguardando confirmação...)")
                elif self._contagem[chave] >= self.MIN_APARICOES:
                    if src_ip not in self.tabela_confiavel:
                        self.tabela_confiavel[src_ip] = src_mac
                        print(f"{Fore.CYAN}[LEARN]  {src_ip:>16}  ->  {src_mac}  ✓")
                return

            # ── Fase de detecção ────────────────────────────────────────
            if src_ip in self.tabela_confiavel:
                mac_real = self.tabela_confiavel[src_ip]
                if src_mac != mac_real:
                    self.bloquear(src_mac, src_ip, bridge_alvo)
                return

            # IP nunca visto (nem no aprendizado, nem na detecção até agora).
            # ANTES: confiava de cara no primeiro pacote — se esse pacote
            # fosse forjado, o atacante virava a "verdade". AGORA: exige a
            # mesma confirmação (MIN_APARICOES) usada no aprendizado, e avisa
            # explicitamente que é um host pós-aprendizado (deve ser raro
            # numa rede industrial com hosts fixos).
            chave = (src_ip, src_mac)
            self._contagem[chave] += 1

            if self._contagem[chave] == 1:
                print(f"{Fore.YELLOW}[NEW?] {src_ip:>16}  ->  {src_mac}  "
                      f"(host não aprendido, aguardando confirmação...)")
            elif self._contagem[chave] >= self.MIN_APARICOES:
                if src_ip not in self.tabela_confiavel:
                    self.tabela_confiavel[src_ip] = src_mac
                    print(f"{Fore.YELLOW}[NEW]  Host confirmado após o aprendizado: "
                          f"{src_ip} -> {src_mac}")
                    print(f"{Fore.YELLOW}[AVISO] Host não estava na fase de aprendizado — "
                          f"verifique se essa entrada era esperada.")

    # Remove regras de bloqueio inseridas durante a sessão
    def encerrar(self):
        if self._timer:
            self._timer.cancel()
        print(f"\n{Fore.YELLOW}[EXIT] Encerrando IDS. Total de alertas: {self.total_alertas}")
        if self.macs_bloqueados_map:
            print(f"{Fore.YELLOW}[EXIT] Removendo {len(self.macs_bloqueados_map)} regra(s)...")
            for mac, bridge in self.macs_bloqueados_map.items():
                if self.ambiente == "mininet" and bridge:
                    desbloquear_ovs(bridge, mac)
                else:
                    desbloquear_ebtables(mac)
        print(f"{Fore.GREEN}[EXIT] Feito.")

    def iniciar(self):
        if os.geteuid() != 0:
            print(f"{Fore.RED}[ERRO] Execute como root: sudo python3 {sys.argv[0]}")
            sys.exit(1)

        metodo = (
            f"ovs-ofctl (bridge padrão: {self.bridge})"
            if self.ambiente == "mininet"
            else "ebtables / arptables"
        )

        print(f"\n{Fore.YELLOW}{'='*60}")
        print(f"  ARP IDS — Detector Híbrido de ARP Spoofing")
        print(f"{'='*60}")
        print(f"  Ambiente   : {self.ambiente.upper()}")
        print(f"  Interfaces : {', '.join(self.interfaces)}")
        if len(self.interfaces) > 1:
            print(f"  Mapa bridge: {self.bridge_por_iface}")
        print(f"  Modo NAC   : {'ATIVO (bloqueio automático)' if self.auto_bloquear else 'PASSIVO (só alertas)'}")
        print(f"  Método     : {metodo}")
        print(f"  Aprendizado: {self.tempo_aprendizado}s")
        print(f"  Confirmação: {self.MIN_APARICOES} pacotes por IP/MAC")
        print(f"  Debug      : {'ATIVO' if self.debug else 'inativo'}")
        if self.safe_macs:
            print(f"  MACs seguros: {', '.join(self.safe_macs)}")
        print(f"{'='*60}\n")

        print(f"{Fore.BLUE}[INFO] Fase de aprendizado iniciada ({self.tempo_aprendizado}s)...")

        for iface in self.interfaces:
            subprocess.run(
                ["ip", "link", "set", iface, "promisc", "on"],
                capture_output=True
            )

        # Timer independente de tráfego — garante que a fase de aprendizado
        # termina no tempo configurado mesmo que nenhum pacote ARP novo
        # chegue durante a janela (ex: caches já resolvidos por um pingAll
        # anterior à inicialização do detector).
        self._timer = threading.Timer(self.tempo_aprendizado, self.finalizar_aprendizado)
        self._timer.daemon = True
        self._timer.start()

        # scapy aceita uma lista de interfaces em iface= e preenche
        # pkt.sniffed_on com o nome de qual delas cada pacote veio — é assim
        # que um único processo consegue escutar o espelhamento local de
        # vários switches ao mesmo tempo e ainda saber onde bloquear cada um.
        sniff(
            iface=self.interfaces if len(self.interfaces) > 1 else self.interfaces[0],
            filter="arp",
            prn=self.processar_pacote,
            store=False
        )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Detector híbrido de ARP Spoofing (Mininet/OVS e Linux real)"
    )
    parser.add_argument("--iface",     "-i", type=str, nargs="+", default=None,
        help="Interface(s) de rede (ex: h7-eth0, ou h7-eth0 h7-eth1 h7-eth2 para "
             "escutar o espelhamento local de vários switches num só processo). "
             "Detecta automaticamente se omitido.")
    parser.add_argument("--nac",       action="store_true",
        help="Ativa bloqueio automático de atacantes.")
    parser.add_argument("--tempo",     "-t", type=int, default=15,
        help="Duração do aprendizado em segundos (padrão: 15).")
    parser.add_argument("--bridge",    "-b", type=str, default=None,
        help="Bridge OVS padrão (ex: s1). Usada quando --bridge-map não cobre "
             "a interface de origem do pacote, ou detectada automaticamente se omitida.")
    parser.add_argument("--bridge-map", nargs="*", default=[], metavar="IFACE:BRIDGE",
        help="Mapeamento interface->bridge para bloqueio quando --iface recebe "
             "mais de uma interface, ex: h7-eth0:s1 h7-eth1:s2 h7-eth2:s3. "
             "Interfaces não listadas caem no valor de --bridge (ou autodetecção).")
    parser.add_argument("--safe-macs", nargs="*", default=[], metavar="MAC",
        help="MACs que nunca serão bloqueados.")
    parser.add_argument("--debug",     action="store_true",
        help="Imprime cada pacote ARP recebido.")

    args = parser.parse_args()

    interfaces = args.iface or ([detectar_interface()] if detectar_interface() else None)
    if not interfaces or not interfaces[0]:
        print(f"{Fore.RED}[ERRO] Nenhuma interface encontrada. Use --iface.")
        sys.exit(1)

    bridge_map = {}
    for par in args.bridge_map:
        try:
            iface_nome, bridge_nome = par.split(":", 1)
            bridge_map[iface_nome] = bridge_nome
        except ValueError:
            print(f"{Fore.YELLOW}[AVISO] Formato inválido em --bridge-map: '{par}' "
                  f"(esperado IFACE:BRIDGE) — ignorado.")

    ids = ARPDetector(
        interfaces=interfaces,
        auto_bloquear=args.nac,
        tempo_aprendizado=args.tempo,
        safe_macs=args.safe_macs,
        bridge=args.bridge,
        bridge_por_iface=bridge_map,
        debug=args.debug,
    )

    def encerrar_graciosamente(sig, frame):
        ids.encerrar()
        sys.exit(0)

    signal.signal(signal.SIGINT,  encerrar_graciosamente)
    signal.signal(signal.SIGTERM, encerrar_graciosamente)

    ids.iniciar()
