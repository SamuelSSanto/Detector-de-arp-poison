#!/usr/bin/env python3
# Testes experimentais - detecção de ARP Poisoning em redes industriais
# TCC - FEMEC/UFU
#
# Como rodar: deixar este arquivo na mesma pasta do arp_detector_arrumado.py e
#   sudo python3 testes_experimentais_passf.py
# O resultado vai sendo salvo em resultados_experimentos_pass.txt.
#
# Os switches são bridges Linux (iproute2), sem OVS nem controlador.
# O h7 (IDS) tem um link só, ligado ao s1. Cada switch espelha suas portas
# (tc mirred) para uma porta sX-spn que marca a cópia com uma VLAN
# (101/102/103). As cópias chegam ao s1 por s1-rx1/2/3 e são redirecionadas
# pro h7. O detector usa a tag (--vlan-map) pra saber de qual switch veio
# cada ARP.
#
# Configuração atual = teste rápido (1 repetição, só s1, sem --nac).
# Pro teste completo: CENARIOS = ["s1", "s2", "s3"], REPETICOES_POR_CENARIO = 5,
# MEDICOES_OVERHEAD = 3 e colocar "--nac" em iniciar_detector_unico().

import os
import re
import sys
import shutil
import time
import datetime
import statistics

from mininet.net import Mininet
from mininet.node import Switch
from mininet.link import TCLink
from mininet.log import setLogLevel

# ============================================================================
# Configuração
# ============================================================================
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
DETECTOR_PATH = os.path.join(SCRIPT_DIR, "arp_detector_arrumado.py")
RESULTS_DIR = SCRIPT_DIR

APRENDIZADO_SEG = 15
MARGEM_APRENDIZADO_SEG = 5
ATAQUE_DURACAO_SEG = 6
PAUSA_ENTRE_RODADAS_SEG = 3

# (host atacante, IP vítima 1, IP vítima 2) - um atacante diferente por rodada
PARES_ATAQUE = [
    ("h8",  "10.0.0.1", "10.0.0.2"),   # PLC1 <-> PLC2, ambos em s2
    ("h10", "10.0.0.4", "10.0.0.5"),   # Sensor1 <-> Sensor2, ambos em s3
    ("h11", "10.0.0.3", "10.0.0.6"),   # IHM <-> SCADA, segmentos diferentes
    ("h12", "10.0.0.1", "10.0.0.6"),   # PLC1 <-> SCADA, segmentos diferentes
]
RODADAS_DETECCAO = len(PARES_ATAQUE)
RODADAS_FALSO_POSITIVO = 3     # host conhecido (h3) voltando a falar
RODADAS_HOST_NOVO = 3          # host que só aparece depois do aprendizado (h9)

# VLAN de cada switch e par de portas do link de espelho (saída, entrada no s1)
VLAN_POR_SWITCH = {"s1": 101, "s2": 102, "s3": 103}
PAR_ESPELHO = {
    "s1": ("s1-spn", "s1-rx1"),
    "s2": ("s2-spn", "s1-rx2"),
    "s3": ("s3-spn", "s1-rx3"),
}

CENARIOS = ["s1"]
REPETICOES_POR_CENARIO = 1

PING_COUNT = 50
IPERF_DURACAO = 10
MEDICOES_OVERHEAD = 1

os.makedirs(RESULTS_DIR, exist_ok=True)
RESULTS_TXT = os.path.join(RESULTS_DIR, "resultados_experimentos_pass.txt")
TMP_DIR = "/tmp/tcc_testes"

# ============================================================================
# Log
# ============================================================================
_log_file_handle = None


def log(msg=""):
    print(msg)
    if _log_file_handle:
        _log_file_handle.write(str(msg) + "\n")
        _log_file_handle.flush()


def secao(titulo):
    log("")
    log("=" * 78)
    log(f" {titulo}")
    log("=" * 78)


def subsecao(titulo):
    log("")
    log("-" * 78)
    log(f" {titulo}")
    log("-" * 78)


# ============================================================================
# Topologia
# ============================================================================
def corrigir_r2q_htb(iface):
    out = os.popen(f"tc qdisc show dev {iface} 2>/dev/null").read()
    if "htb" in out:
        os.system(f"tc qdisc change dev {iface} root handle 1: htb r2q 100 2>/dev/null || true")


class LinuxBridgeIP(Switch):
    """Switch feito com bridge Linux (iproute2). STP desligado, a topologia não tem laço."""

    def __init__(self, name, **params):
        params.pop("failMode", None)    # parâmetro do OVS, não serve aqui
        Switch.__init__(self, name, **params)

    def start(self, controllers):
        self.cmd(f"ip link set {self.name} down 2>/dev/null")
        self.cmd(f"ip link del {self.name} 2>/dev/null")
        self.cmd(f"ip link add name {self.name} type bridge")
        self.cmd(f"ip link set {self.name} type bridge stp_state 0 2>/dev/null")
        self.cmd(f"sysctl -w net.ipv6.conf.{self.name}.disable_ipv6=1 2>/dev/null")
        for intf in self.intfList():
            if intf.name == "lo":
                continue
            self.cmd(f"ip link set {intf.name} master {self.name}")
            self.cmd(f"ip link set {intf.name} up")
        self.cmd(f"ip link set {self.name} up")

    def stop(self, deleteIntfs=True):
        self.cmd(f"ip link set {self.name} down 2>/dev/null")
        self.cmd(f"ip link del {self.name} 2>/dev/null")
        Switch.stop(self, deleteIntfs)

    def connected(self):
        return True


def preparar_ambiente():
    # módulos do kernel usados no espelhamento e desligar o netfilter na bridge
    for mod in ("bridge", "sch_ingress", "act_mirred", "act_vlan", "cls_matchall", "cls_u32", "veth"):
        os.system(f"modprobe {mod} 2>/dev/null")
    for chave in ("bridge-nf-call-iptables", "bridge-nf-call-ip6tables",
                  "bridge-nf-call-arptables"):
        os.system(f"sysctl -w net.bridge.{chave}=0 > /dev/null 2>&1")


def portas_do_bridge(bridge):
    try:
        nomes = os.listdir(f"/sys/class/net/{bridge}/brif")
    except OSError:
        return []

    def chave(nome):
        return [int(t) if t.isdigit() else t for t in re.split(r"(\d+)", nome)]
    return sorted(nomes, key=chave)


def _tc_matchall(dev, direcao, acao):
    # tenta matchall; se o kernel não tiver, usa u32 que casa tudo
    base = f"tc filter add dev {dev} {direcao} protocol all prio 1"
    if os.system(f"{base} matchall {acao} 2>/dev/null") == 0:
        return True
    return os.system(f"{base} u32 match u32 0 0 {acao} 2>/dev/null") == 0


def _filtro_contem(dev, direcao, *trechos):
    out = os.popen(f"tc filter show dev {dev} {direcao} 2>/dev/null").read().lower()
    return all(t.lower() in out for t in trechos)


def configurar_espelho(bridge, porta_saida, portas_monitorar):
    # espelha o ingress de cada porta, assim todo quadro que passa pela
    # bridge é copiado uma vez só
    if not portas_monitorar:
        log(f"[AVISO] Nenhuma porta para monitorar em {bridge}")
        return False
    ok = True
    for porta in portas_monitorar:
        os.system(f"tc qdisc del dev {porta} clsact 2>/dev/null")
        if os.system(f"tc qdisc add dev {porta} clsact 2>/dev/null") != 0:
            log(f"[ERRO] Não consegui criar qdisc clsact em {porta}")
            ok = False
            continue
        if (not _tc_matchall(porta, "ingress",
                             f"action mirred egress mirror dev {porta_saida}")
                or not _filtro_contem(porta, "ingress", "mirred", porta_saida)):
            log(f"[ERRO] Espelho não instalado em {porta} -> {porta_saida}")
            ok = False
    return ok


def remover_pares_espelho():
    # apagar uma ponta do veth apaga a outra
    for saida, _ in PAR_ESPELHO.values():
        os.system(f"ip link del {saida} 2>/dev/null")


def criar_caminho_espelho(porta_h7_s1):
    # um par veth por switch: sX-spn coloca a VLAN (no egress, só na cópia)
    # e s1-rxN redireciona tudo pra porta do h7 no s1
    ok = True
    for sw, (saida, entrada) in PAR_ESPELHO.items():
        vlan = VLAN_POR_SWITCH[sw]
        os.system(f"ip link del {saida} 2>/dev/null")
        if os.system(f"ip link add {saida} type veth peer name {entrada}") != 0:
            log(f"[ERRO] Não consegui criar o link de espelho {saida}<->{entrada}")
            ok = False
            continue
        for dev in (saida, entrada):
            os.system(f"sysctl -w net.ipv6.conf.{dev}.disable_ipv6=1 > /dev/null 2>&1")
            os.system(f"ip link set {dev} up")
        os.system(f"tc qdisc add dev {saida} clsact 2>/dev/null")
        os.system(f"tc qdisc add dev {entrada} clsact 2>/dev/null")
        if (not _tc_matchall(saida, "egress", f"action vlan push id {vlan}")
                or not _filtro_contem(saida, "egress", "vlan", str(vlan))):
            log(f"[ERRO] Não consegui instalar o push da VLAN {vlan} em {saida}")
            ok = False
        if (not _tc_matchall(entrada, "ingress",
                             f"action mirred egress redirect dev {porta_h7_s1}")
                or not _filtro_contem(entrada, "ingress", "mirred", porta_h7_s1)):
            log(f"[ERRO] Não consegui instalar o redirect {entrada} -> {porta_h7_s1}")
            ok = False
        log(f"[TOPO] Espelho {sw}: {saida} (push VLAN {vlan}) -> {entrada} -> {porta_h7_s1}")
    return ok


def hosts_exceto(net, excluir):
    return [h for h in net.hosts if h.name not in excluir]


def montar_topologia(switch_atacante):
    """Monta a rede com os atacantes ligados ao switch indicado. h7 é o IDS
    (um link só, no s1) e h9 é o host novo, que fica quieto até o teste dele.
    Retorna (net, interface_do_h7)."""
    log(f"[TOPO] Criando rede com atacante (h8) ligado a {switch_atacante}...")

    net = Mininet(switch=LinuxBridgeIP, link=TCLink, autoSetMacs=True,
                  controller=None)

    s1 = net.addSwitch("s1")
    s2 = net.addSwitch("s2")
    s3 = net.addSwitch("s3")

    h1 = net.addHost("h1", ip="10.0.0.1/24", mac="00:00:00:00:00:01")
    h2 = net.addHost("h2", ip="10.0.0.2/24", mac="00:00:00:00:00:02")
    h3 = net.addHost("h3", ip="10.0.0.3/24", mac="00:00:00:00:00:03")
    h4 = net.addHost("h4", ip="10.0.0.4/24", mac="00:00:00:00:00:04")
    h5 = net.addHost("h5", ip="10.0.0.5/24", mac="00:00:00:00:00:05")
    h6 = net.addHost("h6", ip="10.0.0.6/24", mac="00:00:00:00:00:06")
    h7 = net.addHost("h7", ip="10.0.0.7/24", mac="00:00:00:00:00:07")
    h8 = net.addHost("h8", ip="10.0.0.8/24", mac="00:00:00:00:00:08")
    h9 = net.addHost("h9", ip="10.0.0.9/24", mac="00:00:00:00:00:09")
    h10 = net.addHost("h10", ip="10.0.0.10/24", mac="00:00:00:00:00:0a")
    h11 = net.addHost("h11", ip="10.0.0.11/24", mac="00:00:00:00:00:0b")
    h12 = net.addHost("h12", ip="10.0.0.12/24", mac="00:00:00:00:00:0c")

    net.addLink(s1, s2, bw=100, delay="1ms", max_queue_size=1000)
    net.addLink(s1, s3, bw=100, delay="1ms", max_queue_size=1000)
    net.addLink(h1, s2, bw=10, delay="2ms", max_queue_size=1000)
    net.addLink(h2, s2, bw=10, delay="2ms", max_queue_size=1000)
    net.addLink(h3, s2, bw=10, delay="2ms", max_queue_size=1000)
    net.addLink(h4, s3, bw=10, delay="2ms", max_queue_size=1000)
    net.addLink(h5, s3, bw=10, delay="2ms", max_queue_size=1000)
    net.addLink(h6, s3, bw=10, delay="2ms", max_queue_size=1000)

    switch_obj = {"s1": s1, "s2": s2, "s3": s3}[switch_atacante]
    net.addLink(h8, switch_obj, bw=10, delay="2ms", max_queue_size=1000)
    net.addLink(h10, switch_obj, bw=10, delay="2ms", max_queue_size=1000)
    net.addLink(h11, switch_obj, bw=10, delay="2ms", max_queue_size=1000)
    net.addLink(h12, switch_obj, bw=10, delay="2ms", max_queue_size=1000)

    # link do IDS com banda folgada, porque leva o espelho dos três switches
    link_h7_s1 = net.addLink(h7, s1, bw=100, delay="1ms", max_queue_size=1000)
    net.addLink(h9, s1, bw=10, delay="2ms", max_queue_size=1000)

    net.start()
    time.sleep(2)

    for iface in ["s1-eth1", "s1-eth2", "s2-eth1", "s3-eth1"]:
        corrigir_r2q_htb(iface)
    for host in [h1, h2, h3, h4, h5, h6, h7, h8, h9, h10, h11, h12]:
        host.cmd("sysctl -w net.ipv6.conf.all.disable_ipv6=1 2>/dev/null")

    time.sleep(1)

    porta_h7 = link_h7_s1.intf2.name     # porta do h7 no lado do switch
    iface_h7 = link_h7_s1.intf1.name     # interface do h7 (h7-eth0)
    try:
        if porta_h7 not in portas_do_bridge("s1"):
            raise RuntimeError(f"porta {porta_h7} do h7 não está na bridge s1")
        if not criar_caminho_espelho(porta_h7):
            raise RuntimeError("falha ao criar o caminho de espelhamento (VLAN)")
        for bridge in ("s1", "s2", "s3"):
            monitorar = [p for p in portas_do_bridge(bridge) if p != porta_h7]
            log(f"[TOPO] Espelho em {bridge}: saída={PAR_ESPELHO[bridge][0]}  "
                f"monitorando={monitorar}")
            if not configurar_espelho(bridge, PAR_ESPELHO[bridge][0], monitorar):
                raise RuntimeError(f"falha ao configurar o espelhamento em {bridge}")
    except Exception:
        try:
            net.stop()
        except Exception:
            pass
        remover_pares_espelho()
        raise
    time.sleep(1)

    # warm-up de ARP em todo mundo, menos h9 (ele precisa ser desconhecido)
    log("[TOPO] Testando conectividade inicial (warm-up de ARP, exceto h9)...")
    net.ping(hosts=hosts_exceto(net, ["h9", "h7"]), timeout="1")

    return net, iface_h7


# ============================================================================
# Medições de overhead
# ============================================================================
def _extrair_latencia_media(ping_output):
    m = re.search(r"= [\d.]+/([\d.]+)/[\d.]+", ping_output)
    return float(m.group(1)) if m else None


def _extrair_banda(iperf_output):
    m = re.search(r"([\d.]+)\s*Mbits/sec", iperf_output)
    return float(m.group(1)) if m else None


def _tamanho_arquivo(caminho):
    try:
        return os.path.getsize(caminho)
    except OSError:
        return 0


def medir_overhead(h_origem, h_destino, rotulo):
    """Mede latência (ping) e banda (iperf) MEDICOES_OVERHEAD vezes e
    devolve a média de cada uma."""
    latencias, bandas = [], []
    for i in range(MEDICOES_OVERHEAD):
        ping_out = h_origem.cmd(f"ping -c {PING_COUNT} -i 0.05 {h_destino.IP()}")
        lat = _extrair_latencia_media(ping_out)
        if lat is not None:
            latencias.append(lat)

        h_destino.cmd("iperf -s -p 5001 &")
        time.sleep(1)
        iperf_out = h_origem.cmd(f"iperf -c {h_destino.IP()} -p 5001 -t {IPERF_DURACAO}")
        bw = _extrair_banda(iperf_out)
        if bw is not None:
            bandas.append(bw)
        h_destino.cmd("kill %iperf 2>/dev/null")
        time.sleep(1)

        log(f"  [{rotulo}] medição {i+1}/{MEDICOES_OVERHEAD}: "
            f"latência={lat if lat is not None else 'N/D'} ms, "
            f"banda={bw if bw is not None else 'N/D'} Mbps")

    media_lat = statistics.mean(latencias) if latencias else None
    media_bw = statistics.mean(bandas) if bandas else None
    return media_lat, media_bw


# ============================================================================
# Detector
# ============================================================================
def iniciar_detector_unico(h7, iface_h7, tag):
    # um detector só no h7, que lê a tag VLAN pra saber de qual switch veio o ARP
    # (sem --nac = modo passivo, só alerta)
    caminho = os.path.join(TMP_DIR, f"detector_{tag}.log")
    h7.cmd(f"rm -f {caminho}")

    vlan_map_str = " ".join(f"{v}:{sw}" for sw, v in VLAN_POR_SWITCH.items())
    h7.cmd(
        f"python3 -u {DETECTOR_PATH} --iface {iface_h7} "
        f"--bridge-map {iface_h7}:s1 "
        f"--vlan-map {vlan_map_str} "
        f"--tempo {APRENDIZADO_SEG} > {caminho} 2>&1 &"
    )
    return caminho


def _ler_trecho(caminho, pos_inicio=0):
    try:
        with open(caminho) as fh:
            fh.seek(pos_inicio)
            return fh.read()
    except OSError:
        return ""


# ============================================================================
# Um cenário completo
# ============================================================================
def rodar_cenario(switch_atacante, execucao_idx):
    resultado = {
        "cenario": switch_atacante,
        "execucao": execucao_idx,
        "deteccoes": 0,
        "rodadas_ataque": RODADAS_DETECCAO,
        "falsos_positivos": 0,
        "rodadas_fp": RODADAS_FALSO_POSITIVO,
        "host_novo_alertas": 0,
        "host_novo_aceito": False,
        "latencia_baseline_ms": None,
        "latencia_com_ids_ms": None,
        "banda_baseline_mbps": None,
        "banda_com_ids_mbps": None,
        "erros": [],
    }

    os.makedirs(TMP_DIR, exist_ok=True)
    tag = f"{switch_atacante}_{execucao_idx}"

    net = None
    try:
        net, iface_h7 = montar_topologia(switch_atacante)
        h7 = net.get("h7")
        h1 = net.get("h1")
        h2 = net.get("h2")
        h9 = net.get("h9")

        # 1) overhead sem o detector
        subsecao(f"[{switch_atacante} #{execucao_idx}] Overhead BASELINE "
                 f"({MEDICOES_OVERHEAD}x, {PING_COUNT} pacotes, {IPERF_DURACAO}s)")
        lat_base, bw_base = medir_overhead(h1, h2, "baseline")
        resultado["latencia_baseline_ms"] = lat_base
        resultado["banda_baseline_mbps"] = bw_base

        # 2) sobe o detector e gera ARP legítimo durante o aprendizado
        subsecao(f"[{switch_atacante} #{execucao_idx}] Iniciando detector único "
                 f"(espelho de s1+s2+s3 via VLAN, aprendizado: {APRENDIZADO_SEG}s)")
        log_detector = iniciar_detector_unico(h7, iface_h7, tag)
        time.sleep(2)

        hosts_legitimos = [net.get(h) for h in
                           ["h1", "h2", "h3", "h4", "h5", "h6", "h8", "h10", "h11", "h12"]]
        for h in hosts_legitimos:
            h.cmd("ip neigh flush all 2>/dev/null")
        time.sleep(1)
        for _ in range(2):
            net.ping(hosts=hosts_exceto(net, ["h9", "h7"]), timeout="1")
            time.sleep(1)

        tempo_gasto = 2 + 1 + 2 * 1
        tempo_restante = (APRENDIZADO_SEG + MARGEM_APRENDIZADO_SEG) - tempo_gasto
        if tempo_restante > 0:
            time.sleep(tempo_restante)

        conteudo_aprendizado = _ler_trecho(log_detector)
        log(conteudo_aprendizado)
        if "Aprendizado conclu" not in conteudo_aprendizado:
            resultado["erros"].append("Fase de aprendizado não confirmou conclusão a tempo.")
        if re.search(r"sem-tag=\d+|vlan\d+\?=\d+", conteudo_aprendizado):
            resultado["erros"].append(
                "Detector recebeu ARPs sem tag VLAN reconhecida — origem do "
                "switch não identificada (verifique a versão do scapy / o espelho).")
        # (?<!\d) pra não casar com "10 host(s)", "20 host(s)" etc.
        if re.search(r"(?<!\d)0 host\(s\) mapeado", conteudo_aprendizado):
            resultado["erros"].append("Aprendizado terminou com 0 hosts mapeados.")

        # 3) overhead com o detector rodando
        subsecao(f"[{switch_atacante} #{execucao_idx}] Overhead COM detector ativo")
        lat_com, bw_com = medir_overhead(h1, h2, "com IDS")
        resultado["latencia_com_ids_ms"] = lat_com
        resultado["banda_com_ids_mbps"] = bw_com

        # 4) detecção: cada rodada usa um atacante diferente
        subsecao(f"[{switch_atacante} #{execucao_idx}] Rodadas de ataque "
                 f"(hosts atacantes dedicados por rodada)")
        pos_atual = _tamanho_arquivo(log_detector)
        deteccoes = 0
        for i, (nome_atacante, ip1, ip2) in enumerate(PARES_ATAQUE, start=1):
            h_atk = net.get(nome_atacante)
            log(f"  Rodada {i}/{RODADAS_DETECCAO}: atacante={nome_atacante} "
                f"({h_atk.MAC()})  arpspoof {ip1} <-> {ip2}")
            h_atk.cmd(f"timeout {ATAQUE_DURACAO_SEG} arpspoof -i {nome_atacante}-eth0 "
                      f"-t {ip1} {ip2} "
                      f"> {TMP_DIR}/ataque_{tag}_{i}.log 2>&1")
            time.sleep(PAUSA_ENTRE_RODADAS_SEG)

            trecho_rodada = _ler_trecho(log_detector, pos_atual)
            if trecho_rodada.strip():
                log(trecho_rodada)
            mac_atk = h_atk.MAC().lower()
            houve_alerta = "ARP SPOOFING DETECTADO" in trecho_rodada
            detectou = houve_alerta and mac_atk in trecho_rodada.lower()
            if detectou:
                deteccoes += 1
                log(f"  >>> [DETECTADO] Rodada {i}: ataque de {nome_atacante} "
                    f"({mac_atk}) foi identificado pelo IDS")
            elif houve_alerta:
                log(f"  >>> [NÃO DETECTADO] Rodada {i}: houve alerta, mas não "
                    f"com o MAC de {nome_atacante} ({mac_atk})")
            else:
                log(f"  >>> [NÃO DETECTADO] Rodada {i}: nenhum alerta para "
                    f"{nome_atacante} ({mac_atk})")
            pos_atual = _tamanho_arquivo(log_detector)
        resultado["deteccoes"] = deteccoes
        log(f"  >>> RESULTADO DOS ATAQUES: {deteccoes}/{RODADAS_DETECCAO} detectados")

        # 5) falso positivo: h3 já conhecido falando normalmente
        subsecao(f"[{switch_atacante} #{execucao_idx}] Falso positivo — host reincidente (h3)")
        h3 = net.get("h3")
        pos_atual = _tamanho_arquivo(log_detector)
        falsos_positivos = 0
        for i in range(RODADAS_FALSO_POSITIVO):
            h3.cmd(f"ping -c 1 {h1.IP()} > /dev/null 2>&1")
            time.sleep(1)
            trecho = _ler_trecho(log_detector, pos_atual)
            if trecho.strip():
                log(trecho)
            if "ARP SPOOFING DETECTADO" in trecho:
                falsos_positivos += 1
                log(f"  >>> [FALSO POSITIVO] Rodada {i+1}: h3 legítimo gerou alerta")
            else:
                log(f"  >>> [OK] Rodada {i+1}: h3 legítimo não gerou alerta")
            pos_atual = _tamanho_arquivo(log_detector)
        resultado["falsos_positivos"] = falsos_positivos
        log(f"  >>> RESULTADO FALSOS POSITIVOS: {falsos_positivos}/{RODADAS_FALSO_POSITIVO}")

        # 6) host novo: h9 nunca foi visto pelo detector
        subsecao(f"[{switch_atacante} #{execucao_idx}] Host genuinamente novo pós-aprendizado (h9)")
        pos_atual = _tamanho_arquivo(log_detector)
        host_novo_alertas = 0
        h9_apareceu = False
        for i in range(RODADAS_HOST_NOVO):
            h9.cmd(f"ping -c 2 {h1.IP()} > /dev/null 2>&1")
            time.sleep(1)
            trecho = _ler_trecho(log_detector, pos_atual)
            if trecho.strip():
                log(trecho)
            if "10.0.0.9" in trecho:
                h9_apareceu = True
            if "ARP SPOOFING DETECTADO" in trecho:
                host_novo_alertas += 1
            pos_atual = _tamanho_arquivo(log_detector)
        resultado["host_novo_alertas"] = host_novo_alertas
        resultado["host_novo_aceito"] = h9_apareceu and host_novo_alertas == 0
        log(f"  >>> RESULTADO HOST NOVO (h9): visto pelo IDS={h9_apareceu}, "
            f"alertas de spoofing={host_novo_alertas} -> "
            f"{'ACEITO corretamente' if resultado['host_novo_aceito'] else 'FALHOU'}")
        if not h9_apareceu:
            resultado["erros"].append(
                "h9 não apareceu no log do detector durante o teste de "
                "host novo — verifique se o tráfego chegou até algum mirror."
            )

        if resultado["erros"]:
            log("[AVISO] " + "; ".join(resultado["erros"]))

        h7.cmd(f"pkill -f {os.path.basename(DETECTOR_PATH)}")
        time.sleep(2)

    except Exception as exc:
        resultado["erros"].append(f"Exceção durante {switch_atacante} #{execucao_idx}: {exc}")
    finally:
        if net is not None:
            try:
                net.stop()
            except Exception:
                pass
        remover_pares_espelho()
        os.system("mn -c > /dev/null 2>&1")
        time.sleep(2)

    return resultado


# ============================================================================
# Agregação e resumo
# ============================================================================
def media_dp(vals):
    if not vals:
        return None, None
    media = statistics.mean(vals)
    dp = statistics.stdev(vals) if len(vals) > 1 else 0.0
    return media, dp


def agregar_por_cenario(resultados):
    agregados = {}
    for cenario in CENARIOS:
        execs = [r for r in resultados if r["cenario"] == cenario]
        if not execs:
            continue

        total_deteccoes = sum(r["deteccoes"] for r in execs)
        total_rodadas = sum(r["rodadas_ataque"] for r in execs)
        total_fp = sum(r["falsos_positivos"] for r in execs)
        total_rodadas_fp = sum(r["rodadas_fp"] for r in execs)
        total_host_novo_aceito = sum(1 for r in execs if r["host_novo_aceito"])
        total_host_novo_alertas = sum(r["host_novo_alertas"] for r in execs)

        lat_base_vals = [r["latencia_baseline_ms"] for r in execs if r["latencia_baseline_ms"]]
        lat_com_vals = [r["latencia_com_ids_ms"] for r in execs if r["latencia_com_ids_ms"]]
        bw_base_vals = [r["banda_baseline_mbps"] for r in execs if r["banda_baseline_mbps"]]
        bw_com_vals = [r["banda_com_ids_mbps"] for r in execs if r["banda_com_ids_mbps"]]

        lat_base_media, lat_base_dp = media_dp(lat_base_vals)
        lat_com_media, lat_com_dp = media_dp(lat_com_vals)
        bw_base_media, bw_base_dp = media_dp(bw_base_vals)
        bw_com_media, bw_com_dp = media_dp(bw_com_vals)

        agregados[cenario] = {
            "cenario": cenario,
            "n_execucoes": len(execs),
            "deteccoes": total_deteccoes,
            "rodadas_ataque": total_rodadas,
            "taxa_deteccao": (total_deteccoes / total_rodadas * 100) if total_rodadas else 0,
            "falsos_positivos": total_fp,
            "rodadas_fp": total_rodadas_fp,
            "taxa_fp": (total_fp / total_rodadas_fp * 100) if total_rodadas_fp else 0,
            "host_novo_aceito": total_host_novo_aceito,
            "host_novo_execucoes": len(execs),
            "host_novo_alertas": total_host_novo_alertas,
            "lat_base_media": lat_base_media, "lat_base_dp": lat_base_dp,
            "lat_com_media": lat_com_media, "lat_com_dp": lat_com_dp,
            "bw_base_media": bw_base_media, "bw_base_dp": bw_base_dp,
            "bw_com_media": bw_com_media, "bw_com_dp": bw_com_dp,
            "erros": [e for r in execs for e in r["erros"]],
        }
    return agregados


def tabela_overhead(agregados, tit_base, tit_com, chave, larg):
    # chave = "lat" ou "bw"
    log(f"{'Cenário':<10}{tit_base:<{larg}}{tit_com:<{larg}}{'Overhead':<12}")
    log("-" * 78)
    for c in CENARIOS:
        if c not in agregados:
            continue
        a = agregados[c]
        base = a[f"{chave}_base_media"]
        com = a[f"{chave}_com_media"]
        if base and com:
            overhead_str = f"{(com - base) / base * 100:+.1f}%"
        else:
            overhead_str = "N/D"
        base_str = f"{base:.2f}±{a[f'{chave}_base_dp']:.2f}" if base else "N/D"
        com_str = f"{com:.2f}±{a[f'{chave}_com_dp']:.2f}" if com else "N/D"
        log(f"{c:<10}{base_str:<{larg}}{com_str:<{larg}}{overhead_str:<12}")
    log("")


def escrever_resumo(resultados):
    secao("RESUMO FINAL")

    agregados = agregar_por_cenario(resultados)

    log(f"Cada cenário foi executado {REPETICOES_POR_CENARIO} vez(es), com a "
        f"topologia reconstruída do zero a cada repetição. Cada rodada de "
        f"ataque usou um MAC de atacante distinto, simulando dispositivos "
        f"diferentes. [TESTE RÁPIDO: detector SEM --nac]")
    log("")

    log(f"{'Cenário':<10}{'Execuções':<12}{'Detecção/rodada':<20}{'Taxa':<10}")
    log("-" * 78)
    for c in CENARIOS:
        if c not in agregados:
            continue
        a = agregados[c]
        log(f"{c:<10}{a['n_execucoes']:<12}"
            f"{str(a['deteccoes']) + '/' + str(a['rodadas_ataque']):<20}"
            f"{a['taxa_deteccao']:.1f}%")
    log("")

    log(f"{'Cenário':<10}{'Falsos + (h3)':<18}{'Taxa FP':<12}"
        f"{'Host novo aceito (h9)':<24}{'Alertas h9':<12}")
    log("-" * 78)
    for c in CENARIOS:
        if c not in agregados:
            continue
        a = agregados[c]
        taxa_fp_str = f"{a['taxa_fp']:.1f}%"
        log(f"{c:<10}"
            f"{str(a['falsos_positivos']) + '/' + str(a['rodadas_fp']):<18}"
            f"{taxa_fp_str:<12}"
            f"{str(a['host_novo_aceito']) + '/' + str(a['host_novo_execucoes']):<24}"
            f"{a['host_novo_alertas']:<12}")
    log("")

    tabela_overhead(agregados, "Lat. base (ms)", "Lat. c/IDS (ms)", "lat", 20)
    tabela_overhead(agregados, "Banda base (Mbps)", "Banda c/IDS (Mbps)", "bw", 22)

    total_det = sum(a["deteccoes"] for a in agregados.values())
    total_rod = sum(a["rodadas_ataque"] for a in agregados.values())
    total_fp = sum(a["falsos_positivos"] for a in agregados.values())
    total_rod_fp = sum(a["rodadas_fp"] for a in agregados.values())
    total_h9_aceito = sum(a["host_novo_aceito"] for a in agregados.values())
    total_h9_exec = sum(a["host_novo_execucoes"] for a in agregados.values())

    log("RESUMO GERAL (todos os cenários e repetições agregados):")
    log(f"  Taxa de detecção geral (por rodada) : {total_det}/{total_rod} "
        f"({(total_det/total_rod*100 if total_rod else 0):.1f}%)")
    log(f"  Taxa de falso positivo (h3)         : {total_fp}/{total_rod_fp} "
        f"({(total_fp/total_rod_fp*100 if total_rod_fp else 0):.1f}%)")
    log(f"  Host novo aceito corretamente (h9)  : {total_h9_aceito}/{total_h9_exec} "
        f"({(total_h9_aceito/total_h9_exec*100 if total_h9_exec else 0):.1f}%)")

    erros_totais = [e for a in agregados.values() for e in a["erros"]]
    if erros_totais:
        log("")
        log("AVISOS/ERROS OCORRIDOS DURANTE OS TESTES (revise antes de usar os números):")
        for e in erros_totais:
            log(f"  - {e}")


# ============================================================================
# Main
# ============================================================================
def main():
    global _log_file_handle

    if os.geteuid() != 0:
        print("[ERRO] Execute como root: sudo python3 testes_experimentais_passf.py")
        sys.exit(1)

    if not os.path.exists(DETECTOR_PATH):
        print(f"[ERRO] Não encontrei o detector em: {DETECTOR_PATH}")
        sys.exit(1)

    faltando = [c for c in ("ip", "tc") if shutil.which(c) is None]
    if faltando:
        print(f"[ERRO] Ferramenta(s) ausente(s): {', '.join(faltando)} "
              f"(instale o pacote iproute2).")
        sys.exit(1)
    for c in ("arpspoof", "iperf"):
        if shutil.which(c) is None:
            print(f"[AVISO] '{c}' não encontrado no PATH — o teste vai falhar sem ele.")

    preparar_ambiente()
    remover_pares_espelho()
    setLogLevel("error")

    _log_file_handle = open(RESULTS_TXT, "w", encoding="utf-8")
    log("=" * 78)
    log(" RESULTADOS DOS TESTES EXPERIMENTAIS (TESTE RÁPIDO, SEM --nac)")
    log(" Detecção de ARP Poisoning em Redes Industriais com Python")
    log(f" Gerado em: {datetime.datetime.now().strftime('%d/%m/%Y %H:%M:%S')}")
    log("=" * 78)
    log("")
    log("Parâmetros usados nesta execução:")
    log(f"  Tempo de aprendizado........: {APRENDIZADO_SEG}s")
    log(f"  Repetições por cenário......: {REPETICOES_POR_CENARIO}")
    log(f"  Rodadas de ataque/execução..: {RODADAS_DETECCAO} (MAC de atacante diferente a cada rodada)")
    log(f"  Rodadas de falso positivo...: {RODADAS_FALSO_POSITIVO} (host reincidente h3)")
    log(f"  Rodadas de host novo........: {RODADAS_HOST_NOVO} (host inédito h9)")
    log(f"  Amostras de overhead........: {MEDICOES_OVERHEAD}x de {PING_COUNT} pacotes / {IPERF_DURACAO}s")
    log(f"  Cenários (posição de h8)....: {', '.join(CENARIOS)}")
    log(f"  Total de execuções completas: {len(CENARIOS) * REPETICOES_POR_CENARIO}")

    tempo_inicio = time.time()
    resultados = []
    total_execucoes = len(CENARIOS) * REPETICOES_POR_CENARIO
    execucao_num = 0

    for switch_atacante in CENARIOS:
        for rep in range(1, REPETICOES_POR_CENARIO + 1):
            execucao_num += 1
            secao(f"CENÁRIO {switch_atacante} — EXECUÇÃO {rep}/{REPETICOES_POR_CENARIO} "
                  f"(geral: {execucao_num}/{total_execucoes})")
            r = rodar_cenario(switch_atacante, rep)
            resultados.append(r)
            decorrido_min = (time.time() - tempo_inicio) / 60
            log(f"[PROGRESSO] {execucao_num}/{total_execucoes} execuções concluídas "
                f"em {decorrido_min:.1f} min.")

    escrever_resumo(resultados)

    log("")
    log("=" * 78)
    log(" FIM DOS TESTES")
    log(f" Tempo total: {(time.time() - tempo_inicio) / 60:.1f} minutos")
    log("=" * 78)
    _log_file_handle.close()

    print(f"\nResultados completos salvos em: {RESULTS_TXT}")


if __name__ == "__main__":
    main()
