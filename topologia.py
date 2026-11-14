#!/usr/bin/env python3
# Topologia do TCC - detecção de ARP Poisoning em redes industriais
# Só monta a rede e o espelhamento. Detector e ataque a gente roda na mão.
#
# Uso: sudo python3 topologia.py [s1|s2|s3]
#   o argumento é o switch onde ficam os atacantes (padrão: s1)
#
#              s1 (núcleo)
#           /   |    \
#         s2    s3    h7 (IDS) e h9 (host novo)
#       h1 h2 h3  h4 h5 h6
#
#   h1 PLC1 | h2 PLC2 | h3 IHM | h4 Sensor1 | h5 Sensor2 | h6 SCADA
#   h8, h10, h11, h12 = atacantes (todos no mesmo switch)
#   h9 = host que só entra em uso depois do aprendizado
#
# Espelhamento: cada switch copia o que entra nas suas portas pra um par veth
# (sX-spn -> s1-rxN). A cópia sai com uma VLAN (101 = s1, 102 = s2, 103 = s3)
# e vai pra porta do h7 no s1. Assim o h7 tem um link só e ainda sabe de qual
# switch veio cada ARP.
#
# Depois de subir:
#   mininet> xterm h7
#   python3 arp_detector_arrumado.py --iface h7-eth0 --nac --tempo 15 \
#       --bridge-map h7-eth0:s1 --vlan-map 101:s1 102:s2 103:s3
#
#   mininet> xterm h8
#   arpspoof -i h8-eth0 -t 10.0.0.1 10.0.0.2
#
#   ovs-ofctl dump-flows s2     (ver o bloqueio)

import os
import re
import sys
import time

from mininet.net import Mininet
from mininet.node import OVSSwitch
from mininet.cli import CLI
from mininet.link import TCLink
from mininet.log import setLogLevel

VLAN_POR_SWITCH = {"s1": 101, "s2": 102, "s3": 103}

# (ponta de saída no switch, ponta de entrada no s1)
PAR_ESPELHO = {
    "s1": ("s1-spn", "s1-rx1"),
    "s2": ("s2-spn", "s1-rx2"),
    "s3": ("s3-spn", "s1-rx3"),
}


def corrigir_r2q_htb(iface):
    out = os.popen(f"tc qdisc show dev {iface} 2>/dev/null").read()
    if "htb" in out:
        os.system(f"tc qdisc change dev {iface} root handle 1: htb r2q 100 2>/dev/null || true")


def portas_do_bridge(bridge):
    out = os.popen(f"ovs-vsctl list-ports {bridge} 2>/dev/null").read()
    return [p.strip() for p in out.strip().splitlines() if p.strip()]


def tc_matchall(dev, direcao, acao):
    # matchall, e se o kernel não tiver usa u32 que casa tudo
    base = f"tc filter add dev {dev} {direcao} protocol all prio 1"
    if os.system(f"{base} matchall {acao} 2>/dev/null") == 0:
        return True
    return os.system(f"{base} u32 match u32 0 0 {acao} 2>/dev/null") == 0


def filtro_existe(dev, direcao, *trechos):
    out = os.popen(f"tc filter show dev {dev} {direcao} 2>/dev/null").read().lower()
    return all(t.lower() in out for t in trechos)


def remover_pares_espelho():
    # apagar uma ponta do veth já apaga a outra
    for saida, _ in PAR_ESPELHO.values():
        os.system(f"ip link del {saida} 2>/dev/null")


def criar_caminho_espelho(porta_h7):
    ok = True
    for sw, (saida, entrada) in PAR_ESPELHO.items():
        vlan = VLAN_POR_SWITCH[sw]
        os.system(f"ip link del {saida} 2>/dev/null")
        if os.system(f"ip link add {saida} type veth peer name {entrada}") != 0:
            print(f"[ERRO] não consegui criar o veth {saida}<->{entrada}")
            ok = False
            continue

        for dev in (saida, entrada):
            os.system(f"sysctl -w net.ipv6.conf.{dev}.disable_ipv6=1 > /dev/null 2>&1")
            os.system(f"ip link set {dev} up")
        os.system(f"tc qdisc add dev {saida} clsact 2>/dev/null")
        os.system(f"tc qdisc add dev {entrada} clsact 2>/dev/null")

        # a VLAN é colocada na saída, então só a cópia fica marcada
        if not tc_matchall(saida, "egress", f"action vlan push id {vlan}") \
                or not filtro_existe(saida, "egress", "vlan", str(vlan)):
            print(f"[ERRO] push da VLAN {vlan} falhou em {saida}")
            ok = False

        if not tc_matchall(entrada, "ingress", f"action mirred egress redirect dev {porta_h7}") \
                or not filtro_existe(entrada, "ingress", "mirred", porta_h7):
            print(f"[ERRO] redirect {entrada} -> {porta_h7} falhou")
            ok = False

        print(f"    {sw}: {saida} (VLAN {vlan}) -> {entrada} -> {porta_h7}")
    return ok


def configurar_espelho(bridge, porta_saida, portas_monitorar):
    # copia o ingress de cada porta, então todo quadro é copiado uma vez só
    ok = True
    for porta in portas_monitorar:
        os.system(f"tc qdisc del dev {porta} clsact 2>/dev/null")
        if os.system(f"tc qdisc add dev {porta} clsact 2>/dev/null") != 0:
            print(f"[ERRO] clsact falhou em {porta}")
            ok = False
            continue
        if not tc_matchall(porta, "ingress", f"action mirred egress mirror dev {porta_saida}") \
                or not filtro_existe(porta, "ingress", "mirred", porta_saida):
            print(f"[ERRO] espelho {porta} -> {porta_saida} não instalou")
            ok = False
    return ok


def topologia(switch_atacante):
    print("*** Criando rede industrial")

    net = Mininet(switch=OVSSwitch, link=TCLink, autoSetMacs=True)

    # ---- switches ----
    s1 = net.addSwitch("s1", failMode="standalone")
    s2 = net.addSwitch("s2", failMode="standalone")
    s3 = net.addSwitch("s3", failMode="standalone")

    # ---- hosts ----
    h1 = net.addHost("h1", ip="10.0.0.1/24", mac="00:00:00:00:00:01")    # PLC 1
    h2 = net.addHost("h2", ip="10.0.0.2/24", mac="00:00:00:00:00:02")    # PLC 2
    h3 = net.addHost("h3", ip="10.0.0.3/24", mac="00:00:00:00:00:03")    # IHM
    h4 = net.addHost("h4", ip="10.0.0.4/24", mac="00:00:00:00:00:04")    # Sensor 1
    h5 = net.addHost("h5", ip="10.0.0.5/24", mac="00:00:00:00:00:05")    # Sensor 2
    h6 = net.addHost("h6", ip="10.0.0.6/24", mac="00:00:00:00:00:06")    # SCADA
    h7 = net.addHost("h7", ip="10.0.0.7/24", mac="00:00:00:00:00:07")    # IDS
    h8 = net.addHost("h8", ip="10.0.0.8/24", mac="00:00:00:00:00:08")    # atacante 1
    h9 = net.addHost("h9", ip="10.0.0.9/24", mac="00:00:00:00:00:09")    # host novo
    h10 = net.addHost("h10", ip="10.0.0.10/24", mac="00:00:00:00:00:0a")  # atacante 2
    h11 = net.addHost("h11", ip="10.0.0.11/24", mac="00:00:00:00:00:0b")  # atacante 3
    h12 = net.addHost("h12", ip="10.0.0.12/24", mac="00:00:00:00:00:0c")  # atacante 4

    # ---- links ----
    # uplinks do núcleo (100 Mbps)
    net.addLink(s1, s2, bw=100, delay="1ms", max_queue_size=1000)
    net.addLink(s1, s3, bw=100, delay="1ms", max_queue_size=1000)

    # hosts de s2 e s3 (10 Mbps)
    net.addLink(h1, s2, bw=10, delay="2ms", max_queue_size=1000)
    net.addLink(h2, s2, bw=10, delay="2ms", max_queue_size=1000)
    net.addLink(h3, s2, bw=10, delay="2ms", max_queue_size=1000)
    net.addLink(h4, s3, bw=10, delay="2ms", max_queue_size=1000)
    net.addLink(h5, s3, bw=10, delay="2ms", max_queue_size=1000)
    net.addLink(h6, s3, bw=10, delay="2ms", max_queue_size=1000)

    # atacantes no switch escolhido
    sw_atk = {"s1": s1, "s2": s2, "s3": s3}[switch_atacante]
    for atk in (h8, h10, h11, h12):
        net.addLink(atk, sw_atk, bw=10, delay="2ms", max_queue_size=1000)

    # IDS: link único, 100 Mbps porque leva o espelho dos 3 switches
    link_h7 = net.addLink(h7, s1, bw=100, delay="1ms", max_queue_size=1000)
    net.addLink(h9, s1, bw=10, delay="2ms", max_queue_size=1000)

    print("*** Iniciando rede")
    net.start()
    time.sleep(2)

    for iface in ["s1-eth1", "s1-eth2", "s2-eth1", "s3-eth1"]:
        corrigir_r2q_htb(iface)

    for host in net.hosts:
        host.cmd("sysctl -w net.ipv6.conf.all.disable_ipv6=1 2>/dev/null")

    print("\n*** Portas OVS:")
    for sw in ["s1", "s2", "s3"]:
        print(f"    {sw}: {portas_do_bridge(sw)}")

    # limpa mirror antigo do OVS, aqui o espelho é feito com tc
    for sw in ["s1", "s2", "s3"]:
        os.system(f"ovs-vsctl clear bridge {sw} mirrors 2>/dev/null")
    time.sleep(1)

    # ---- espelhamento ----
    porta_h7 = link_h7.intf2.name    # porta do h7 dentro do s1
    iface_h7 = link_h7.intf1.name    # h7-eth0

    print("\n*** Criando caminho de espelho (VLAN por switch)")
    if not criar_caminho_espelho(porta_h7):
        print("[ERRO] caminho de espelho incompleto, confere os módulos do kernel")

    print("\n*** Configurando espelho nos switches")
    for bridge in ["s1", "s2", "s3"]:
        monitorar = [p for p in portas_do_bridge(bridge) if p != porta_h7]
        print(f"    {bridge} monitorando: {monitorar}")
        configurar_espelho(bridge, PAR_ESPELHO[bridge][0], monitorar)
    time.sleep(1)

    # ping em todo mundo menos o h9, ele tem que continuar desconhecido
    print("\n*** Testando conectividade (sem o h9)")
    net.ping(hosts=[h for h in net.hosts if h.name != "h9"])

    print("\n" + "=" * 65)
    print(f" TOPOLOGIA PRONTA - atacantes em {switch_atacante}, IDS em {iface_h7}")
    print("=" * 65 + "\n")

    CLI(net)

    net.stop()
    remover_pares_espelho()


if __name__ == "__main__":
    if os.geteuid() != 0:
        print("Rode como root: sudo python3 topologia.py")
        sys.exit(1)

    escolha = sys.argv[1] if len(sys.argv) > 1 else "s1"
    if not re.fullmatch(r"s[123]", escolha):
        print("Switch inválido, use s1, s2 ou s3")
        sys.exit(1)

    for mod in ("sch_ingress", "act_mirred", "act_vlan", "cls_matchall", "cls_u32", "veth"):
        os.system(f"modprobe {mod} 2>/dev/null")

    remover_pares_espelho()
    setLogLevel("info")
    topologia(escolha)
