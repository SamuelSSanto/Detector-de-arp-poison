#!/usr/bin/env python3
"""
Topologia Industrial simulaçao
TCC — Detecção de ARP Poisoning em Redes Industriais
FEMEC/UFU — Samuel Silva dos Santos

TOPOLOGIA:

                    s1 (Core)
                   /         \\
                 s2            s3
              /  |  \\        /  |  \\
            h1  h2  h3      h4  h5  h6
          (PLC1)(PLC2)(IHM) (Sen1)(Sen2)(SCADA)

  h7  (IDS)       — uma interface para CADA switch (h7-eth0→s1, h7-eth1→s2,
                     h7-eth2→s3), cada uma alimentada pelo espelhamento
                     LOCAL daquele switch.
  h8, h10, h11, h12 (atacantes) — ligados ao switch escolhido em
                     ATACANTE_SWITCH (padrão s1). Quatro hosts distintos
                     para que cada rodada de ataque use um MAC próprio.
  h9  (host novo)  — ligado a s1, fica fora do warm-up de ARP de propósito,
                     para simular um equipamento instalado depois que o
                     detector já está em operação.

COMO RODAR
----------
  1) sudo python3 topologia.py [s1|s2|s3]
     
  2) Em outro terminal (xterm h7 a partir do CLI do Mininet), inicie o
     detector escutando as três interfaces de uma vez:

       xterm h7
       sudo python3 arp_detector.py --iface h7-eth0 h7-eth1 h7-eth2 --nac \\
           --bridge-map h7-eth0:s1 h7-eth1:s2 h7-eth2:s3 --tempo 15

  3) Aguarde "Aprendizado concluído, N host(s) mapeado(s)".

  4) xterm h8
     arpspoof -i h8-eth0 -t 10.0.0.1 10.0.0.2

  5) Verifique o bloqueio:
     ovs-ofctl dump-flows s1   (ou s2 / s3, conforme o switch do atacante)
"""

import os
import sys
import time

from mininet.net import Mininet
from mininet.node import OVSSwitch
from mininet.cli import CLI
from mininet.link import TCLink
from mininet.log import setLogLevel


# ============================================================================
# UTILITÁRIOS DE REDE
# ============================================================================
def corrigir_r2q_htb(iface):
    """Evita o limite baixo de banda que o parâmetro padrão de r2q do HTB
    impõe em enlaces com bw configurada pelo TCLink do Mininet."""
    out = os.popen(f"tc qdisc show dev {iface} 2>/dev/null").read()
    if "htb" in out:
        os.system(
            f"tc qdisc change dev {iface} root handle 1: htb r2q 100 2>/dev/null || true"
        )


def portas_do_bridge(bridge):
    out = os.popen(f"ovs-vsctl list-ports {bridge} 2>/dev/null").read()
    return [p.strip() for p in out.strip().splitlines() if p.strip()]


def configurar_espelho(bridge, porta_saida, portas_monitorar):
    """Configura um port mirror no Open vSwitch: tudo que entra ou sai das
    portas em 'portas_monitorar' é copiado para 'porta_saida' (a interface
    do IDS), sem interferir no encaminhamento normal do tráfego."""
    if not portas_monitorar:
        print(f"[AVISO] Nenhuma porta para monitorar em {bridge}")
        return False

    refs, select_src, select_dst = [], [], []
    for i, porta in enumerate(portas_monitorar):
        alias = f"@pm{i}"
        refs.append(f"-- --id={alias} get port {porta}")
        select_src.append(alias)
        select_dst.append(alias)
    refs.append(f"-- --id=@pout get port {porta_saida}")

    cmd = (
        "ovs-vsctl "
        + " ".join(refs)
        + f" -- --id=@m create mirror name=mirror_{bridge}"
        + f" select-src-port={','.join(select_src)}"
        + f" select-dst-port={','.join(select_dst)}"
        + " output-port=@pout"
        + f" -- set bridge {bridge} mirrors=@m"
    )
    ret = os.system(cmd)
    if ret == 0:
        print(f"[OK] Mirror em {bridge}: monitorar={portas_monitorar} saída={porta_saida}")
    else:
        print(f"[ERRO] Mirror em {bridge} falhou")
    return ret == 0


def hosts_exceto(net, excluir):
    """Retorna a lista de hosts do net, exceto os nomes em 'excluir'.
    Usado para manter h9 fora do warm-up de ARP (ele deve permanecer
    'desconhecido' do detector até o teste de host novo)."""
    return [h for h in net.hosts if h.name not in excluir]


# ============================================================================
# TOPOLOGIA
# ============================================================================
def montar_topologia(atacante_switch="s1"):
    """Monta a topologia industrial completa, com h8/h10/h11/h12 (atacantes)
    ligados ao switch indicado em 'atacante_switch'. h7 recebe uma interface
    para CADA switch (s1, s2, s3), cada uma alimentada pelo espelhamento
    LOCAL daquele switch. Retorna (net, ifaces_h7), onde ifaces_h7 é um dict
    {"s1": "h7-ethX", "s2": "h7-ethY", "s3": "h7-ethZ"}."""
    print(f"*** Criando rede industrial — atacantes ligados a {atacante_switch}")

    net = Mininet(switch=OVSSwitch, link=TCLink, autoSetMacs=True)

    # Switches ──────────────────────────────────────────────────────
    print("*** Criando switches")
    s1 = net.addSwitch("s1", failMode="standalone")  # Core
    s2 = net.addSwitch("s2", failMode="standalone")  # Acesso — PLC/IHM
    s3 = net.addSwitch("s3", failMode="standalone")  # Acesso — Sensores/SCADA

    # Hosts ─────────────────────────────────────────────────────────
    print("*** Criando hosts")
    h1 = net.addHost("h1", ip="10.0.0.1/24", mac="00:00:00:00:00:01")    # PLC 1
    h2 = net.addHost("h2", ip="10.0.0.2/24", mac="00:00:00:00:00:02")    # PLC 2
    h3 = net.addHost("h3", ip="10.0.0.3/24", mac="00:00:00:00:00:03")    # IHM
    h4 = net.addHost("h4", ip="10.0.0.4/24", mac="00:00:00:00:00:04")    # Sensor 1
    h5 = net.addHost("h5", ip="10.0.0.5/24", mac="00:00:00:00:00:05")    # Sensor 2
    h6 = net.addHost("h6", ip="10.0.0.6/24", mac="00:00:00:00:00:06")    # SCADA
    h7 = net.addHost("h7", ip="10.0.0.7/24", mac="00:00:00:00:00:07")    # IDS
    h8 = net.addHost("h8", ip="10.0.0.8/24", mac="00:00:00:00:00:08")    # Atacante 1
    h9 = net.addHost("h9", ip="10.0.0.9/24", mac="00:00:00:00:00:09")    # Host "novo"
    h10 = net.addHost("h10", ip="10.0.0.10/24", mac="00:00:00:00:00:0a")  # Atacante 2
    h11 = net.addHost("h11", ip="10.0.0.11/24", mac="00:00:00:00:00:0b")  # Atacante 3
    h12 = net.addHost("h12", ip="10.0.0.12/24", mac="00:00:00:00:00:0c")  # Atacante 4

    # Links ─────────────────────────────────────────────────────────
    print("*** Criando links com QoS")

    # Uplinks do núcleo (100 Mbps)
    net.addLink(s1, s2, bw=100, delay="1ms", max_queue_size=1000)
    net.addLink(s1, s3, bw=100, delay="1ms", max_queue_size=1000)

    # Hosts em s2 (10 Mbps)
    net.addLink(h1, s2, bw=10, delay="2ms", max_queue_size=1000)
    net.addLink(h2, s2, bw=10, delay="2ms", max_queue_size=1000)
    net.addLink(h3, s2, bw=10, delay="2ms", max_queue_size=1000)

    # Hosts em s3 (10 Mbps)
    net.addLink(h4, s3, bw=10, delay="2ms", max_queue_size=1000)
    net.addLink(h5, s3, bw=10, delay="2ms", max_queue_size=1000)
    net.addLink(h6, s3, bw=10, delay="2ms", max_queue_size=1000)

    # Atacantes (h8, h10, h11, h12) — todos no mesmo switch, definido por
    # 'atacante_switch', para manter a posição do atacante como a única
    # variável entre cenários.
    switch_atacante_obj = {"s1": s1, "s2": s2, "s3": s3}[atacante_switch]
    net.addLink(h8, switch_atacante_obj, bw=10, delay="2ms", max_queue_size=1000)
    net.addLink(h10, switch_atacante_obj, bw=10, delay="2ms", max_queue_size=1000)
    net.addLink(h11, switch_atacante_obj, bw=10, delay="2ms", max_queue_size=1000)
    net.addLink(h12, switch_atacante_obj, bw=10, delay="2ms", max_queue_size=1000)

    # h7 (IDS) — uma interface para cada switch (50 Mbps), cada uma
    # recebendo o espelhamento LOCAL daquele switch.
    link_h7_s1 = net.addLink(h7, s1, bw=50, delay="1ms", max_queue_size=1000)
    link_h7_s2 = net.addLink(h7, s2, bw=50, delay="1ms", max_queue_size=1000)
    link_h7_s3 = net.addLink(h7, s3, bw=50, delay="1ms", max_queue_size=1000)

    # h9 (host "novo") fica ligado a s1, mas fora do warm-up de ARP — ver
    # abaixo — para permanecer desconhecido do detector até o teste
    # específico de aceitação de host novo.
    net.addLink(h9, s1, bw=10, delay="2ms", max_queue_size=1000)

    # Carregamento da rede ─────────────────────────────────────────────────────────
    print("*** Iniciando rede")
    net.start()
    time.sleep(2)

    # ── Corrige r2q HTB ───────────────────────────────────────────────
    print("*** Ajustando r2q HTB")
    for iface in ["s1-eth1", "s1-eth2", "s2-eth1", "s3-eth1"]:
        corrigir_r2q_htb(iface)

    # IPv6 off ──────────────────────────────────────────────────────
    for host in [h1, h2, h3, h4, h5, h6, h7, h8, h9, h10, h11, h12]:
        host.cmd("sysctl -w net.ipv6.conf.all.disable_ipv6=1 2>/dev/null")
        host.cmd("sysctl -w net.ipv6.conf.default.disable_ipv6=1 2>/dev/null")
        host.cmd("sysctl -w net.ipv6.conf.lo.disable_ipv6=1 2>/dev/null")

    # ── Debug: mapa de portas ─────────────────────────────────────────
    print("\n*** Mapa de portas OVS:")
    for sw in ["s1", "s2", "s3"]:
        print(f"    {sw}: {portas_do_bridge(sw)}")

    # ── Limpa mirrors antigos ─────────────────────────────────────────
    print("\n*** Limpando mirrors antigos")
    for sw in ["s1", "s2", "s3"]:
        os.system(f"ovs-vsctl clear bridge {sw} mirrors 2>/dev/null")
    time.sleep(1)

    # Espelhamento independente em s1, s2 e s3 ─────────────────────
    # A porta de saída de cada mirror é obtida DIRETAMENTE do objeto Link
    # retornado por net.addLink (o lado ".intf2" é o conectado ao switch) 
    print("\n*** Configurando espelhamento em s1, s2 e s3")
    ifaces_h7 = {}
    for bridge, link_h7 in [("s1", link_h7_s1), ("s2", link_h7_s2), ("s3", link_h7_s3)]:
        porta_h7 = link_h7.intf2.name
        portas_bridge = portas_do_bridge(bridge)
        if porta_h7 not in portas_bridge:
            print(f"[AVISO] Porta de h7 em {bridge} ({porta_h7}) não encontrada — usando fallback.")
            porta_h7 = portas_bridge[-1]
        monitorar = [p for p in portas_bridge if p != porta_h7]
        configurar_espelho(bridge, porta_h7, monitorar)
        ifaces_h7[bridge] = link_h7.intf1.name  # nome da interface do LADO de h7
    time.sleep(1)

    #  Teste de conectividade ─────────────────────────────────────────
    #  EXCETO h9 — h9 precisa permanecer "desconhecido" do detector até o teste de host novo.
    print("\n*** Testando conectividade inicial (warm-up de ARP, exceto h9)")
    print("    >>> ABRA h7 E INICIE O IDS AGORA <<<\n")
    time.sleep(5)
    net.ping(hosts=hosts_exceto(net, ["h9"]))

    # Instruções para rodar ────────────────────────────────────────────────────
    print("\n" + "=" * 65)
    print(" TOPOLOGIA PRONTA")
    print("=" * 65)
    print(f"""
INTERFACES DE h7 (uma por switch):
  {ifaces_h7.get("s1", "?")} -> s1 (núcleo)
  {ifaces_h7.get("s2", "?")} -> s2 (acesso)
  {ifaces_h7.get("s3", "?")} -> s3 (acesso)

ATACANTES (h8, h10, h11, h12) ligados a: {atacante_switch}
HOST NOVO (h9): ligado a s1, fora do warm-up de ARP de propósito

COMO RODAR:
  1) xterm h7
     sudo python3 arp_detector.py \\
         --iface {ifaces_h7.get("s1", "h7-eth0")} {ifaces_h7.get("s2", "h7-eth1")} {ifaces_h7.get("s3", "h7-eth2")} \\
         --nac \\
         --bridge-map {ifaces_h7.get("s1", "h7-eth0")}:s1 {ifaces_h7.get("s2", "h7-eth1")}:s2 {ifaces_h7.get("s3", "h7-eth2")}:s3 \\
         --tempo 15

  2) Aguardar: "Aprendizado concluído, N host(s) mapeado(s)"

  3) xterm h8
     arpspoof -i h8-eth0 -t 10.0.0.1 10.0.0.2

  4) Verificar bloqueio:
     ovs-ofctl dump-flows {atacante_switch}
""")
    print("=" * 65 + "\n")

    return net, ifaces_h7


if __name__ == "__main__":
    setLogLevel("info")

    atacante_switch = sys.argv[1] if len(sys.argv) > 1 else "s1"
    if atacante_switch not in ("s1", "s2", "s3"):
        print(f"[ERRO] Switch inválido: {atacante_switch} (use s1, s2 ou s3)")
        sys.exit(1)

    net, ifaces_h7 = montar_topologia(atacante_switch)
    CLI(net)
    net.stop()
