#!/usr/bin/env python3
"""
================================================================================
 TESTES EXPERIMENTAIS CONSOLIDADOS — Detecção de ARP Poisoning em Redes
 Industriais — TCC — FEMEC/UFU — Samuel Silva dos Santos
================================================================================

O QUE MUDOU NESTA VERSÃO (consolidação pedida após o Capítulo 5)
-------------------------------------------------------------------
Esta versão resolve as quatro limitações apontadas na Seção 5.3 do TCC:

  1. CADA CENÁRIO RODA VÁRIAS VEZES (REPETICOES_POR_CENARIO), com a topologia
     reconstruída do zero a cada repetição. O resumo final reporta média e
     desvio padrão por cenário, em vez de um único "sim/não".

  2. CADA RODADA DE ATAQUE É FEITA POR UM HOST ATACANTE DEDICADO DIFERENTE
     (h8, h10, h11 e h12), em vez de um único host reaproveitado. Isso
     resolve o efeito em que, antes, o bloqueio da 1ª rodada "neutralizava"
     as rodadas seguintes sem testar a detecção de fato — agora cada rodada
     é uma tentativa independente e a taxa de detecção por rodada volta a
     ser uma métrica válida.
     (Uma primeira tentativa desta correção usou uma única interface h8
     trocando de MAC a cada rodada; isso se mostrou problemático em duas
     frentes — trocar o MAC real de h8 disparava um ARP gratuito do próprio
     host anunciando sua nova identidade para o seu PRÓPRIO IP, gerando
     alertas espúrios; e a alternativa com sub-interfaces macvlan não se
     mostrou confiável sobre os links veth do Mininet, com os quadros nem
     sempre chegando ao espelhamento. Hosts dedicados de verdade usam o
     mesmo mecanismo, já validado, de h1-h8.)

  3. AMOSTRAS DE OVERHEAD MAIORES E REPETIDAS: ping de 50 pacotes (era 10) e
     iperf de 10s (era 5s), cada medição repetida MEDICOES_OVERHEAD vezes e
     com a média reportada — reduz o ruído que gerava overheads "negativos"
     sem sentido físico na versão anterior.

  4. TESTE DE HOST GENUINAMENTE NOVO: além do teste de falso positivo com um
     host já conhecido reincidindo (h3), agora um host adicional (h9) só
     entra em atividade DEPOIS da fase de aprendizado, simulando um
     equipamento novo sendo instalado na fábrica.

  5. ESPELHAMENTO TAMBÉM EM s2 E s3 (não só no núcleo s1): rodando com só o
     espelho de s1, foi descoberto que um ataque entre dois hosts do MESMO
     switch de acesso (ex.: h1<->h2, ambos em s2) nunca atravessa o núcleo —
     é um quadro unicast comutado localmente — e por isso NUNCA chegava a
     ser visto pelo IDS, independente de qualquer bug de código. Isso
     derrubava a taxa de detecção nos cenários s2 (25%) e s3 (75%), embora
     a lógica de detecção em si estivesse correta sempre que o pacote
     chegava até ela. Agora h7 tem uma interface para cada switch (s1, s2 e
     s3), cada uma alimentada pelo espelhamento LOCAL daquele switch, e uma
     instância do detector roda em cada uma (aplicando o NAC na própria
     bridge onde o ataque foi visto). O mesmo problema, por sinal, também
     afetava silenciosamente o teste de falso positivo (h3 e h1 estão no
     mesmo switch s2 em TODOS os cenários) — o "0% de falso positivo" das
     versões anteriores media, sem querer, "0% das vezes que o tráfego
     chegou a ser visto", nem sempre "0% de verdade". Isso também foi
     corrigido por tabela.

AVISO DE DURAÇÃO
-----------------
Com REPETICOES_POR_CENARIO=5 (padrão), o tempo total estimado é de
~60-90 minutos (3 cenários x 5 repetições x ~4-5 min cada, já com os 3
detectores rodando simultaneamente por execução). Ajuste
REPETICOES_POR_CENARIO abaixo se quiser um teste mais rápido.

COMO RODAR
----------
  1) Coloque este arquivo NA MESMA PASTA do arp_detector_arrumado.py.
  2) Ajuste RESULTS_DIR se quiser salvar o .txt na pasta de texto do TCC.
  3) sudo python3 testes_experimentais.py
  4) Pode deixar rodando em segundo plano — tudo é salvo incrementalmente
     em resultados_experimentos.txt conforme cada cenário termina.

REQUISITOS (mesmos de antes)
------------------------------
  - mininet, openvswitch-switch
  - dsniff (arpspoof)                        -> sudo apt install dsniff
  - iperf                                    -> sudo apt install iperf
  - scapy, colorama
================================================================================
"""

import os
import re
import sys
import time
import datetime
import statistics

from mininet.net import Mininet
from mininet.node import OVSSwitch
from mininet.link import TCLink
from mininet.log import setLogLevel

# ============================================================================
# CONFIGURAÇÃO — ajuste aqui se precisar
# ============================================================================
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
DETECTOR_PATH = os.path.join(SCRIPT_DIR, "arp_detector_arrumado.py")

# Pasta onde o resultados_experimentos.txt será salvo — ajuste para a pasta
# de texto/redação do TCC.
RESULTS_DIR = SCRIPT_DIR
# RESULTS_DIR = os.path.join(os.path.expanduser("~"), "tcc", "texto")

APRENDIZADO_SEG = 15          # mesmo valor usado no Capítulo 3 (padrão da ferramenta)
MARGEM_APRENDIZADO_SEG = 5    # tempo extra de segurança para garantir que o aprendizado terminou
ATAQUE_DURACAO_SEG = 6        # duração de cada rodada de arpspoof
PAUSA_ENTRE_RODADAS_SEG = 3   # pausa entre uma rodada de ataque e outra

# Cada rodada de ataque é feita por um HOST ATACANTE DEDICADO diferente
# (não por rotação de MAC virtual — ver nota no topo do arquivo). Formato:
# (nome_do_host_atacante, IP_vitima_1, IP_vitima_2)
PARES_ATAQUE = [
    ("h8",  "10.0.0.1", "10.0.0.2"),  # h1 (PLC1) <-> h2 (PLC2), ambos em s2
    ("h10", "10.0.0.4", "10.0.0.5"),  # h4 (Sensor1) <-> h5 (Sensor2), ambos em s3
    ("h11", "10.0.0.3", "10.0.0.6"),  # h3 (IHM) <-> h6 (SCADA), em segmentos diferentes
    ("h12", "10.0.0.1", "10.0.0.6"),  # h1 (PLC1) <-> h6 (SCADA), em segmentos diferentes
]
RODADAS_DETECCAO = len(PARES_ATAQUE)
RODADAS_FALSO_POSITIVO = 3      # repetições do teste de host reincidente (h3)
RODADAS_HOST_NOVO = 3            # repetições do teste de host genuinamente novo (h9)

CENARIOS = ["s1", "s2", "s3"]
REPETICOES_POR_CENARIO = 5   # <<< ajuste aqui para testes mais rápidos/robustos

# Overhead de rede: amostras maiores e repetidas
PING_COUNT = 50                  # pacotes ICMP por medição (era 10)
IPERF_DURACAO = 10               # segundos por medição de banda (era 5)
MEDICOES_OVERHEAD = 3            # repetições de cada medição, reporta a média

os.makedirs(RESULTS_DIR, exist_ok=True)
RESULTS_TXT = os.path.join(RESULTS_DIR, "resultados_experimentos.txt")
TMP_DIR = "/tmp/tcc_testes"

# ============================================================================
# UTILITÁRIOS DE LOG
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
# Nota: rodadas de ataque agora usam hosts atacantes dedicados (h8, h10,
# h11, h12) — ver PARES_ATAQUE e montar_topologia — em vez de truques de
# interface virtual, então não há mais geração/rotação de MAC aqui.
# ============================================================================


# ============================================================================
# FUNÇÕES DE TOPOLOGIA
# ============================================================================
def corrigir_r2q_htb(iface):
    out = os.popen(f"tc qdisc show dev {iface} 2>/dev/null").read()
    if "htb" in out:
        os.system(f"tc qdisc change dev {iface} root handle 1: htb r2q 100 2>/dev/null || true")


def portas_do_bridge(bridge):
    out = os.popen(f"ovs-vsctl list-ports {bridge} 2>/dev/null").read()
    return [p.strip() for p in out.strip().splitlines() if p.strip()]


def configurar_espelho(bridge, porta_saida, portas_monitorar):
    if not portas_monitorar:
        log(f"[AVISO] Nenhuma porta para monitorar em {bridge}")
        return False
    refs, select_src, select_dst = [], [], []
    for i, porta in enumerate(portas_monitorar):
        alias = f"@pm{i}"
        refs.append(f"-- --id={alias} get port {porta}")
        select_src.append(alias)
        select_dst.append(alias)
    refs.append(f"-- --id=@pout get port {porta_saida}")
    cmd = (
        "ovs-vsctl " + " ".join(refs)
        + f" -- --id=@m create mirror name=mirror_{bridge}"
        + f" select-src-port={','.join(select_src)}"
        + f" select-dst-port={','.join(select_dst)}"
        + " output-port=@pout"
        + f" -- set bridge {bridge} mirrors=@m"
    )
    ret = os.system(cmd)
    return ret == 0


def hosts_exceto(net, excluir):
    """Retorna a lista de hosts do net, exceto os nomes em 'excluir'.
    Usado para manter h9 fora do warm-up de ARP (ele deve permanecer
    'desconhecido' até o teste de host novo, de propósito)."""
    return [h for h in net.hosts if h.name not in excluir]


def montar_topologia(switch_atacante):
    """Monta a topologia com h8 (atacante) ligado ao switch indicado, mais o
    host h9 (dispositivo 'novo', usado só no teste de host genuinamente novo
    pós-aprendizado — Seção 5.3, item 'd'). h7 recebe uma interface para
    CADA switch (s1, s2, s3), cada uma alimentada pelo espelhamento LOCAL
    daquele switch — não apenas o do núcleo — para que ataques entre hosts
    do mesmo switch de acesso também sejam visíveis. Retorna (net, ifaces_h7),
    onde ifaces_h7 é um dict {"s1": "h7-ethX", "s2": "h7-ethY", "s3": "h7-ethZ"}."""
    log(f"[TOPO] Criando rede com atacante (h8) ligado a {switch_atacante}...")

    net = Mininet(switch=OVSSwitch, link=TCLink, autoSetMacs=True)

    s1 = net.addSwitch("s1", failMode="standalone")
    s2 = net.addSwitch("s2", failMode="standalone")
    s3 = net.addSwitch("s3", failMode="standalone")

    h1 = net.addHost("h1", ip="10.0.0.1/24", mac="00:00:00:00:00:01")
    h2 = net.addHost("h2", ip="10.0.0.2/24", mac="00:00:00:00:00:02")
    h3 = net.addHost("h3", ip="10.0.0.3/24", mac="00:00:00:00:00:03")
    h4 = net.addHost("h4", ip="10.0.0.4/24", mac="00:00:00:00:00:04")
    h5 = net.addHost("h5", ip="10.0.0.5/24", mac="00:00:00:00:00:05")
    h6 = net.addHost("h6", ip="10.0.0.6/24", mac="00:00:00:00:00:06")
    h7 = net.addHost("h7", ip="10.0.0.7/24", mac="00:00:00:00:00:07")
    h8 = net.addHost("h8", ip="10.0.0.8/24", mac="00:00:00:00:00:08")
    h9 = net.addHost("h9", ip="10.0.0.9/24", mac="00:00:00:00:00:09")  # "novo" equipamento
    # h10, h11, h12: atacantes dedicados para as rodadas 2, 3 e 4 (h8 faz a
    # rodada 1). Todos ligados ao MESMO switch de h8 em cada cenário, para
    # manter "posição do atacante na topologia" como a única variável.
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

    # h7 agora tem UMA INTERFACE PARA CADA SWITCH (h7-eth0->s1, h7-eth1->s2,
    # h7-eth2->s3), cada uma recebendo o espelhamento LOCAL daquele switch.
    # Isso resolve uma limitação real identificada nos testes: um ataque
    # unicast entre dois hosts do MESMO switch de acesso (ex.: h1<->h2, ambos
    # em s2) nunca atravessa o núcleo s1, então um espelhamento centralizado
    # em s1 nunca o vê. Com espelho também em s2 e s3, esse tráfego local
    # passa a ser visível a uma instância do detector rodando naquele switch.
    link_h7_s1 = net.addLink(h7, s1, bw=50, delay="1ms", max_queue_size=1000)
    link_h7_s2 = net.addLink(h7, s2, bw=50, delay="1ms", max_queue_size=1000)
    link_h7_s3 = net.addLink(h7, s3, bw=50, delay="1ms", max_queue_size=1000)
    net.addLink(h9, s1, bw=10, delay="2ms", max_queue_size=1000)  # h9 fica "quieto" até o teste

    net.start()
    time.sleep(2)

    for iface in ["s1-eth1", "s1-eth2", "s2-eth1", "s3-eth1"]:
        corrigir_r2q_htb(iface)
    for host in [h1, h2, h3, h4, h5, h6, h7, h8, h9, h10, h11, h12]:
        host.cmd("sysctl -w net.ipv6.conf.all.disable_ipv6=1 2>/dev/null")

    for sw in ["s1", "s2", "s3"]:
        os.system(f"ovs-vsctl clear bridge {sw} mirrors 2>/dev/null")
    time.sleep(1)

    # Configura um espelho em CADA switch (s1, s2 e s3), cada um enviando
    # para a interface de h7 correspondente. A porta é obtida DIRETAMENTE do
    # objeto Link retornado por net.addLink (o lado ".intf2" é o conectado ao
    # switch) — evita depender de heurísticas frágeis como "external_ids"
    # (nem sempre preenchido pelo Mininet) ou "última porta da lista" (que já
    # nos deu problema antes, ao adicionar hosts depois de h7).
    ifaces_h7 = {}
    for bridge, link_h7 in [("s1", link_h7_s1), ("s2", link_h7_s2), ("s3", link_h7_s3)]:
        porta_h7 = link_h7.intf2.name
        portas_bridge = portas_do_bridge(bridge)
        if porta_h7 not in portas_bridge:
            log(f"[AVISO] Porta de h7 em {bridge} ({porta_h7}) não encontrada — usando fallback.")
            porta_h7 = portas_bridge[-1]
        monitorar = [p for p in portas_bridge if p != porta_h7]
        log(f"[TOPO] Espelho em {bridge}: saída={porta_h7}  monitorando={monitorar}")
        configurar_espelho(bridge, porta_h7, monitorar)
        ifaces_h7[bridge] = link_h7.intf1.name  # nome da interface do LADO de h7
    time.sleep(1)

    # Warm-up de ARP em TODOS os hosts, EXCETO h9 — h9 precisa permanecer
    # "desconhecido" do detector até o teste de host novo (item 4 acima).
    log("[TOPO] Testando conectividade inicial (warm-up de ARP, exceto h9)...")
    net.ping(hosts=hosts_exceto(net, ["h9"]))

    return net, ifaces_h7


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
    """Repete a medição de latência e banda MEDICOES_OVERHEAD vezes e retorna
    a média de cada uma, além das listas brutas (para desvio padrão depois)."""
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
# HELPER PARA O DETECTOR ÚNICO MULTI-INTERFACE (um processo, 3 switches)
# ============================================================================
def iniciar_detector_unico(h7, ifaces_h7, tag):
    """Inicia UM ÚNICO processo do detector escutando a interface local de
    CADA switch ao mesmo tempo (via --iface com múltiplos valores). O
    detector usa pkt.sniffed_on internamente para saber de qual switch cada
    pacote veio e aplica o NAC na bridge correspondente (--bridge-map) — ver
    Seção 5.3: um bloqueio inserido sempre no núcleo não teria efeito sobre
    ataques que nunca saem do switch de acesso onde o atacante está."""
    caminho = os.path.join(TMP_DIR, f"detector_{tag}.log")
    h7.cmd(f"rm -f {caminho}")

    ifaces_ordem = list(ifaces_h7.items())  # [(bridge, iface), ...]
    ifaces_str = " ".join(iface for _, iface in ifaces_ordem)
    bridge_map_str = " ".join(f"{iface}:{bridge}" for bridge, iface in ifaces_ordem)

    h7.cmd(
        f"python3 {DETECTOR_PATH} --iface {ifaces_str} --nac "
        f"--bridge-map {bridge_map_str} "
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
# EXECUÇÃO DE UM CENÁRIO (uma repetição)
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
        net, ifaces_h7 = montar_topologia(switch_atacante)
        h7 = net.get("h7")
        h1 = net.get("h1")
        h2 = net.get("h2")
        h9 = net.get("h9")

        # ----------------------------------------------------------
        # 1) OVERHEAD — BASELINE
        # ----------------------------------------------------------
        subsecao(f"[{switch_atacante} #{execucao_idx}] Overhead BASELINE "
                  f"({MEDICOES_OVERHEAD}x, {PING_COUNT} pacotes, {IPERF_DURACAO}s)")
        lat_base, bw_base = medir_overhead(h1, h2, "baseline")
        resultado["latencia_baseline_ms"] = lat_base
        resultado["banda_baseline_mbps"] = bw_base

        # ----------------------------------------------------------
        # 2) Inicia o detector ÚNICO (escuta s1+s2+s3 num só processo)
        # ----------------------------------------------------------
        subsecao(f"[{switch_atacante} #{execucao_idx}] Iniciando detector único "
                  f"(interfaces de s1+s2+s3, aprendizado: {APRENDIZADO_SEG}s)")
        log_detector = iniciar_detector_unico(h7, ifaces_h7, tag)
        time.sleep(2)

        # Gera tráfego ARP legítimo real durante a janela de aprendizado
        # (exceto h9, que deve continuar desconhecido — ver montar_topologia)
        hosts_legitimos = [net.get(h) for h in
                            ["h1", "h2", "h3", "h4", "h5", "h6", "h8", "h10", "h11", "h12"]]
        for h in hosts_legitimos:
            h.cmd("ip neigh flush all 2>/dev/null")
        time.sleep(1)
        for _ in range(2):
            net.ping(hosts=hosts_exceto(net, ["h9"]))
            time.sleep(1)

        tempo_gasto = 2 + 1 + 2 * 1
        tempo_restante = (APRENDIZADO_SEG + MARGEM_APRENDIZADO_SEG) - tempo_gasto
        if tempo_restante > 0:
            time.sleep(tempo_restante)

        conteudo_aprendizado = _ler_trecho(log_detector)
        log(conteudo_aprendizado)
        if "Aprendizado conclu" not in conteudo_aprendizado:
            resultado["erros"].append("Fase de aprendizado não confirmou conclusão a tempo.")
        if "0 host(s) mapeado(s)" in conteudo_aprendizado:
            resultado["erros"].append("Aprendizado terminou com 0 hosts mapeados.")

        # ----------------------------------------------------------
        # 3) OVERHEAD — COM o detector ativo
        # ----------------------------------------------------------
        subsecao(f"[{switch_atacante} #{execucao_idx}] Overhead COM detector ativo")
        lat_com, bw_com = medir_overhead(h1, h2, "com IDS")
        resultado["latencia_com_ids_ms"] = lat_com
        resultado["banda_com_ids_mbps"] = bw_com

        # ----------------------------------------------------------
        # 4) TAXA DE DETECÇÃO — cada rodada feita por um HOST ATACANTE
        #    dedicado diferente (h8, h10, h11, h12). O detector único
        #    identifica sozinho, via pkt.sniffed_on, em qual switch cada
        #    pacote entrou, e bloqueia na bridge correta — não sempre s1.
        # ----------------------------------------------------------
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
            if "ARP SPOOFING DETECTADO" in trecho_rodada:
                deteccoes += 1
            pos_atual = _tamanho_arquivo(log_detector)
        resultado["deteccoes"] = deteccoes

        # ----------------------------------------------------------
        # 5) FALSOS POSITIVOS — host já conhecido reincidindo (h3)
        # ----------------------------------------------------------
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
            pos_atual = _tamanho_arquivo(log_detector)
        resultado["falsos_positivos"] = falsos_positivos

        # ----------------------------------------------------------
        # 6) HOST GENUINAMENTE NOVO — h9 nunca visto pelo detector
        #    (não participou do warm-up nem do aprendizado)
        # ----------------------------------------------------------
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
        os.system("mn -c > /dev/null 2>&1")
        time.sleep(2)

    return resultado


# ============================================================================
# AGREGAÇÃO DAS REPETIÇÕES
# ============================================================================
def agregar_por_cenario(resultados):
    """Agrupa os resultados de todas as repetições por cenário e calcula
    médias, desvios padrão e taxas agregadas."""
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

        def media_dp(vals):
            if not vals:
                return None, None
            media = statistics.mean(vals)
            dp = statistics.stdev(vals) if len(vals) > 1 else 0.0
            return media, dp

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


# ============================================================================
# RELATÓRIO FINAL
# ============================================================================
def escrever_resumo(resultados):
    secao("RESUMO FINAL — TABELAS PARA OS CAPÍTULOS 4 e 5 DO TCC")

    agregados = agregar_por_cenario(resultados)

    log(f"Cada cenário foi executado {REPETICOES_POR_CENARIO} vezes, com a "
        f"topologia reconstruída do zero a cada repetição. Cada rodada de "
        f"ataque usou um MAC de atacante distinto, simulando dispositivos "
        f"diferentes — por isso a taxa de detecção por rodada abaixo já "
        f"reflete tentativas independentes, sem o efeito de mascaramento "
        f"pelo bloqueio NAC observado na versão anterior dos testes.")
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

    log(f"{'Cenário':<10}{'Lat. base (ms)':<20}{'Lat. c/IDS (ms)':<20}{'Overhead':<12}")
    log("-" * 78)
    for c in CENARIOS:
        if c not in agregados:
            continue
        a = agregados[c]
        if a["lat_base_media"] and a["lat_com_media"]:
            overhead = (a["lat_com_media"] - a["lat_base_media"]) / a["lat_base_media"] * 100
            overhead_str = f"{overhead:+.1f}%"
        else:
            overhead_str = "N/D"
        base_str = f"{a['lat_base_media']:.2f}±{a['lat_base_dp']:.2f}" if a["lat_base_media"] else "N/D"
        com_str = f"{a['lat_com_media']:.2f}±{a['lat_com_dp']:.2f}" if a["lat_com_media"] else "N/D"
        log(f"{c:<10}{base_str:<20}{com_str:<20}{overhead_str:<12}")
    log("")

    log(f"{'Cenário':<10}{'Banda base (Mbps)':<22}{'Banda c/IDS (Mbps)':<22}{'Overhead':<12}")
    log("-" * 78)
    for c in CENARIOS:
        if c not in agregados:
            continue
        a = agregados[c]
        if a["bw_base_media"] and a["bw_com_media"]:
            overhead = (a["bw_com_media"] - a["bw_base_media"]) / a["bw_base_media"] * 100
            overhead_str = f"{overhead:+.1f}%"
        else:
            overhead_str = "N/D"
        base_str = f"{a['bw_base_media']:.2f}±{a['bw_base_dp']:.2f}" if a["bw_base_media"] else "N/D"
        com_str = f"{a['bw_com_media']:.2f}±{a['bw_com_dp']:.2f}" if a["bw_com_media"] else "N/D"
        log(f"{c:<10}{base_str:<22}{com_str:<22}{overhead_str:<12}")
    log("")

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
# MAIN
# ============================================================================
def main():
    global _log_file_handle

    if os.geteuid() != 0:
        print("[ERRO] Execute como root: sudo python3 testes_experimentais.py")
        sys.exit(1)

    if not os.path.exists(DETECTOR_PATH):
        print(f"[ERRO] Não encontrei o detector em: {DETECTOR_PATH}")
        sys.exit(1)

    setLogLevel("error")

    _log_file_handle = open(RESULTS_TXT, "w", encoding="utf-8")
    log("=" * 78)
    log(" RESULTADOS DOS TESTES EXPERIMENTAIS (VERSÃO CONSOLIDADA)")
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
