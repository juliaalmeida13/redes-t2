import asyncio
from curses import flash
from random import randint
from sys import flags
from tcputils import *
import struct
from time import time

# Valores das flags que serão usadas na nossa implementação simplificada
FLAGS_FIN = 1<<0
FLAGS_SYN = 1<<1
FLAGS_RST = 1<<2
FLAGS_ACK = 1<<4

MSS = 1460   # Tamanho do payload de um segmento TCP (em bytes)

def make_header(src_port, dst_port, seq_no, ack_no, flags):
    """
    Constrói um cabeçalho TCP simplificado.
    Consulte o formato completo em https://en.wikipedia.org/wiki/Transmission_Control_Protocol#TCP_segment_structure
    """
    return struct.pack('!HHIIHHHH',
                       src_port, dst_port, seq_no, ack_no, (5 << 12) | flags,
                       8*MSS, 0, 0)


def read_header(segment):
    """
    Lê um cabeçalho
    """
    src_port, dst_port, seq_no, ack_no, \
        flags, window_size, checksum, urg_ptr = \
        struct.unpack('!HHIIHHHH', segment[:20])
    return src_port, dst_port, seq_no, ack_no, \
        flags, window_size, checksum, urg_ptr


def calc_checksum(segment, src_addr=None, dst_addr=None):
    """
    Calcula o checksum complemento-de-um (formato do TCP e do UDP) para os
    dados fornecidos.
    É necessário passar os endereços IPv4 de origem e de destino, já que
    apesar de não fazerem parte da camada de transporte, eles são incluídos
    no pseudocabeçalho, que faz parte do cálculo do checksum.
    Os endereços IPv4 devem ser passados como string (no formato x.y.z.w)
    """
    if src_addr is None and dst_addr is None:
        data = segment
    else:
        pseudohdr = str2addr(src_addr) + str2addr(dst_addr) + \
            struct.pack('!HH', 0x0006, len(segment))
        data = pseudohdr + segment

    if len(data) % 2 == 1:
        # se for ímpar, faz padding à direita
        data += b'\x00'
    checksum = 0
    for i in range(0, len(data), 2):
        x, = struct.unpack('!H', data[i:i+2])
        checksum += x
        while checksum > 0xffff:
            checksum = (checksum & 0xffff) + 1
    checksum = ~checksum
    return checksum & 0xffff


def fix_checksum(segment, src_addr, dst_addr):
    """
    Corrige o checksum de um segmento TCP.
    """
    seg = bytearray(segment)
    seg[16:18] = b'\x00\x00'
    seg[16:18] = struct.pack('!H', calc_checksum(seg, src_addr, dst_addr))
    return bytes(seg)


def addr2str(addr):
    """
    Converte um endereço IPv4 binário para uma string (no formato x.y.z.w)
    """
    return '%d.%d.%d.%d' % tuple(int(x) for x in addr)


def str2addr(addr):
    """
    Converte uma string (no formato x.y.z.w) para um endereço IPv4 binário
    """
    return bytes(int(x) for x in addr.split('.'))
class Servidor:
    def __init__(self, rede, porta):
        self.rede = rede
        self.porta = porta
        self.conexoes = {}
        self.callback = None
        self.rede.registrar_recebedor(self._rdt_rcv)

    def registrar_monitor_de_conexoes_aceitas(self, callback):
        """
        Usado pela camada de aplicação para registrar uma função para ser chamada
        sempre que uma nova conexão for aceita
        """
        self.callback = callback

    def _rdt_rcv(self, src_addr, dst_addr, segment):
        src_port, dst_port, seq_no, ack_no, \
            flags, window_size, checksum, urg_ptr = read_header(segment)

        if dst_port != self.porta:
            # Ignora segmentos que não são destinados à porta do nosso servidor
            return
        if not self.rede.ignore_checksum and calc_checksum(segment, src_addr, dst_addr) != 0:
            print('descartando segmento com checksum incorreto')
            return

        payload = segment[4*(flags>>12):]
        id_conexao = (src_addr, src_port, dst_addr, dst_port)


        # Passo 1

        if (flags & FLAGS_SYN) == FLAGS_SYN:
            # A flag SYN estar setada significa que é um cliente tentando estabelecer uma conexão nova
            # TODO: talvez você precise passar mais coisas para o construtor de conexão            
            conexao = self.conexoes[id_conexao] = Conexao(self, id_conexao)
            # TODO: você precisa fazer o handshake aceitando a conexão. Escolha se você acha melhor
            # fazer aqui mesmo ou dentro da classe Conexao.
            # Criando as flags
            flags = flags & 0
            flags = flags | (FLAGS_SYN | FLAGS_ACK)

            conexao.seq_no = randint(0, 0xffff)
            conexao.ack_no = seq_no + 1
            src_port, dst_port = dst_port, src_port
            src_addr, dst_addr = dst_addr, src_addr

            segmento = make_header(src_port, dst_port, conexao.seq_no, conexao.ack_no, flags)
            segmento_checksum_corrigido = fix_checksum(segmento, src_addr, dst_addr)
            self.rede.enviar(segmento_checksum_corrigido, dst_addr)

            conexao.seq_no += 1
            conexao.seq_no_base = conexao.seq_no

            if self.callback:
                self.callback(conexao)
        elif id_conexao in self.conexoes:
            # Passa para a conexão adequada se ela já estiver estabelecida
            self.conexoes[id_conexao]._rdt_rcv(seq_no, ack_no, flags, payload)
        else:
            print('%s:%d -> %s:%d (pacote associado a conexão desconhecida)' %
                  (src_addr, src_port, dst_addr, dst_port))


class Conexao:
    def __init__(self, servidor, id_conexao):
        self.servidor = servidor
        self.id_conexao = id_conexao
        self.callback = None
        #self.timer = asyncio.get_event_loop().call_later(1, self._exemplo_timer)  # um timer pode ser criado assim; esta linha é só um exemplo e pode ser removida
        self.timer = None
        self.timeoutInterval = 1
        #Passo1
        self.seq_no = None
        self.ack_no = None
        self.seq_no_base = None

        self.pacotes_sem_ack = []
        #self.timer.cancel()   # é possível cancelar o timer chamando esse método; esta linha é só um exemplo e pode ser removida
        self.devRTT = None
        self.estimatedRTT = None
        self.fila_envio = []
        self.cwnd = 1
        self.pktsQ = []
        self.sent_pkts = []

    #def _exemplo_timer(self):
        # Esta função é só um exemplo e pode ser removida
        #print('Este é um exemplo de como fazer um timer')

    # Passo 5: Timer
    def _timer(self):
        self.cwnd = max(1, self.cwnd // 2)
        for i, (pkt, _) in enumerate(self.sent_pkts):
            self.sent_pkts[i] = (pkt, None) # remove timing since it was not recvd
        pkt, _ = self.sent_pkts[0]
        if self.pacotes_sem_ack:
            segmento, _, dst_addr, _ = self.pacotes_sem_ack[0]

            self.servidor.rede.enviar(segmento, dst_addr)
            self.pacotes_sem_ack[0][3] = None


    # Passo 6: calculando o TimeoutInterval
    def timeout_interval(self):
        _, _, _, sampleRTT = self.pacotes_sem_ack[0]
        if sampleRTT is None:
            return

        sampleRTT = round(time(), 5) - sampleRTT
        if self.estimatedRTT is None:
            self.estimatedRTT = sampleRTT
            self.devRTT = sampleRTT/2
        else:
            self.estimatedRTT = 0.875*self.estimatedRTT + 0.125*sampleRTT
            self.devRTT = 0.75*self.devRTT + 0.25 * abs(sampleRTT-self.estimatedRTT)

        self.timeoutInterval = self.estimatedRTT + 4*self.devRTT

    def _get_idx(self, acked_pkt):
        max_idx = None
        for i, (pkt, _) in enumerate(self.sent_pkts):
            _, _, seq_not_acked, _, _, _, _, _ = read_header(pkt)
            if acked_pkt > seq_not_acked:
                max_idx = i
        return 

    def _ack_pkt(self, ack_no):
        if len(self.sent_pkts) == 0:
            return
        self.cwnd += 1
        idx = self._get_idx(ack_no)
        _, t0 = self.sent_pkts[idx]
        del self.sent_pkts[:idx + 1]
        if t0 is not None:
            self.timeout_interval = self.timeout_interval(t0, time.time())
        if len(self.sent_pkts) == 0:
            self.timer.cancel()
            self._send_window()    
    
    def _rdt_rcv(self, seq_no, ack_no, flags, payload):
        # TODO: trate aqui o recebimento de segmentos provenientes da camada de rede.
        # Chame self.callback(self, dados) para passar dados para a camada de aplicação após
        # garantir que eles não sejam duplicados e que tenham sido recebidos em ordem.
        print('recebido payload: %r' % payload)

        if (flags & FLAGS_ACK) == FLAGS_ACK and ack_no > self.seq_no_base:
            self.seq_no_base = ack_no
            if self.pacotes_sem_ack:
                self.timeout_interval()
                self.timer.cancel()
                self.pacotes_sem_ack.pop(0)
                if self.pacotes_sem_ack:
                    self.timer = asyncio.get_event_loop().call_later(self.timeoutInterval, self._timer)

        #Lidando com o Passo 2 aqui
        if (flags & FLAGS_FIN) == FLAGS_FIN:
            payload = b''
            self.ack_no += 1
        elif len(payload) <= 0:
            return

        if seq_no != self.ack_no:
            return
        self.callback(self, payload)
        self.ack_no += len(payload)

        dst_addr, dst_port, src_addr, src_port = self.id_conexao

        segmento = make_header(src_port, dst_port, self.seq_no_base, self.ack_no, FLAGS_ACK)
        segmento_checksum_corrigido = fix_checksum(segmento, src_addr, dst_addr)
        self.servidor.rede.enviar(segmento_checksum_corrigido, dst_addr)
    # Os métodos abaixo fazem parte da API

    def registrar_recebedor(self, callback):
        """
        Usado pela camada de aplicação para registrar uma função para ser chamada
        sempre que dados forem corretamente recebidos
        """
        self.callback = callback

    def _send_window(self):
        if len(self.pktsQ) == 0:
            return
        i = 0
        while i < self.cwnd and len(self.pktsQ) != 0:
            package = self.pktsQ.pop(0)
            self.sent_pkts.append((package, time.time()))
            _, _, seq, ack, _, _, _, _ = read_header(package)
            self.servidor.rede.enviar(package, self.dst_addr)
            i += 1
        if self.timer is not None:
            self.timer.cancel()
        self.timer = asyncio.get_event_loop().call_later(self.timeout_interval, self._timeout)

    def enviar(self, dados):
        """
        Usado pela camada de aplicação para enviar dados
        """
        # TODO: implemente aqui o envio de dados.
        # Chame self.servidor.rede.enviar(segmento, dest_addr) para enviar o segmento
        # que você construir para a camada de rede.

        #Passo 3 
        dst_addr, dst_port, src_addr, src_port = self.id_conexao

        flags = 0 | FLAGS_ACK

        for i in range(int(len(dados)/MSS)):
            ini = i*MSS
            fim = min(len(dados), (i+1)*MSS)

            payload = dados[ini:fim]

            segmento = make_header(src_port, dst_port, self.seq_no, self.ack_no, flags)
            segmento_checksum_corrigido = fix_checksum(segmento+payload, src_addr, dst_addr)
            
            self.servidor.rede.enviar(segmento_checksum_corrigido, dst_addr)
            self.timer = asyncio.get_event_loop().call_later(self.timeoutInterval, self._timer)
            self.pacotes_sem_ack.append( [segmento_checksum_corrigido, len(payload), dst_addr, round(time(), 5)] )

            # Atualizando seq_no com os dados recém enviados
            self.seq_no += len(payload)   

    def fechar(self):
        """
        Usado pela camada de aplicação para fechar a conexão
        """
        # TODO: implemente aqui o fechamento de conexão
        #Passo 4
        package_header = make_header(
            self.src_port, self.dst_port, self.seq_no + 1, self.ack_no, FLAGS_FIN
        )
        package = fix_checksum(package_header, self.src_addr, self.dst_addr)
        self.servidor.rede.enviar(package, self.dst_addr)
        self.servidor.close(self.id_conexao)
        pass