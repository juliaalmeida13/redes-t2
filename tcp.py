import asyncio
from curses import flash
from random import randint
from tcputils import *
import struct

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

        #Passo 1

        if (flags & FLAGS_SYN) == FLAGS_SYN:
            # A flag SYN estar setada significa que é um cliente tentando estabelecer uma conexão nova
            # TODO: talvez você precise passar mais coisas para o construtor de conexão            
            conexao = self.conexoes[id_conexao] = Conexao(self, id_conexao)
            # TODO: você precisa fazer o handshake aceitando a conexão. Escolha se você acha melhor
            # fazer aqui mesmo ou dentro da classe Conexao.
            flags = flash & 0
            flags = flags or ( FLAGS_SYN or FLAGS_ACK)

            conexao.seq_no = randint(0, 0xffff)
            conexao.ack_no = seq_no + 1
            src_port, dst_port = dst_port, src_port
            src_addr, dst_addr = dst_addr, src_addr

            seg = make_header(src_port,dst_port,conexao.seq_no,conexao.ack_no, flags)
            seg_checksum_ver = fix_checksum(seg, src_addr, dst_addr)
            self.rede.enviar(seg_checksum_ver, dst_addr)

            conexao.seq_no = conexao.seq_no  + 1
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
        self.timer = asyncio.get_event_loop().call_later(1, self._exemplo_timer)  # um timer pode ser criado assim; esta linha é só um exemplo e pode ser removida
        #Passo 1
        self.seq_no = None
        self.ack_no = None
        self.seq_no_base = None
        #self.timer.cancel()   # é possível cancelar o timer chamando esse método; esta linha é só um exemplo e pode ser removida

    def _exemplo_timer(self):
        # Esta função é só um exemplo e pode ser removida
        print('Este é um exemplo de como fazer um timer')

    def _rdt_rcv(self, seq_no, ack_no, flags, payload):
        # TODO: trate aqui o recebimento de segmentos provenientes da camada de rede.
        # Chame self.callback(self, dados) para passar dados para a camada de aplicação após
        # garantir que eles não sejam duplicados e que tenham sido recebidos em ordem.
        print('recebido payload: %r' % payload)

    # Os métodos abaixo fazem parte da API

    def registrar_recebedor(self, callback):
        """
        Usado pela camada de aplicação para registrar uma função para ser chamada
        sempre que dados forem corretamente recebidos
        """
        self.callback = callback

    def enviar(self, dados):
        """
        Usado pela camada de aplicação para enviar dados
        """
        # TODO: implemente aqui o envio de dados.
        # Chame self.servidor.rede.enviar(segmento, dest_addr) para enviar o segmento
        # que você construir para a camada de rede.
        pass

    def fechar(self):
        """
        Usado pela camada de aplicação para fechar a conexão
        """
        # TODO: implemente aqui o fechamento de conexão
        pass
