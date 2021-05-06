package icmp

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"
)

const (
	icmpv4EchoRequest = 8
	icmpv4EchoReply   = 0
	icmpv6EchoRequest = 128
	icmpv6EchoReply   = 129
)

// icmpMessage Estrutura para guardar as informações do pacote que será enviado
type icmpMessage struct {
	Type     int             // type
	Code     int             // code
	ID       int             // id
	Seq      int             // seq
	Checksum int             // checksum
	Body     icmpMessageBody // body
}

// imcpEcho Estrutura para guardar as informações do pacote que será recebido
type icmpEcho struct {
	ID   int    // identifier
	Seq  int    // sequence number
	Data []byte // data
}

type icmpMessageBody interface {
	len() int
	marshal() ([]byte, error)
}

// CheckPing Responsavel por checar o ping do IP fornecido
func CheckPing(ip string, numPkg int, codigo int) (string, int, float64, float64, float64, error) {

	var (
		pkgLoss, pkgReceived     int
		minTts, maxTts, mediaTts float64
		msg                      string
		timeout                  = 3
	)

	for i := 1; i <= numPkg; i++ {
		timePackage, err := sendPackage(ip, timeout, codigo, i)
		if err != nil {
			if strings.Contains(err.Error(), "operation not permitted") {
				return "", 0, 0, 0, 0, errors.New("Operação não permitida!")
			}
			pkgLoss++
		} else {
			mediaTts += timePackage
			pkgReceived++
			if timePackage < minTts || i == 1 {
				minTts = timePackage
			}
			if timePackage > maxTts {
				maxTts = timePackage
			}
			time.Sleep(1*time.Second - time.Duration(timePackage))
		}
	}
	if pkgReceived > 0 {
		mediaTts = mediaTts / float64(pkgReceived)
	}
	msg = fmt.Sprintf("Pacote Enviado: %v | Pacote Recebido: %v | Pacote Perdido: %v", numPkg, pkgReceived, pkgLoss)
	if pkgLoss != numPkg {
		msg += fmt.Sprintf(" | Média do Tempo: %.3f", mediaTts)
	}

	return msg, pkgLoss, minTts, mediaTts, maxTts, nil
}

// sendPackage Envia um pacote de ping para o endereço fornecido
func sendPackage(address string, timeout, code, n int) (float64, error) {

	IPAddr, err := net.ResolveIPAddr("ip", address)
	if err != nil {
		return 0, err
	}

	conn, err := net.Dial("ip:icmp", IPAddr.IP.String())
	if err != nil {
		return 0, err
	}

	conn.SetDeadline(time.Now().Add(time.Duration(timeout) * time.Second))
	defer conn.Close()

	var typ int
	if net.ParseIP(IPAddr.IP.String()).To4() != nil {
		typ = icmpv4EchoRequest
	} else {
		typ = icmpv6EchoRequest
	}
	xid, xseq := code, n+1
	dataMsg := bytes.Repeat([]byte("[ICMP c019]"), 0)
	wb, err := (&icmpMessage{
		Type: typ, Code: 0,
		Body: &icmpEcho{
			ID: xid, Seq: xseq,
			Data: dataMsg,
		},
	}).marshal()
	if err != nil {
		return 0, err
	}
	beginTime := float64(time.Now().UnixNano())
	if _, err := conn.Write(wb); err != nil {
		return 0, err
	}
	rb := make([]byte, 20+len(wb))
	for {
		if _, err := conn.Read(rb); err != nil {
			return 0, err
		}
		m, err := parseICMPMessage(ipPayload(rb))
		if err != nil {
			return 0, err
		}
		if m.ID == xid && m.Seq == xseq {
			if m.Type == 0 && m.Code == 0 {
				finsihTime := (float64(time.Now().UnixNano()) - beginTime) / float64(time.Millisecond)
				return finsihTime, nil
			}
			return 0, err
		}
	}
}

func (m *icmpMessage) marshal() ([]byte, error) {
	b := []byte{byte(m.Type), byte(m.Code), 0, 0}
	if m.Body != nil && m.Body.len() != 0 {
		mb, err := m.Body.marshal()
		if err != nil {
			return nil, err
		}
		b = append(b, mb...)
	}
	switch m.Type {
	case icmpv6EchoRequest, icmpv6EchoReply:
		return b, nil
	}
	csumcv := len(b) - 1 // checksum coverage
	s := uint32(0)
	for i := 0; i < csumcv; i += 2 {
		s += uint32(b[i+1])<<8 | uint32(b[i])
	}
	if csumcv&1 == 0 {
		s += uint32(b[csumcv])
	}
	s = s>>16 + s&0xffff
	s = s + s>>16

	b[2] ^= byte(^s & 0xff)
	b[3] ^= byte(^s >> 8)
	return b, nil
}

func parseICMPMessage(b []byte) (*icmpMessage, error) {
	msglen := len(b)
	if msglen < 4 {
		return nil, errors.New("Mensagem muito curta")
	}
	m := &icmpMessage{Type: int(b[0]), Code: int(b[1]), Checksum: int(b[2])<<8 | int(b[3]), ID: int(b[4])<<8 | int(b[5]), Seq: int(b[7])}
	if msglen > 4 {
		var err error
		switch m.Type {
		case icmpv4EchoRequest, icmpv4EchoReply, icmpv6EchoRequest, icmpv6EchoReply:
			m.Body, err = parseICMPEcho(b[4:])
			if err != nil {
				return nil, err
			}
		}
	}
	return m, nil
}

func (p *icmpEcho) len() int {
	if p == nil {
		return 0
	}
	return 4 + len(p.Data)
}

func (p *icmpEcho) marshal() ([]byte, error) {
	b := make([]byte, 4+len(p.Data))
	b[0], b[1] = byte(p.ID>>8), byte(p.ID&0xff)
	b[2], b[3] = byte(p.Seq>>8), byte(p.Seq&0xff)
	copy(b[4:], p.Data)
	return b, nil
}

func parseICMPEcho(b []byte) (*icmpEcho, error) {
	bodylen := len(b)
	p := &icmpEcho{ID: int(b[0])<<8 | int(b[1]), Seq: int(b[2])<<8 | int(b[3])}
	if bodylen > 4 {
		p.Data = make([]byte, bodylen-4)
		copy(p.Data, b[4:])
	}
	return p, nil
}

func ipPayload(b []byte) []byte {
	if len(b) < 20 {
		return b
	}
	hdrlen := int(b[0]&0x0f) << 2
	return b[hdrlen:]
}
