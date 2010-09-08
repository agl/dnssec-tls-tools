package main

import (
	"asn1"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"flag"
	"http"
	"io"
	"io/ioutil"
	"json"
	"log"
	"net"
	"os"
	"strconv"
	"time"
)

var port *int = flag.Int("port", 5000, "HTTP port number to listen on")

// TLS handshake message types.
const (
	typeClientHello        uint8 = 1
)

// TLS extension numbers
var (
	extensionServerName    uint16 = 0
	extensionStatusRequest uint16 = 5
	extensionNextProtoNeg  uint16 = 13172 // not IANA assigned
)

const (
	kCertificate = "CERTIFICATE"
)

type clientHelloMsg struct {
	raw                []byte
	vers               uint16
	random             []byte
	sessionId          []byte
	cipherSuites       []uint16
	compressionMethods []uint8
	nextProtoNeg       bool
	serverName         string
	ocspStapling       bool
}

func (m *clientHelloMsg) marshal() []byte {
	if m.raw != nil {
		return m.raw
	}

	length := 2 + 32 + 1 + len(m.sessionId) + 2 + len(m.cipherSuites)*2 + 1 + len(m.compressionMethods)
	numExtensions := 0
	extensionsLength := 0
	if m.nextProtoNeg {
		numExtensions++
	}
	if m.ocspStapling {
		extensionsLength += 1 + 2 + 2
		numExtensions++
	}
	if len(m.serverName) > 0 {
		extensionsLength += 5 + len(m.serverName)
		numExtensions++
	}
	if numExtensions > 0 {
		extensionsLength += 4 * numExtensions
		length += 2 + extensionsLength
	}

	x := make([]byte, 4+length)
	x[0] = typeClientHello
	x[1] = uint8(length >> 16)
	x[2] = uint8(length >> 8)
	x[3] = uint8(length)
	x[4] = uint8(m.vers >> 8)
	x[5] = uint8(m.vers)
	copy(x[6:38], m.random)
	x[38] = uint8(len(m.sessionId))
	copy(x[39:39+len(m.sessionId)], m.sessionId)
	y := x[39+len(m.sessionId):]
	y[0] = uint8(len(m.cipherSuites) >> 7)
	y[1] = uint8(len(m.cipherSuites) << 1)
	for i, suite := range m.cipherSuites {
		y[2+i*2] = uint8(suite >> 8)
		y[3+i*2] = uint8(suite)
	}
	z := y[2+len(m.cipherSuites)*2:]
	z[0] = uint8(len(m.compressionMethods))
	copy(z[1:], m.compressionMethods)

	z = z[1+len(m.compressionMethods):]
	if numExtensions > 0 {
		z[0] = byte(extensionsLength >> 8)
		z[1] = byte(extensionsLength)
		z = z[2:]
	}
	if m.nextProtoNeg {
		z[0] = byte(extensionNextProtoNeg >> 8)
		z[1] = byte(extensionNextProtoNeg)
		// The length is always 0
		z = z[4:]
	}
	if len(m.serverName) > 0 {
		z[0] = byte(extensionServerName >> 8)
		z[1] = byte(extensionServerName)
		l := len(m.serverName) + 5
		z[2] = byte(l >> 8)
		z[3] = byte(l)
		z = z[4:]

		// RFC 3546, section 3.1
		//
		// struct {
		//     NameType name_type;
		//     select (name_type) {
		//         case host_name: HostName;
		//     } name;
		// } ServerName;
		//
		// enum {
		//     host_name(0), (255)
		// } NameType;
		//
		// opaque HostName<1..2^16-1>;
		//
		// struct {
		//     ServerName server_name_list<1..2^16-1>
		// } ServerNameList;

		z[0] = byte((len(m.serverName) + 3) >> 8)
		z[1] = byte(len(m.serverName) + 3)
		z[3] = byte(len(m.serverName) >> 8)
		z[4] = byte(len(m.serverName))
		copy(z[5:], []byte(m.serverName))
		z = z[l:]
	}
	if m.ocspStapling {
		// RFC 4366, section 3.6
		z[0] = byte(extensionStatusRequest >> 8)
		z[1] = byte(extensionStatusRequest)
		z[2] = 0
		z[3] = 5
		z[4] = 1 // OCSP type
		// Two zero valued uint16s for the two lengths.
		z = z[9:]
	}

	m.raw = x

	return x
}

type certificateMsg struct {
	raw          []byte
	certificates [][]byte
}

func (m *certificateMsg) unmarshal(data []byte) bool {
	if len(data) < 7 {
		return false
	}

	m.raw = data
	certsLen := uint32(data[4])<<16 | uint32(data[5])<<8 | uint32(data[6])
	if uint32(len(data)) != certsLen+7 {
		return false
	}

	numCerts := 0
	d := data[7:]
	for certsLen > 0 {
		if len(d) < 4 {
			return false
		}
		certLen := uint32(d[0])<<24 | uint32(d[1])<<8 | uint32(d[2])
		if uint32(len(d)) < 3+certLen {
			return false
		}
		d = d[3+certLen:]
		certsLen -= 3 + certLen
		numCerts++
	}

	m.certificates = make([][]byte, numCerts)
	d = data[7:]
	for i := 0; i < numCerts; i++ {
		certLen := uint32(d[0])<<24 | uint32(d[1])<<8 | uint32(d[2])
		m.certificates[i] = d[3 : 3+certLen]
		d = d[3+certLen:]
	}

	return true
}

type tlsConn struct {
	net.Conn
	handshakeData []byte
	recordsRead uint
}

func readHandshake(conn *tlsConn) ([]byte, os.Error) {
	if conn.recordsRead > 16 {
		return nil, os.ErrorString("Read too many records")
	}

	if len(conn.handshakeData) >= 4 {
		x := conn.handshakeData
		l := uint32(x[1]) << 16 | uint32(x[2]) << 8 | uint32(x[3])
		if uint32(len(x)) >= 4 + l {
			// We have a handshake message ready
			conn.handshakeData = conn.handshakeData[4 + l:]
			return x[0:4 + l], nil
		}
	}

	// Read a TLS record in
	var header [5]byte
	_, err := io.ReadFull(conn, header[0:])
	if err != nil {
		return nil, err
	}

	if header[0] != 0x16 {
		return nil, os.ErrorString("Found non-handshake record")
	}
	l := uint32(header[3]) << 8 | uint32(header[4])
	newData := make([]byte, uint32(len(conn.handshakeData)) + l)
	copy(newData, conn.handshakeData)
	_, err = io.ReadFull(conn, newData[len(conn.handshakeData):])
	if err != nil {
		return nil, err
	}

	conn.handshakeData = newData
	conn.recordsRead++
	return readHandshake(conn)
}

func FetchCertificate(domain string) (pemData []byte, ok bool) {
	ok = false

	log.Stdoutf("Fetching for %s", domain)

	conn, err := net.Dial("tcp", "", domain + ":443")
	if err != nil {
		log.Stderrf("Connection error for %s: %s", domain, err)
		return
	}
	defer conn.Close()
	conn.SetTimeout(5 * 1000 * 1000 * 1000)

	clientHello := clientHelloMsg{
		vers: 0x0301,
		random: []byte{
			0, 0, 0, 0, 0, 0, 0, 0,
			0, 0, 0, 0, 0, 0, 0, 0,
			0, 0, 0, 0, 0, 0, 0, 0,
			0, 0, 0, 0, 0, 0, 0, 0,
		},
		cipherSuites: []uint16{
			4,       // TLS_RSA_WITH_RC4_128_MD5
			5,       // TLS_RSA_WITH_RC4_128_SHA
			0x0a,    // TLS_RSA_WITH_3DES_EDE_CBC_SHA
			0x2f,    // TLS_RSA_WITH_AES_128_CBC_SHA
		},
		compressionMethods: []byte{0},
		serverName: domain,
	}

	bytes := clientHello.marshal()
	header := [5]byte{0x16, 3, 1, uint8(len(bytes) >> 8), uint8(len(bytes))}
	conn.Write(header[0:])
	conn.Write(bytes)
	tls := new(tlsConn)
	tls.Conn = conn
	msg, err := readHandshake(tls)
	if err != nil {
		log.Stderrf("Error reading first handshake from %s: %s", domain, err)
		return
	}
	// discard the ServerHello
	msg, err = readHandshake(tls)
	if err != nil {
		log.Stderrf("Error reading Certificate message from %s: %s", domain, err)
		return
	}

	if msg[0] != 11 {
		log.Stderrf("Expected a Certificate message from %s, got %d: %s", domain, msg[0])
		return
	}

	var certMsg certificateMsg
	if !certMsg.unmarshal(msg) || len(certMsg.certificates) < 1 {
		log.Stderrf("Error parsing Certificate message from %s", domain)
		return
	}

	return pem.EncodeToMemory(&pem.Block{Type: kCertificate, Bytes: certMsg.certificates[0]}), true
}

func HandleRoot(c *http.Conn, req *http.Request) {
	contents, err := ioutil.ReadFile("root.html")
	if err != nil {
		c.SetHeader("Content-Type", "text/plain")
		c.SetHeader("Cache-control", "no-cache")
		c.WriteHeader(http.StatusInternalServerError)
		c.Write([]byte(err.String()))
		return
	}

	c.SetHeader("Content-Type", "text/html; charset=utf-8")
	c.SetHeader("Cache-control", "public")
	c.Write(contents)
}

type certificate struct {
	TBSCertificate tbsCertificate
}

type tbsCertificate struct {
	Version int "optional,explicit,default:1,tag:0"
	SerialNumber asn1.RawValue
	SignatureAlgorithm algorithmIdentifier
	Issuer rdnSequence
	Validity validity
	Subject rdnSequence
	PublicKey asn1.RawValue
}

type algorithmIdentifier struct {
	Algorithm asn1.ObjectIdentifier
}

type rdnSequence []relativeDistinguishedNameSET

type relativeDistinguishedNameSET []attributeTypeAndValue

type attributeTypeAndValue struct {
	Type  asn1.ObjectIdentifier
	Value interface{}
}

type validity struct {
	NotBefore, NotAfter *time.Time
}

func sha1Hash(in []byte) []byte {
	s := sha1.New()
	s.Write(in)
	return s.Sum()
}

func sha256Hash(in []byte) []byte {
	s := sha256.New()
	s.Write(in)
	return s.Sum()
}

func base64Encode(in []byte) string {
	buf := make([]byte, base64.StdEncoding.EncodedLen(len(in)))
	base64.StdEncoding.Encode(buf, in)
	return string(buf)
}

type parseResult struct {
	certStrings []string
	certSHA1, certSHA256, keySHA1, keySHA256 string
}

func buildRecord(pkix, hashFunc bool, certSHA1, certSHA256 []byte) string {
	h := certSHA1
	if hashFunc {
		h = certSHA256
	}
	d := make([]byte, 2 + len(h))
	copy(d[2:], h)
	if pkix {
		d[1] = 1
	}
	if hashFunc {
		d[0] = 2  // RFC 4043, App A.2
	} else {
		d[0] = 1
	}

	return base64Encode(d)
}

func HandleParse(c *http.Conn, req *http.Request) {
	c.SetHeader("Cache-control", "no-cache")
	if req.ContentLength == 0 || req.ContentLength > 16384 {
		log.Stderrf("Rejecting bad parse body length: %d", req.ContentLength)
		c.WriteHeader(http.StatusInternalServerError)
		return
	}
	pemBytes := make([]byte, req.ContentLength)
	_, err := io.ReadFull(req.Body, pemBytes)
	if err != nil {
		c.WriteHeader(http.StatusInternalServerError)
		return
	}

	block, _ := pem.Decode(pemBytes)
	if block == nil || block.Type != kCertificate {
		c.WriteHeader(http.StatusInternalServerError)
		return
	}

	c.SetHeader("Content-Type", "application/json")

	var cert certificate
	_, err = asn1.Unmarshal(&cert, block.Bytes)
	if err != nil {
		log.Stderrf("Error decoding ASN.1: %s", err)
		c.WriteHeader(http.StatusInternalServerError)
		return
	}

	var result parseResult
	key := cert.TBSCertificate.PublicKey.FullBytes
	keySHA1 := sha1Hash(key)
	keySHA256 := sha256Hash(key)
	certSHA1 := sha1Hash(block.Bytes)
	certSHA256 := sha256Hash(block.Bytes)

	result.certStrings = make([]string, 4)
	for i := 0; i < 4; i++ {
		result.certStrings[i] = buildRecord(i & 2 != 0, i & 1 != 0, certSHA1, certSHA256)
	}

	result.keySHA1 = hex.EncodeToString(keySHA1)
	result.keySHA256 = hex.EncodeToString(keySHA256)
	result.certSHA1 = hex.EncodeToString(certSHA1)
	result.certSHA256 = hex.EncodeToString(certSHA256)

	out, err := json.Marshal(result)
	if err != nil {
		log.Stderrf("JSON error: %s", err)
		c.WriteHeader(http.StatusInternalServerError)
		return
	}

	c.Write(out)

	return
}

func HandleFetch(c *http.Conn, req *http.Request) {
	c.SetHeader("Cache-control", "no-cache")
	c.SetHeader("Content-Type", "text/plain")
	domain := req.URL.Path[7:]
	pem, ok := FetchCertificate(domain)
	if !ok {
		c.WriteHeader(http.StatusInternalServerError)
		return
	}
	c.Write(pem)
}

func main() {
	http.HandleFunc("/", HandleRoot)
	http.HandleFunc("/fetch/", HandleFetch)
	http.HandleFunc("/parse", HandleParse)
	err := http.ListenAndServe(":" + strconv.Itoa(*port), nil)
	if err != nil {
		log.Exit("ListenAndServe: ", err.String())
	}
}
