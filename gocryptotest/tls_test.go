package unittest

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"io/ioutil"
	"log"
	"net"
	"testing"

	gmtls "github.com/ChainSQL/gm-crypto/tls"
	gmx509 "github.com/ChainSQL/gm-crypto/x509"
)

var DefaultTLSCipherSuites = []uint16{
	tls.ECDHE_SM2_WITH_SMS4_GCM_SM3,
	gmtls.GMTLS_SM2_WITH_SM4_SM3,
}

var (
	//AuthType = tls.RequestClientCert //fabric单证书模式
	GmAuthType       = gmtls.RequireAndVerifyClientCert //fabric双证书模式
	AuthType         = tls.RequireAndVerifyClientCert   //fabric双证书模式
	SERVER_CA        = "../tls/gmcert/ca.crt"           //服务端根证书
	SERVER_SIGN_CERT = "../tls/gmcert/server.crt"       //服务端签名证书
	SERVER_SIGN_KEY  = "../tls/gmcert/server.key"       //服务端签名私钥
	SERVER_ENC_CERT  = "../tls/gmcert/server.crt"       //服务端加密证书
	SERVER_ENC_KEY   = "../tls/gmcert/server.key"       //服务端加密私钥
	CLIENT_CA        = "../tls/gmcert/ca.crt"           //客户端根证书
	CLIENT_SIGN_CERT = "../tls/gmcert/client.crt"       //客户端签名证书
	CLIENT_SIGN_KEY  = "../tls/gmcert/client.key"       //客户端签名私钥
	CLIENT_ENC_CERT  = "../tls/gmcert/client.crt"       //客户端加密证书
	CLIENT_ENC_KEY   = "../tls/gmcert/client.key"       //客户端签名私钥
)

func TestTLSServer(t *testing.T) {
	log.Println("启动三方包gm server")
	go runthreeserver(t)
	log.Println("启动标准库gm server")
	runstandardserver(t)
}

func TestTLSClient(t *testing.T) {
	log.Println("启动三方包gm client")
	runthreeclient(t)
	log.Println("启动标准库gm client")
	runstandardclient(t)
}

func handleConnection(conn net.Conn) {
	defer conn.Close()
	r := bufio.NewReader(conn)
	for {
		msg, err := r.ReadString('\n')
		if err != nil {
			log.Println(err)
			return
		}
		log.Println(msg)
		n, err := conn.Write([]byte("server pong!\n"))
		if err != nil {
			log.Println(n, err)
			return
		}
	}
}

//运行三方包方式server
func runthreeserver(t *testing.T) {
	signcert, err := gmtls.LoadX509KeyPair(SERVER_SIGN_CERT, SERVER_SIGN_KEY)
	if err != nil {
		t.Fatal(err)
	}
	caPem, err := ioutil.ReadFile(SERVER_CA)
	if err != nil {
		t.Fatalf("Failed to load ca cert %v", err)
	}
	certpool := gmx509.NewCertPool()
	certpool.AppendCertsFromPEM(caPem)
	c := &gmtls.Config{
		GMSupport:    &gmtls.GMSupport{},
		ClientAuth:   GmAuthType,
		Certificates: []gmtls.Certificate{signcert /*, enccert*/},
		ClientCAs:    certpool,
		CipherSuites: DefaultTLSCipherSuites,
	}

	ln, err := gmtls.Listen("tcp", ":6666", c)
	if err != nil {
		t.Fatal(err)
	}
	log.Printf("Start to three server address:%v  clientAuthType=%v\n", ln.Addr(), AuthType)
	defer ln.Close()
	for {
		conn, err := ln.Accept()
		if err != nil {
			t.Fatal(err)
			continue
		}
		go handleConnection(conn)
	}
}

func runthreeclient(t *testing.T) {
	caPem, err := ioutil.ReadFile(CLIENT_CA)
	if err != nil {
		t.Fatal(err)
	}
	cp := gmx509.NewCertPool()
	if !cp.AppendCertsFromPEM(caPem) {
		t.Fatal("credentials: failed to append certificates")
	}
	signcert, err := gmtls.LoadX509KeyPair(CLIENT_SIGN_CERT, CLIENT_SIGN_KEY)
	if err != nil {
		t.Fatal("Failed to Load client keypair")
	}
	//enccert, err := LoadX509KeyPair(CLIENT_ENC_CERT, CLIENT_ENC_KEY)
	//if err != nil {
	//	log.Fatal("Failed to Load client keypair")
	//}
	c := &gmtls.Config{
		ServerName:   "peer0.org1.example.com",
		GMSupport:    &gmtls.GMSupport{},
		Certificates: []gmtls.Certificate{signcert /*, enccert*/},
		RootCAs:      cp,
		CipherSuites: DefaultTLSCipherSuites,
		//InsecureSkipVerify: true, // Client verifies server's cert if false, else skip.
	}
	serverAddress := "127.0.0.1:6666"
	log.Printf("start three client connect %s\n", serverAddress)
	conn, err := gmtls.Dial("tcp", serverAddress, c)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	n, err := conn.Write([]byte("three client write ping!\n"))
	if err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 100)
	n, err = conn.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	log.Println(string(buf[:n]))
}

//运行标准口方式server
func runstandardserver(t *testing.T) {
	signcert, err := tls.LoadX509KeyPair(SERVER_SIGN_CERT, SERVER_SIGN_KEY)
	if err != nil {
		t.Fatal(err)
	}
	caPem, err := ioutil.ReadFile(SERVER_CA)
	if err != nil {
		t.Fatalf("Failed to load ca gmcert %v", err)
	}
	certpool := x509.NewCertPool()
	certpool.AppendCertsFromPEM(caPem)
	c := &tls.Config{
		ClientAuth:   AuthType,
		Certificates: []tls.Certificate{signcert /*, enccert*/},
		ClientCAs:    certpool,
		CipherSuites: DefaultTLSCipherSuites,
	}

	ln, err := tls.Listen("tcp", ":5555", c)
	if err != nil {
		t.Fatal(err)
	}
	log.Printf("Start to standard server address:%v  clientAuthType=%v\n", ln.Addr(), AuthType)
	defer ln.Close()
	for {
		conn, err := ln.Accept()
		if err != nil {
			t.Fatal(err)
			continue
		}
		go handleConnection(conn)
	}
}

func runstandardclient(t *testing.T) {
	caPem, err := ioutil.ReadFile(CLIENT_CA)
	if err != nil {
		t.Fatal(err)
	}
	cp := x509.NewCertPool()
	if !cp.AppendCertsFromPEM(caPem) {
		t.Fatal("credentials: failed to append certificates")
	}
	signcert, err := tls.LoadX509KeyPair(CLIENT_SIGN_CERT, CLIENT_SIGN_KEY)
	if err != nil {
		t.Fatal("Failed to Load client keypair")
	}
	c := &tls.Config{
		MaxVersion:   tls.VersionTLS12,
		ServerName:   "peer0.org1.example.com",
		Certificates: []tls.Certificate{signcert /*, enccert*/},
		RootCAs:      cp,
		CipherSuites: DefaultTLSCipherSuites,
		//InsecureSkipVerify: true, // Client verifies server's gmcert if false, else skip.
	}
	serverAddress := "127.0.0.1:5555"
	log.Printf("start standard client connect %s\n", serverAddress)
	conn, err := tls.Dial("tcp", serverAddress, c)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	n, err := conn.Write([]byte("standard client write ping!\n"))
	if err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 100)
	n, err = conn.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	log.Println(string(buf[:n]))
}
