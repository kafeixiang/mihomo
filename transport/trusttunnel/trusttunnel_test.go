package trusttunnel

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/metacubex/mihomo/transport/vmess"
	"github.com/metacubex/sing/common/logger"
	M "github.com/metacubex/sing/common/metadata"
	"github.com/metacubex/sing/common/network"
	"github.com/metacubex/tls"
	"github.com/stretchr/testify/require"
)

type mockHandler struct{}

func (m *mockHandler) NewConnection(ctx context.Context, conn net.Conn, metadata M.Metadata) error {
	defer conn.Close()
	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil {
		return err
	}
	_, err = conn.Write(append([]byte("TT_ECHO:"), buf[:n]...))
	return err
}

func (m *mockHandler) NewPacketConnection(ctx context.Context, conn network.PacketConn, metadata M.Metadata) error {
	return nil
}

type stdDialer struct{}

func (d stdDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	var dialer net.Dialer
	return dialer.DialContext(ctx, network, address)
}

func (d stdDialer) ListenPacket(ctx context.Context, network, address string, rAddrPort netip.AddrPort) (net.PacketConn, error) {
	var lc net.ListenConfig
	return lc.ListenPacket(ctx, network, address)
}

func generateCertAndKey(t *testing.T) ([]byte, []byte) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"TrustTunnel Test"},
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"localhost"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	require.NoError(t, err)

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})
	return certPEM, keyPEM
}

func TestTrustTunnelServerClientE2E(t *testing.T) {
	certPEM, keyPEM := generateCertAndKey(t)
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	require.NoError(t, err)

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{"h2"},
	}

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer listener.Close()

	serverAddr := listener.Addr().String()

	service := NewService(ServiceOptions{
		Ctx:     context.Background(),
		Logger:  logger.NOP(),
		Handler: &mockHandler{},
	})
	service.UpdateUsers(map[string]string{
		"testuser": "testpassword123",
	})

	err = service.Start(listener, nil, tlsConfig)
	require.NoError(t, err)
	defer service.Close()

	client, err := NewClient(context.Background(), ClientOptions{
		Dialer:   stdDialer{},
		Server:   serverAddr,
		Username: "testuser",
		Password: "testpassword123",
		TLSConfig: &vmess.TLSConfig{
			Host:           "localhost",
			SkipCertVerify: true,
			NextProtos:     []string{"h2"},
		},
		QUIC:        false,
		HealthCheck: false,
	})
	require.NoError(t, err)

	conn, err := client.Dial(context.Background(), "echo.target:80")
	require.NoError(t, err)
	defer conn.Close()

	message := []byte("Hello TrustTunnel from Test")
	_, err = conn.Write(message)
	require.NoError(t, err)

	reply := make([]byte, 1024)
	n, err := conn.Read(reply)
	require.NoError(t, err)

	expected := append([]byte("TT_ECHO:"), message...)
	require.Equal(t, expected, reply[:n])
}
