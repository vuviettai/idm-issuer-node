package network

import (
	"context"
	"crypto/x509"
	"fmt"
	"os"
	"path"
	"time"

	"github.com/hyperledger/fabric-gateway/pkg/client"
	"github.com/hyperledger/fabric-gateway/pkg/hash"
	"github.com/hyperledger/fabric-gateway/pkg/identity"
	"github.com/polygonid/sh-id-platform/internal/log"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

type FabricSetting struct {
	OrgName          string `yaml:"orgName"`
	OrgDomain        string `yaml:"orgDomain"`
	OrgMSP           string `yaml:"orgMSP"`
	OrgUsername      string `yaml:"orgUsername"`
	OrgPeerEndpoint  string `yaml:"orgPeerEndpoint"`
	OrgPeerName      string `yaml:"orgPeerName"`
	OrgPeerHostAlias string `yaml:"orgPeerHostAlias"`
	OrgCryptoPath    string `yaml:"orgCryptoPath"`
	ChainCode        string `yaml:"chainCode"`
	ChannelID        string `yaml:"channelID"`
	NetworkFlag      byte   `yaml:"networkFlag"`
	ChainID          string `yaml:"chainID"`
	Method           string `yaml:"method"`
}
type FabricSettings map[string]FabricSetting
type FabricClient struct {
	setting  *FabricSetting
	identity *identity.X509Identity
	sign     identity.Sign
}

func CreateFabricClient(ctx context.Context, setting *FabricSetting) (*FabricClient, error) {
	userCertPath := fmt.Sprintf("%s/users/%s@%s/msp/signcerts", setting.OrgCryptoPath, setting.OrgUsername, setting.OrgDomain)
	userKeyPath := fmt.Sprintf("%s/users/%s@%s/msp/keystore", setting.OrgCryptoPath, setting.OrgUsername, setting.OrgDomain)
	identity := newIdentity(userCertPath, setting.OrgMSP)
	sign := newSign(userKeyPath)

	return &FabricClient{
		setting:  setting,
		identity: identity,
		sign:     sign,
	}, nil
}
func (f *FabricClient) Connect(ctx context.Context) (*grpc.ClientConn, *client.Gateway, *client.Contract, error) {
	peerHost := fmt.Sprintf("%s.%s", f.setting.OrgPeerName, f.setting.OrgDomain)
	tlsCertPath := fmt.Sprintf("%s/peers/%s/tls/ca.crt", f.setting.OrgCryptoPath, peerHost)
	// Create a gRPC connection to the Gateway server
	grpcClient := newGrpcConnection(tlsCertPath, peerHost, f.setting.OrgPeerEndpoint)
	// Create a Gateway connection for a specific client identity
	gateway, err := client.Connect(
		f.identity,
		client.WithSign(f.sign),
		client.WithHash(hash.SHA256),
		client.WithClientConnection(grpcClient),
		// Default timeouts for different gRPC calls
		client.WithEvaluateTimeout(5*time.Second),
		client.WithEndorseTimeout(15*time.Second),
		client.WithSubmitTimeout(5*time.Second),
		client.WithCommitStatusTimeout(1*time.Minute),
	)
	if err != nil {
		log.Error(ctx, "failed to create gateway connection: %+v", err)
		return nil, nil, nil, err
	}
	network := gateway.GetNetwork(f.setting.ChannelID)
	contract := network.GetContract(f.setting.ChainCode)
	return grpcClient, gateway, contract, nil
}

// newGrpcConnection creates a gRPC connection to the Gateway server.
func newGrpcConnection(tlsCertPath string, peerHost string, peerEndpoint string) *grpc.ClientConn {
	certificatePEM, err := os.ReadFile(tlsCertPath)
	if err != nil {
		panic(fmt.Errorf("failed to read TLS certifcate file: %w", err))
	}

	certificate, err := identity.CertificateFromPEM(certificatePEM)
	if err != nil {
		panic(err)
	}

	certPool := x509.NewCertPool()
	certPool.AddCert(certificate)
	transportCredentials := credentials.NewClientTLSFromCert(certPool, peerHost)

	connection, err := grpc.NewClient(peerEndpoint, grpc.WithTransportCredentials(transportCredentials))
	if err != nil {
		panic(fmt.Errorf("failed to create gRPC connection: %w", err))
	}

	return connection
}

// newIdentity creates a client identity for this Gateway connection using an X.509 certificate.
func newIdentity(userCertPath string, mspID string) *identity.X509Identity {
	certificatePEM, err := readFirstFile(userCertPath)
	if err != nil {
		panic(fmt.Errorf("failed to read certificate file: %w", err))
	}

	certificate, err := identity.CertificateFromPEM(certificatePEM)
	if err != nil {
		panic(err)
	}

	id, err := identity.NewX509Identity(mspID, certificate)
	if err != nil {
		panic(err)
	}

	return id
}

// newSign creates a function that generates a digital signature from a message digest using a private key.
func newSign(keyPath string) identity.Sign {
	privateKeyPEM, err := readFirstFile(keyPath)
	if err != nil {
		panic(fmt.Errorf("failed to read private key file: %w", err))
	}

	privateKey, err := identity.PrivateKeyFromPEM(privateKeyPEM)
	if err != nil {
		panic(err)
	}

	sign, err := identity.NewPrivateKeySign(privateKey)
	if err != nil {
		panic(err)
	}

	return sign
}

func readFirstFile(dirPath string) ([]byte, error) {
	dir, err := os.Open(dirPath)
	if err != nil {
		return nil, err
	}

	fileNames, err := dir.Readdirnames(1)
	if err != nil {
		return nil, err
	}

	return os.ReadFile(path.Join(dirPath, fileNames[0]))
}
