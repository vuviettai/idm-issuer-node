package schema_test

import (
	"context"
	"testing"

	auth "github.com/iden3/go-iden3-auth/v2"
	authLoaders "github.com/iden3/go-iden3-auth/v2/loaders"
	"github.com/iden3/go-iden3-core/v2/w3c"
	"github.com/iden3/iden3comm/v2"
	"github.com/iden3/iden3comm/v2/packers"
	iden3commProtocol "github.com/iden3/iden3comm/v2/protocol"
	"github.com/polygonid/sh-id-platform/internal/cache"
	"github.com/polygonid/sh-id-platform/internal/config"
	"github.com/polygonid/sh-id-platform/internal/core/ports"
	"github.com/polygonid/sh-id-platform/internal/core/services"
	"github.com/polygonid/sh-id-platform/internal/db"
	"github.com/polygonid/sh-id-platform/internal/loader"
	"github.com/polygonid/sh-id-platform/internal/log"
	"github.com/polygonid/sh-id-platform/internal/network"
	"github.com/polygonid/sh-id-platform/internal/packagemanager"
	"github.com/polygonid/sh-id-platform/internal/providers"
	"github.com/polygonid/sh-id-platform/internal/pubsub"
	"github.com/polygonid/sh-id-platform/internal/repositories"
	"github.com/polygonid/sh-id-platform/internal/reversehash"
	"github.com/polygonid/sh-id-platform/internal/revocationstatus"
	"github.com/stretchr/testify/require"
)

// go test -timeout 30s -run ^TestProcess$ github.com/polygonid/sh-id-platform/internal/schema -v
func TestProcess(t *testing.T) {
	ctx := context.Background()
	cfg, err := config.Load()
	if err != nil {
		log.Error(ctx, "cannot load config", "err", err)
		return
	}
	// cfg := config.Configuration{
	// 	IPFS: config.IPFS{
	// 		GatewayURL: "https://ipfs.io",
	// 	},
	// 	SchemaCache: true,
	// 	Database: config.Database{
	// 		URL: "postgres://postgres:postgres@postgres:5432/platformid?sslmode=disable",
	// 	},
	// 	ServerUrl: "http://localhost:3001",
	// 	UniversalLinks: config.UniversalLinks{
	// 		BaseUrl: "https://wallet.privado.id",
	// 	},
	// 	KeyStore: config.KeyStore{
	// 		Address:                   "http://vault:8200",
	// 		BJJProvider:               "vault",
	// 		VaultUserPassAuthEnabled:  true,
	// 		VaultUserPassAuthPassword: "issuernodepwd",
	// 		TLSEnabled:                false,
	// 	},
	// }
	storage, err := db.NewStorage(cfg.Database.URL)
	if err != nil {
		log.Error(ctx, "cannot connect to database", "err", err)
		return
	}
	schemaLoader := loader.NewDocumentLoader(cfg.IPFS.GatewayURL, cfg.SchemaCache)
	vaultCfg := providers.Config{
		UserPassAuthEnabled: cfg.KeyStore.VaultUserPassAuthEnabled,
		Pass:                cfg.KeyStore.VaultUserPassAuthPassword,
		Address:             cfg.KeyStore.Address,
		Token:               cfg.KeyStore.Token,
		TLSEnabled:          cfg.KeyStore.TLSEnabled,
		CertPath:            cfg.KeyStore.CertPath,
	}
	keyStore, err := config.KeyStoreConfig(ctx, cfg, vaultCfg)
	if err != nil {
		log.Error(ctx, "cannot initialize key store", "err", err)
		return
	}

	cachex, err := cache.NewCacheClient(ctx, *cfg)
	if err != nil {
		log.Error(ctx, "cannot initialize cache", "err", err)
		return
	}
	ps, err := pubsub.NewPubSub(ctx, *cfg)
	if err != nil {
		log.Error(ctx, "cannot initialize pubsub", "err", err)
		return
	}
	reader, err := network.GetReaderFromConfig(cfg, ctx)
	if err != nil {
		log.Error(ctx, "cannot read network resolver file", "err", err)
		return
	}
	networkResolver, err := network.NewResolver(ctx, *cfg, keyStore, reader)
	if err != nil {
		log.Error(ctx, "failed initialize network resolver", "err", err)
		return
	}

	rhsFactory := reversehash.NewFactory(*networkResolver, reversehash.DefaultRHSTimeOut)
	identityRepository := repositories.NewIdentity()
	claimsRepository := repositories.NewClaim()
	connectionsRepository := repositories.NewConnection()
	mtRepository := repositories.NewIdentityMerkleTreeRepository()
	identityStateRepository := repositories.NewIdentityState()
	revocationRepository := repositories.NewRevocation()
	// schemaRepository := repositories.NewSchema(*storage)
	// linkRepository := repositories.NewLink(*storage)
	sessionRepository := repositories.NewSessionCached(cachex)

	mtService := services.NewIdentityMerkleTrees(mtRepository)
	qrService := services.NewQrStoreService(cachex)

	mediaTypeManager := services.NewMediaTypeManager(
		map[iden3comm.ProtocolMessage][]string{
			iden3commProtocol.CredentialFetchRequestMessageType:  {string(packers.MediaTypeZKPMessage)},
			iden3commProtocol.RevocationStatusRequestMessageType: {"*"},
		},
		*cfg.MediaTypeManager.Enabled,
	)

	universalDIDResolverUrl := auth.UniversalResolverURL
	if cfg.UniversalDIDResolver.UniversalResolverURL != nil && *cfg.UniversalDIDResolver.UniversalResolverURL != "" {
		universalDIDResolverUrl = *cfg.UniversalDIDResolver.UniversalResolverURL
	}
	universalDIDResolverHandler := packagemanager.NewUniversalDIDResolverHandler(universalDIDResolverUrl)

	verificationKeyLoader := &authLoaders.FSKeyLoader{Dir: cfg.Circuit.Path + "/authV2"}
	verifier, err := auth.NewVerifier(verificationKeyLoader, networkResolver.GetStateResolvers(), auth.WithDIDResolver(universalDIDResolverHandler))
	if err != nil {
		log.Error(ctx, "failed init verifier", "err", err)
		return
	}

	revocationStatusResolver := revocationstatus.NewRevocationStatusResolver(*networkResolver)
	identityService := services.NewIdentity(keyStore,
		identityRepository,
		mtRepository,
		identityStateRepository,
		mtService,
		qrService,
		claimsRepository,
		revocationRepository,
		connectionsRepository,
		storage,
		verifier,
		sessionRepository,
		ps,
		*networkResolver,
		rhsFactory,
		revocationStatusResolver)

	claimService := services.NewClaim(
		repositories.NewClaim(),
		identityService,
		qrService,
		mtService,
		identityStateRepository,
		schemaLoader,
		storage,
		cfg.ServerUrl,
		ps,
		cfg.IPFS.GatewayURL,
		revocationStatusResolver,
		mediaTypeManager,
		cfg.UniversalLinks,
	)
	did := &w3c.DID{
		Method: "iden3",
		ID:     "fabric:beka:24FZC7gj9oPnPdqKQK2m2nh1oGx3BHDeN9go2MyrM1",
	}
	createClaimRequest := &ports.CreateClaimRequest{
		DID:    did,
		Schema: "ipfs://QmXdnLx9ucyqe6vaouCEz3cYufpjjTA7PMYgZUt81z6SqC",
		CredentialSubject: map[string]interface{}{
			"Branch":     "Moscow",
			"Full_Name":  "Vu Viet Tai",
			"University": "MSU",
			"Year":       2007,
			"cgpa":       4.5,
			"id":         "did:iden3:fabric:beka:249kBnByE8Tp2oxTLwHQMnH5Ydn4fExS54ghNwaPbR",
			//"id":         "did:iden3:66a5283e-ee29-4ca9-a3ce-645fe281d23b",
			//"id":         "did:iden3:fabric:beka:24FZC7gj9oPnPdqKQK2m2nh1oGx3BHDeN9go2MyrM1",
		},
		SignatureProof: true,
		Type:           "Certificate",
	}
	// creadentialStatusType := verifiable.CredentialStatusType("Iden3commRevocationStatusV1.0")
	// identity, err := identityService.Create(ctx, cfg.ServerUrl, &ports.DIDCreationOptions{
	// 	Method:               core.DIDMethodIden3,
	// 	Blockchain:           "fabric",
	// 	Network:              "beka",
	// 	KeyType:              kms.KeyTypeBabyJubJub,
	// 	AuthCredentialStatus: creadentialStatusType,
	// })
	// require.NoError(t, err)
	// require.NotNil(t, identity)
	claim, err := claimService.CreateCredential(ctx, createClaimRequest)
	require.NoError(t, err)
	require.NotNil(t, claim)

}
