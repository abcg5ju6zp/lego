package storage

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-acme/lego/v5/certcrypto"
	"github.com/go-acme/lego/v5/certificate"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ocsp"
)

const testCertID = "example.com"

func makeTestResource(t *testing.T) *certificate.Resource {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	now := time.Now()

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	require.NoError(t, err)

	template := x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName: testCertID,
		},
		DNSNames:    []string{testCertID},
		NotBefore:   now.Add(-time.Hour),
		NotAfter:    now.Add(90 * 24 * time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},

		BasicConstraintsValid: true,
	}

	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	require.NoError(t, err)

	cert := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})

	return &certificate.Resource{
		ID:          testCertID,
		Domains:     []string{testCertID},
		KeyType:     certcrypto.RSA2048,
		CertURL:     fmt.Sprintf("https://acme.example.org/cert/%x", serial),
		Certificate: cert,
		PrivateKey:  certcrypto.PEMEncode(key),
	}
}

func saveCurrent(t *testing.T, store *CertificatesStorage, res *certificate.Resource, opts *SaveOptions) {
	t.Helper()

	err := store.Save(&Certificate{Resource: res, Origin: OriginCommand}, opts)
	require.NoError(t, err)
}

func newTestLease(ctx context.Context, t *testing.T, store *CertificatesStorage) *CertificateLease {
	t.Helper()

	lease, err := store.LeaseCertificate(ctx, testCertID)
	require.NoError(t, err)

	return lease
}

func deployStub(counter *int32, fail error) DeployFunc {
	return func(_ context.Context, _ *certificate.Resource, _ map[string]string) error {
		if counter != nil {
			atomic.AddInt32(counter, 1)
		}

		return fail
	}
}

func ocspNotRequired(t *testing.T, gen *Generation) {
	t.Helper()

	assert.False(t, gen.state.OCSPRequired)
}

func assertNoPendingGeneration(t *testing.T, store *CertificatesStorage) {
	t.Helper()

	entries, err := os.ReadDir(store.pendingCertDir(testCertID))
	require.NoError(t, err)

	for _, entry := range entries {
		if entry.Name() == leaseLockName {
			continue
		}

		assert.Fail(t, "unexpected pending entry", entry.Name())
	}
}

func TestLease_Commit_replacesCurrent(t *testing.T) {
	store := NewCertificatesStorage(t.TempDir())

	old := makeTestResource(t)
	saveCurrent(t, store, old, &SaveOptions{PEM: true})

	fresh := makeTestResource(t)

	var deployCount int32

	ctx := t.Context()

	lease := newTestLease(ctx, t, store)
	defer lease.Release()

	done, err := lease.Recover(ctx, deployStub(&deployCount, nil))
	require.NoError(t, err)
	assert.False(t, done)

	options := &SaveOptions{PEM: true}

	metadata := map[string]string{
		"LEGO_HOOK_CERT_NAME": testCertID,
		"LEGO_HOOK_CERT_PATH": store.GetFileName(testCertID, ExtCert),
	}

	gen, err := lease.NewGeneration(&Certificate{Resource: fresh, Origin: OriginCommand}, options, metadata)
	require.NoError(t, err)

	ocspNotRequired(t, gen)

	err = gen.Ready(ctx, nil)
	require.NoError(t, err)

	err = lease.Commit(ctx, gen, deployStub(&deployCount, nil))
	require.NoError(t, err)

	assert.Equal(t, int32(1), atomic.LoadInt32(&deployCount))

	// The live files contain the new certificate.
	liveCert, err := store.ReadFile(testCertID, ExtCert)
	require.NoError(t, err)
	assert.Equal(t, fresh.Certificate, liveCert)

	liveKey, err := store.ReadFile(testCertID, ExtKey)
	require.NoError(t, err)
	assert.Equal(t, fresh.PrivateKey, liveKey)

	livePEM, err := store.ReadFile(testCertID, ExtPEM)
	require.NoError(t, err)
	assert.Equal(t, append(append([]byte{}, fresh.Certificate...), fresh.PrivateKey...), livePEM)

	// The generation is cleaned.
	assertNoPendingGeneration(t, store)

	lease.Release()
}

func TestRecover_promotedRunsDeploy(t *testing.T) {
	store := NewCertificatesStorage(t.TempDir())

	old := makeTestResource(t)
	saveCurrent(t, store, old, nil)

	fresh := makeTestResource(t)

	ctx := t.Context()

	lease := newTestLease(ctx, t, store)
	defer lease.Release()

	gen, err := lease.NewGeneration(&Certificate{Resource: fresh, Origin: OriginCommand}, nil,
		map[string]string{"LEGO_HOOK_CERT_NAME": testCertID})
	require.NoError(t, err)

	err = gen.Ready(ctx, nil)
	require.NoError(t, err)

	// Promote without deploying: simulates a crash before the deploy hook.
	err = gen.Promote()
	require.NoError(t, err)
	assert.Equal(t, phasePromoted, gen.Phase())

	lease.Release()

	// A new run recovers the generation.
	lease = newTestLease(ctx, t, store)
	defer lease.Release()

	var deployCount int32

	done, err := lease.Recover(ctx, deployStub(&deployCount, nil))
	require.NoError(t, err)
	assert.True(t, done)
	assert.Equal(t, int32(1), atomic.LoadInt32(&deployCount))

	liveCert, err := store.ReadFile(testCertID, ExtCert)
	require.NoError(t, err)
	assert.Equal(t, fresh.Certificate, liveCert)

	assertNoPendingGeneration(t, store)

	lease.Release()
}

func TestRecover_completesInterruptedPromotion(t *testing.T) {
	store := NewCertificatesStorage(t.TempDir())

	old := makeTestResource(t)
	saveCurrent(t, store, old, nil)

	fresh := makeTestResource(t)

	ctx := t.Context()

	lease := newTestLease(ctx, t, store)
	defer lease.Release()

	gen, err := lease.NewGeneration(&Certificate{Resource: fresh, Origin: OriginCommand}, nil,
		map[string]string{"LEGO_HOOK_CERT_NAME": testCertID})
	require.NoError(t, err)

	err = gen.Ready(ctx, nil)
	require.NoError(t, err)

	base := SanitizedName(testCertID)

	// Manually reproduce an interrupted promotion: only the certificate file has been swapped.
	err = os.MkdirAll(filepath.Join(gen.dir, previousDirName), 0o700)
	require.NoError(t, err)

	oldCert, err := os.ReadFile(store.GetFileName(testCertID, ExtCert))
	require.NoError(t, err)

	err = writeSynced(filepath.Join(gen.dir, previousDirName, base+ExtCert), oldCert, filePerm)
	require.NoError(t, err)

	gen.state.Phase = phasePromoting
	gen.state.Swapped = map[string]bool{}
	require.NoError(t, gen.persist())

	require.NoError(t, gen.swap(base+ExtCert))

	gen.state.Swapped[base+ExtCert] = true
	require.NoError(t, gen.persist())

	lease.Release()

	lease = newTestLease(ctx, t, store)
	defer lease.Release()

	var deployCount int32

	done, err := lease.Recover(ctx, deployStub(&deployCount, nil))
	require.NoError(t, err)
	assert.True(t, done)
	assert.Equal(t, int32(1), atomic.LoadInt32(&deployCount))

	// All live files now contain the new generation.
	liveCert, err := store.ReadFile(testCertID, ExtCert)
	require.NoError(t, err)
	assert.Equal(t, fresh.Certificate, liveCert)

	liveKey, err := store.ReadFile(testCertID, ExtKey)
	require.NoError(t, err)
	assert.Equal(t, fresh.PrivateKey, liveKey)

	liveResource, err := store.ReadResource(testCertID)
	require.NoError(t, err)
	assert.Equal(t, testCertID, liveResource.ID)

	assertNoPendingGeneration(t, store)

	lease.Release()
}

func TestCommit_deployFailureIsRetriedWithoutRollback(t *testing.T) {
	store := NewCertificatesStorage(t.TempDir())

	old := makeTestResource(t)
	saveCurrent(t, store, old, nil)

	fresh := makeTestResource(t)

	ctx := t.Context()

	lease := newTestLease(ctx, t, store)
	defer lease.Release()

	gen, err := lease.NewGeneration(&Certificate{Resource: fresh, Origin: OriginCommand}, nil,
		map[string]string{"LEGO_HOOK_CERT_NAME": testCertID})
	require.NoError(t, err)

	err = gen.Ready(ctx, nil)
	require.NoError(t, err)

	deployErr := errors.New("deploy failed")

	err = lease.Commit(ctx, gen, deployStub(nil, deployErr))
	require.ErrorIs(t, err, deployErr)

	// The new certificate stays live and the generation awaits a deploy retry.
	liveCert, err := store.ReadFile(testCertID, ExtCert)
	require.NoError(t, err)
	assert.Equal(t, fresh.Certificate, liveCert)

	gens, err := store.generations(testCertID)
	require.NoError(t, err)
	require.Len(t, gens, 1)
	assert.Equal(t, phasePromoted, gens[0].Phase())

	var deployCount int32

	done, err := lease.Recover(ctx, deployStub(&deployCount, nil))
	require.NoError(t, err)
	assert.True(t, done)
	assert.Equal(t, int32(1), atomic.LoadInt32(&deployCount))

	lease.Release()
}

func TestAdopt_stagedGeneration(t *testing.T) {
	store := NewCertificatesStorage(t.TempDir())

	old := makeTestResource(t)
	saveCurrent(t, store, old, nil)

	fresh := makeTestResource(t)

	ctx := t.Context()

	lease := newTestLease(ctx, t, store)
	defer lease.Release()

	gen, err := lease.NewGeneration(&Certificate{Resource: fresh, Origin: OriginCommand}, nil,
		map[string]string{"LEGO_HOOK_CERT_NAME": testCertID})
	require.NoError(t, err)

	err = gen.Ready(ctx, nil)
	require.NoError(t, err)

	assert.Equal(t, phaseStaged, gen.Phase())

	lease.Release()

	// New run: adopt instead of issuing a new certificate.
	lease = newTestLease(ctx, t, store)
	defer lease.Release()

	adopted, err := lease.Adopt(ctx, []string{testCertID}, "", nil)
	require.NoError(t, err)
	require.NotNil(t, adopted)
	assert.Equal(t, gen.id, adopted.id)

	var deployCount int32

	err = lease.Commit(ctx, adopted, deployStub(&deployCount, nil))
	require.NoError(t, err)
	assert.Equal(t, int32(1), atomic.LoadInt32(&deployCount))

	lease.Release()
}

func TestAdopt_discardsNonMatchingGeneration(t *testing.T) {
	store := NewCertificatesStorage(t.TempDir())

	old := makeTestResource(t)
	saveCurrent(t, store, old, nil)

	fresh := makeTestResource(t)

	ctx := t.Context()

	lease := newTestLease(ctx, t, store)
	defer lease.Release()

	gen, err := lease.NewGeneration(&Certificate{Resource: fresh, Origin: OriginCommand}, nil,
		map[string]string{"LEGO_HOOK_CERT_NAME": testCertID})
	require.NoError(t, err)

	err = gen.Ready(ctx, nil)
	require.NoError(t, err)

	// Requested domains differ: the staged generation is discarded.
	adopted, err := lease.Adopt(ctx, []string{"example.org"}, "", nil)
	require.NoError(t, err)
	assert.Nil(t, adopted)

	gens, err := store.generations(testCertID)
	require.NoError(t, err)
	assert.Empty(t, gens)

	lease.Release()
}

func TestGenerations_corruptGenerationRemoved(t *testing.T) {
	store := NewCertificatesStorage(t.TempDir())

	require.NoError(t, CreateNonExistingFolder(store.pendingCertDir(testCertID)))

	corrupt := filepath.Join(store.pendingCertDir(testCertID), "corrupt-gen")
	require.NoError(t, os.MkdirAll(corrupt, 0o700))
	require.NoError(t, os.WriteFile(filepath.Join(corrupt, stateFileName), []byte("not json"), filePerm))

	gens, err := store.generations(testCertID)
	require.NoError(t, err)
	assert.Empty(t, gens)
}

func TestLease_serializesAccess(t *testing.T) {
	store := NewCertificatesStorage(t.TempDir())

	ctx := t.Context()

	lease := newTestLease(ctx, t, store)
	defer lease.Release()

	shortCtx, cancel := context.WithTimeout(ctx, 100*time.Millisecond)
	defer cancel()

	_, err := store.LeaseCertificate(shortCtx, testCertID)
	require.Error(t, err)

	lease.Release()

	second := newTestLease(ctx, t, store)
	defer second.Release()

	second.Release()
}

func TestReady_ocspFailureIsRetriedViaAdopt(t *testing.T) {
	store := NewCertificatesStorage(t.TempDir())

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	now := time.Now()

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	require.NoError(t, err)

	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: testCertID},
		DNSNames:     []string{testCertID},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(90 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		OCSPServer:   []string{"https://ocsp.example.org"},

		BasicConstraintsValid: true,
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)

	fresh := &certificate.Resource{
		ID:          testCertID,
		Domains:     []string{testCertID},
		KeyType:     certcrypto.RSA2048,
		CertURL:     "https://acme.example.org/cert/1",
		Certificate: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		PrivateKey:  certcrypto.PEMEncode(key),
	}

	ctx := t.Context()

	lease := newTestLease(ctx, t, store)
	defer lease.Release()

	gen, err := lease.NewGeneration(&Certificate{Resource: fresh, Origin: OriginCommand}, nil,
		map[string]string{"LEGO_HOOK_CERT_NAME": testCertID})
	require.NoError(t, err)
	assert.True(t, gen.state.OCSPRequired)

	// OCSP fetch fails: the generation is persisted as staged and kept.
	ocspErr := errors.New("ocsp unavailable")

	err = gen.Ready(ctx, func(context.Context, []byte) ([]byte, error) { return nil, ocspErr })
	require.ErrorIs(t, err, ocspErr)
	assert.Equal(t, phaseStaged, gen.Phase())

	lease.Release()

	// Next run adopts the staged generation and retries the OCSP retrieval only.
	lease = newTestLease(ctx, t, store)
	defer lease.Release()

	adopted, err := lease.Adopt(ctx, []string{testCertID}, "", func(_ context.Context, _ []byte) ([]byte, error) {
		response := ocsp.Response{
			Status:       ocsp.Good,
			SerialNumber: cert.SerialNumber,
			ThisUpdate:   now,
			NextUpdate:   now.Add(7 * 24 * time.Hour),
		}

		return ocsp.CreateResponse(cert, cert, response, key)
	})
	require.NoError(t, err)
	require.NotNil(t, adopted)

	var deployCount int32

	err = lease.Commit(ctx, adopted, deployStub(&deployCount, nil))
	require.NoError(t, err)
	assert.Equal(t, int32(1), atomic.LoadInt32(&deployCount))

	assertNoPendingGeneration(t, store)

	lease.Release()
}
