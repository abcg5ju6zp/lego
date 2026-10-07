package storage

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand/v2"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"sync"
	"time"

	"github.com/go-acme/lego/v5/certcrypto"
	"github.com/go-acme/lego/v5/certificate"
	"github.com/gofrs/flock"
	"golang.org/x/crypto/ocsp"
)

const (
	pendingFolderName = ".pending"

	leaseLockName = ".lock"

	stateFileName    = "state.json"
	metadataFileName = "meta.json"
	previousDirName  = "previous"
)

// Artifact file names stored inside a generation directory.
const (
	artifactCertificate = "certificate.pem"
	artifactIssuer      = "issuer.pem"
	artifactPrivateKey  = "private.pem"
	artifactResource    = "resource.json"
	artifactPEM         = "bundle.pem"
	artifactPFX         = "cert.pfx"
	artifactOCSP        = "ocsp.der"
)

// GenerationPhase is the state of a certificate generation.
type GenerationPhase string

const (
	// phaseStaging: artifacts are being written; the generation is incomplete
	// and must never be promoted.
	phaseStaging GenerationPhase = "staging"
	// phaseStaged: all artifacts are written, fsynced and validated;
	// the generation is ready to be promoted.
	phaseStaged GenerationPhase = "staged"
	// phasePromoting: the live files are being replaced;
	// the promotion is journaled and can be resumed or rolled back.
	phasePromoting GenerationPhase = "promoting"
	// phasePromoted: the live files have been replaced,
	// but the deploy hook has not been confirmed.
	phasePromoted GenerationPhase = "promoted"
	// phaseDeployed: the deploy hook has been confirmed;
	// the generation can be safely removed.
	phaseDeployed GenerationPhase = "deployed"
)

// OCSPFetcher fetches a raw OCSP response for the PEM encoded certificate bundle.
type OCSPFetcher func(ctx context.Context, bundle []byte) ([]byte, error)

// DeployFunc runs the deployment of a certificate resource.
type DeployFunc func(ctx context.Context, certRes *certificate.Resource, metadata map[string]string) error

type generationState struct {
	Phase   GenerationPhase `json:"phase"`
	CertID  string          `json:"certId"`
	Created time.Time       `json:"createdAt"`

	// LiveFiles maps the live base file name (e.g. "example.com.crt")
	// to the artifact file name inside the generation directory.
	LiveFiles map[string]string `json:"liveFiles"`

	// OCSPRequired is true when the certificate advertises an OCSP server.
	OCSPRequired bool `json:"ocspRequired,omitempty"`
	// OCSPFetched is true when a valid OCSP response has been staged.
	OCSPFetched bool `json:"ocspFetched,omitempty"`

	// Swapped tracks completed promotion steps (phase == phasePromoting only).
	Swapped map[string]bool `json:"swapped,omitempty"`
}

// Generation represents a candidate certificate generation.
type Generation struct {
	storage *CertificatesStorage

	certID string
	id     string
	dir    string

	state *generationState
}

// CertID returns the certificate ID of the generation.
func (g *Generation) CertID() string { return g.certID }

// Phase returns the current phase of the generation.
func (g *Generation) Phase() GenerationPhase { return g.state.Phase }

// Metadata returns the persisted deploy metadata.
func (g *Generation) Metadata() (map[string]string, error) {
	raw, err := os.ReadFile(filepath.Join(g.dir, metadataFileName))
	if err != nil {
		return nil, fmt.Errorf("read metadata for generation %q: %w", g.id, err)
	}

	metadata := make(map[string]string)

	err = json.Unmarshal(raw, &metadata)
	if err != nil {
		return nil, fmt.Errorf("parse metadata for generation %q: %w", g.id, err)
	}

	return metadata, nil
}

// Resource reconstructs the certificate resource from the staged artifacts.
func (g *Generation) Resource() (*certificate.Resource, error) {
	raw, err := os.ReadFile(filepath.Join(g.dir, artifactResource))
	if err != nil {
		return nil, fmt.Errorf("read resource for generation %q: %w", g.id, err)
	}

	res := new(certificate.Resource)

	err = json.Unmarshal(raw, res)
	if err != nil {
		return nil, fmt.Errorf("parse resource for generation %q: %w", g.id, err)
	}

	for base, artifact := range g.state.LiveFiles {
		data, errR := os.ReadFile(filepath.Join(g.dir, artifact))
		if errR != nil {
			return nil, fmt.Errorf("read artifact %q for generation %q: %w", artifact, g.id, errR)
		}

		switch ext := filepath.Ext(base); ext {
		case ExtCert:
			if base == SanitizedName(g.certID)+ExtCert {
				res.Certificate = data
			}

		case ExtKey:
			res.PrivateKey = data

		default:
			if base == SanitizedName(g.certID)+ExtIssuer {
				res.IssuerCertificate = data
			}
		}
	}

	return res, nil
}

// Ready finalizes the staging: validates the artifacts,
// transitions the generation to phaseStaged, then fetches the OCSP response if required.
//
// The generation is persisted as staged before the OCSP response is fetched:
// an OCSP failure is retried on the next run (via Adopt) without issuing a new certificate.
func (g *Generation) Ready(ctx context.Context, fetch OCSPFetcher) error {
	if g.Phase() != phaseStaging && g.Phase() != phaseStaged {
		return fmt.Errorf("generation %q for %q cannot be readied in phase %q", g.id, g.certID, g.Phase())
	}

	err := g.validate(false)
	if err != nil {
		return fmt.Errorf("validate generation %q for %q: %w", g.id, g.certID, err)
	}

	if g.Phase() == phaseStaging {
		g.state.Phase = phaseStaged

		err = g.persist()
		if err != nil {
			return err
		}
	}

	err = g.fetchOCSP(ctx, fetch)
	if err != nil {
		return err
	}

	return g.validate(true)
}

// Promote replaces the live files with the staged artifacts.
//
// The current live files are snapshotted first,
// and the replacement is journaled so that an interruption can either be
// completed forward or rolled back to the previous certificate.
func (g *Generation) Promote() error {
	if g.Phase() != phaseStaged {
		return fmt.Errorf("generation %q for %q cannot be promoted in phase %q", g.id, g.certID, g.Phase())
	}

	root := g.storage.rootPath

	err := CreateNonExistingFolder(root)
	if err != nil {
		return fmt.Errorf("root folder creation: %w", err)
	}

	previousDir := filepath.Join(g.dir, previousDirName)

	err = g.snapshotLiveFiles(previousDir)
	if err != nil {
		return err
	}

	// Start the journaled promotion.
	g.state.Phase = phasePromoting
	g.state.Swapped = make(map[string]bool)

	err = g.persist()
	if err != nil {
		return fmt.Errorf("start promotion: %w", err)
	}

	err = g.swapAllLiveFiles()
	if err != nil {
		return g.abort(err)
	}

	err = syncDir(root)
	if err != nil {
		return g.abort(fmt.Errorf("sync live folder: %w", err))
	}

	g.state.Phase = phasePromoted
	g.state.Swapped = nil

	err = g.persist()
	if err != nil {
		return fmt.Errorf("complete promotion: %w", err)
	}

	return nil
}

// snapshotLiveFiles copies the current live files into the snapshot directory.
func (g *Generation) snapshotLiveFiles(previousDir string) error {
	err := os.MkdirAll(previousDir, 0o700)
	if err != nil {
		return fmt.Errorf("snapshot folder creation: %w", err)
	}

	root := g.storage.rootPath

	for _, base := range g.orderedLiveFiles() {
		raw, errR := os.ReadFile(filepath.Join(root, base))
		if errors.Is(errR, os.ErrNotExist) {
			continue
		}

		if errR != nil {
			return fmt.Errorf("snapshot %q: %w", base, errR)
		}

		err = writeSynced(filepath.Join(previousDir, base), raw, filePerm)
		if err != nil {
			return fmt.Errorf("snapshot %q: %w", base, err)
		}
	}

	err = syncDir(previousDir)
	if err != nil {
		return fmt.Errorf("sync snapshot: %w", err)
	}

	return nil
}

// swapAllLiveFiles swaps every live file with its staged artifact,
// recording each step in the promotion journal.
func (g *Generation) swapAllLiveFiles() error {
	for _, base := range g.orderedLiveFiles() {
		if g.state.Swapped[base] {
			continue
		}

		err := g.swap(base)
		if err != nil {
			return fmt.Errorf("promote %q: %w", base, err)
		}

		g.state.Swapped[base] = true

		err = g.persist()
		if err != nil {
			return fmt.Errorf("record promotion of %q: %w", base, err)
		}
	}

	return nil
}

// abort rolls the promotion back to the previous certificate and removes the generation.
func (g *Generation) abort(original error) error {
	if g.Phase() != phasePromoting {
		return original
	}

	if err := g.rollback(); err != nil {
		return errors.Join(original, fmt.Errorf("rollback generation %q for %q: %w", g.id, g.certID, err))
	}

	return original
}

// Rollback restores the snapshotted live files and removes the generation.
func (g *Generation) Rollback() error {
	return g.rollback()
}

func (g *Generation) rollback() error {
	root := g.storage.rootPath

	var errs []error

	for _, base := range g.orderedLiveFiles() {
		previous := filepath.Join(g.dir, previousDirName, base)
		final := filepath.Join(root, base)

		raw, err := os.ReadFile(previous)
		if errors.Is(err, os.ErrNotExist) {
			// The file did not exist before the promotion: remove it.
			if errR := os.Remove(final); errR != nil && !errors.Is(errR, os.ErrNotExist) {
				errs = append(errs, fmt.Errorf("remove %q: %w", base, errR))
			}

			continue
		}

		if err != nil {
			errs = append(errs, fmt.Errorf("read snapshot %q: %w", base, err))
			continue
		}

		tmp := filepath.Join(root, "."+base+".restore-"+g.id+".tmp")

		err = writeSynced(tmp, raw, filePerm)
		if err != nil {
			errs = append(errs, fmt.Errorf("stage restore of %q: %w", base, err))
			continue
		}

		err = os.Rename(tmp, final)
		if err != nil {
			errs = append(errs, fmt.Errorf("restore %q: %w", base, err))
		}
	}

	// Remove any leftover temporary files of this generation.
	for _, base := range g.orderedLiveFiles() {
		_ = os.Remove(filepath.Join(root, "."+base+"."+g.id+".tmp"))
		_ = os.Remove(filepath.Join(root, "."+base+".restore-"+g.id+".tmp"))
	}

	if err := syncDir(root); err != nil {
		errs = append(errs, fmt.Errorf("sync live folder: %w", err))
	}

	if err := g.remove(); err != nil {
		errs = append(errs, err)
	}

	return errors.Join(errs...)
}

// resumePromotion completes an interrupted journaled promotion.
func (g *Generation) resumePromotion() error {
	if g.Phase() != phasePromoting {
		return fmt.Errorf("generation %q for %q is not being promoted", g.id, g.certID)
	}

	root := g.storage.rootPath

	// Files that already contain their artifact are considered already swapped.
	for _, base := range g.orderedLiveFiles() {
		artifact := filepath.Join(g.dir, g.state.LiveFiles[base])

		match, err := fileEquals(filepath.Join(root, base), artifact)
		if err != nil {
			return fmt.Errorf("check promotion of %q: %w", base, err)
		}

		if match {
			g.state.Swapped[base] = true
		}
	}

	err := g.swapAllLiveFiles()
	if err != nil {
		return g.abort(err)
	}

	err = syncDir(root)
	if err != nil {
		return g.abort(fmt.Errorf("sync live folder: %w", err))
	}

	g.state.Phase = phasePromoted
	g.state.Swapped = nil

	err = g.persist()
	if err != nil {
		return fmt.Errorf("complete promotion: %w", err)
	}

	return nil
}

// swap stages an artifact next to the live file and atomically renames it over it.
func (g *Generation) swap(base string) error {
	artifact := filepath.Join(g.dir, g.state.LiveFiles[base])

	data, err := os.ReadFile(artifact)
	if err != nil {
		return fmt.Errorf("read artifact %q: %w", artifact, err)
	}

	root := g.storage.rootPath

	tmp := filepath.Join(root, "."+base+"."+g.id+".tmp")

	err = writeSynced(tmp, data, filePerm)
	if err != nil {
		return fmt.Errorf("stage temporary file: %w", err)
	}

	err = os.Rename(tmp, filepath.Join(root, base))
	if err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("rename temporary file: %w", err)
	}

	return nil
}

// runDeploy runs the deploy callback and, on success,
// marks the generation deployed and removes it.
//
// A failure leaves the generation in phasePromoted:
// the next run will retry the deploy without touching the certificate.
func (g *Generation) runDeploy(ctx context.Context, deploy DeployFunc) error {
	res, err := g.Resource()
	if err != nil {
		return err
	}

	metadata, err := g.Metadata()
	if err != nil {
		return err
	}

	err = deploy(ctx, res, metadata)
	if err != nil {
		return fmt.Errorf("deploy hook: %w", err)
	}

	g.state.Phase = phaseDeployed

	err = g.persist()
	if err != nil {
		return fmt.Errorf("record deployment: %w", err)
	}

	err = g.remove()
	if err != nil {
		return fmt.Errorf("clean deployed generation: %w", err)
	}

	return nil
}

func (g *Generation) fetchOCSP(ctx context.Context, fetch OCSPFetcher) error {
	if g.state.OCSPFetched || !g.state.OCSPRequired {
		g.state.OCSPFetched = true
		return nil
	}

	if fetch == nil {
		return errors.New("missing OCSP fetcher")
	}

	raw, err := os.ReadFile(filepath.Join(g.dir, artifactCertificate))
	if err != nil {
		return fmt.Errorf("read certificate for OCSP: %w", err)
	}

	ocspRaw, err := fetch(ctx, raw)
	if err != nil {
		return fmt.Errorf("fetch OCSP for %q: %w", g.certID, err)
	}

	err = writeSynced(filepath.Join(g.dir, artifactOCSP), ocspRaw, filePerm)
	if err != nil {
		return fmt.Errorf("write OCSP for %q: %w", g.certID, err)
	}

	g.state.OCSPFetched = true

	return nil
}

// validate verifies that all staged artifacts are complete and consistent.
// When checkOCSP is true, the staged OCSP response is verified too.
func (g *Generation) validate(checkOCSP bool) error {
	certRaw, err := os.ReadFile(filepath.Join(g.dir, artifactCertificate))
	if err != nil {
		return fmt.Errorf("read certificate: %w", err)
	}

	certs, err := certcrypto.ParsePEMBundle(certRaw)
	if err != nil {
		return fmt.Errorf("parse certificate: %w", err)
	}

	leaf := certs[0]

	if leaf.IsCA {
		return errors.New("certificate bundle starts with a CA certificate")
	}

	err = g.validatePrivateKey(leaf)
	if err != nil {
		return err
	}

	issuer, err := g.validateIssuer(certs)
	if err != nil {
		return err
	}

	err = g.validateExtraArtifacts()
	if err != nil {
		return err
	}

	if checkOCSP {
		err = g.validateOCSPResponse(issuer)
		if err != nil {
			return err
		}
	}

	return g.validateDomains(leaf)
}

// validatePrivateKey verifies that the staged private key matches the certificate.
func (g *Generation) validatePrivateKey(leaf *x509.Certificate) error {
	keyArtifact, ok := g.state.LiveFiles[SanitizedName(g.certID)+ExtKey]
	if !ok {
		return nil
	}

	keyRaw, err := os.ReadFile(filepath.Join(g.dir, keyArtifact))
	if err != nil {
		return fmt.Errorf("read private key: %w", err)
	}

	privateKey, err := certcrypto.ParsePEMPrivateKey(keyRaw)
	if err != nil {
		return fmt.Errorf("parse private key: %w", err)
	}

	want, err := x509.MarshalPKIXPublicKey(leaf.PublicKey)
	if err != nil {
		return fmt.Errorf("encode certificate public key: %w", err)
	}

	got, err := x509.MarshalPKIXPublicKey(privateKey.Public())
	if err != nil {
		return fmt.Errorf("encode private key public key: %w", err)
	}

	if !bytes.Equal(want, got) {
		return errors.New("private key does not match the certificate")
	}

	return nil
}

// validateIssuer parses the staged issuer certificate and returns it,
// falling back to the issuer bundled in the certificate artifact.
func (g *Generation) validateIssuer(certs []*x509.Certificate) (*x509.Certificate, error) {
	issuerArtifact, ok := g.state.LiveFiles[SanitizedName(g.certID)+ExtIssuer]
	if !ok {
		if len(certs) > 1 {
			return certs[1], nil
		}

		return nil, nil
	}

	issuerRaw, err := os.ReadFile(filepath.Join(g.dir, issuerArtifact))
	if err != nil {
		return nil, fmt.Errorf("read issuer certificate: %w", err)
	}

	issuerCerts, err := certcrypto.ParsePEMBundle(issuerRaw)
	if err != nil {
		return nil, fmt.Errorf("parse issuer certificate: %w", err)
	}

	return issuerCerts[0], nil
}

// validateExtraArtifacts verifies the optional PEM bundle and PFX file.
func (g *Generation) validateExtraArtifacts() error {
	base := SanitizedName(g.certID)

	if _, ok := g.state.LiveFiles[base+ExtPEM]; ok {
		pemRaw, err := os.ReadFile(filepath.Join(g.dir, artifactPEM))
		if err != nil {
			return fmt.Errorf("read PEM bundle: %w", err)
		}

		_, err = certcrypto.ParsePEMBundle(pemRaw)
		if err != nil {
			return fmt.Errorf("parse PEM bundle: %w", err)
		}
	}

	if _, ok := g.state.LiveFiles[base+ExtPFX]; ok {
		info, err := os.Stat(filepath.Join(g.dir, artifactPFX))
		if err != nil {
			return fmt.Errorf("read PFX file: %w", err)
		}

		if info.Size() == 0 {
			return errors.New("empty PFX file")
		}
	}

	return nil
}

// validateOCSPResponse verifies the staged OCSP response when required.
func (g *Generation) validateOCSPResponse(issuer *x509.Certificate) error {
	if !g.state.OCSPRequired || !g.state.OCSPFetched {
		return nil
	}

	ocspRaw, err := os.ReadFile(filepath.Join(g.dir, artifactOCSP))
	if err != nil {
		return fmt.Errorf("read OCSP response: %w", err)
	}

	response, err := ocsp.ParseResponse(ocspRaw, issuer)
	if err != nil {
		return fmt.Errorf("parse OCSP response: %w", err)
	}

	if response.Status != ocsp.Good {
		return fmt.Errorf("OCSP response status is %q, expected %q", statusString(response.Status), "good")
	}

	return nil
}

// validateDomains verifies that the resource domains match the certificate domains.
func (g *Generation) validateDomains(leaf *x509.Certificate) error {
	res, err := g.Resource()
	if err != nil {
		return err
	}

	certDomains := slices.Sorted(slices.Values(certcrypto.ExtractDomains(leaf)))
	resourceDomains := slices.Sorted(slices.Values(res.Domains))

	if !slices.Equal(certDomains, resourceDomains) {
		return errors.New("resource domains do not match the certificate domains")
	}

	return nil
}

func (g *Generation) orderedLiveFiles() []string {
	base := SanitizedName(g.certID)

	order := []string{
		base + ExtCert,
		base + ExtIssuer,
		base + ExtKey,
		base + ExtResource,
		base + ExtPEM,
		base + ExtPFX,
	}

	var live []string

	for _, name := range order {
		if _, ok := g.state.LiveFiles[name]; ok {
			live = append(live, name)
		}
	}

	return live
}

// Remove deletes the generation directory.
func (g *Generation) Remove() error { return g.remove() }

func (g *Generation) remove() error {
	if err := os.RemoveAll(g.dir); err != nil {
		return fmt.Errorf("remove generation %q for %q: %w", g.id, g.certID, err)
	}

	if err := syncDir(filepath.Dir(g.dir)); err != nil {
		return fmt.Errorf("sync pending folder: %w", err)
	}

	return nil
}

func (g *Generation) persist() error {
	raw, err := json.MarshalIndent(g.state, "", "\t")
	if err != nil {
		return fmt.Errorf("marshal state for generation %q: %w", g.id, err)
	}

	err = writeFileAtomic(g.dir, stateFileName, raw, filePerm)
	if err != nil {
		return fmt.Errorf("write state for generation %q: %w", g.id, err)
	}

	return nil
}

func (s *CertificatesStorage) pendingRoot() string {
	return filepath.Join(s.rootPath, pendingFolderName)
}

func (s *CertificatesStorage) pendingCertDir(certID string) string {
	return filepath.Join(s.pendingRoot(), SanitizedName(certID))
}

// generations lists the persisted generations of a certificate, ordered by creation time.
func (s *CertificatesStorage) generations(certID string) ([]*Generation, error) {
	dir := s.pendingCertDir(certID)

	entries, err := os.ReadDir(dir)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}

	if err != nil {
		return nil, fmt.Errorf("read pending folder for %q: %w", certID, err)
	}

	var generations []*Generation

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}

		genDir := filepath.Join(dir, entry.Name())

		raw, errR := os.ReadFile(filepath.Join(genDir, stateFileName))
		if errR != nil {
			// State writes are atomic: an unreadable state means the generation
			// never reached a journaled phase and is safe to discard.
			if cleanErr := os.RemoveAll(genDir); cleanErr != nil {
				return nil, fmt.Errorf("clean corrupt generation %q: %w", entry.Name(), cleanErr)
			}

			continue
		}

		state := new(generationState)

		if errR = json.Unmarshal(raw, state); errR != nil {
			if cleanErr := os.RemoveAll(genDir); cleanErr != nil {
				return nil, fmt.Errorf("clean corrupt generation %q: %w", entry.Name(), cleanErr)
			}

			continue
		}

		generations = append(generations, &Generation{
			storage: s,
			certID:  certID,
			id:      entry.Name(),
			dir:     genDir,
			state:   state,
		})
	}

	return generations, nil
}

// CertificateLease is an exclusive lease on a certificate.
type CertificateLease struct {
	certID string

	storage *CertificatesStorage

	local chan struct{}
	flock *flock.Flock

	releaseOnce sync.Once
}

//nolint:gochecknoglobals // registry of in-process per-certificate locks.
var (
	leasesMu sync.Mutex
	leases   = map[string]chan struct{}{}
)

func localLock(certID string) chan struct{} {
	leasesMu.Lock()
	defer leasesMu.Unlock()

	ch, ok := leases[certID]
	if !ok {
		ch = make(chan struct{}, 1)
		leases[certID] = ch
	}

	return ch
}

// LeaseCertificate acquires an exclusive lease for the certificate:
// an in-process mutex and a cross-process file lock.
//
// Both acquisition steps are interruptible by the context.
// The lock file is never removed: it is reused across runs
// and the kernel releases the lock when the process exits.
func (s *CertificatesStorage) LeaseCertificate(ctx context.Context, certID string) (*CertificateLease, error) {
	local := localLock(certID)

	select {
	case local <- struct{}{}:
	case <-ctx.Done():
		return nil, fmt.Errorf("acquire lock for %q: %w", certID, ctx.Err())
	}

	certDir := s.pendingCertDir(certID)

	err := CreateNonExistingFolder(certDir)
	if err != nil {
		<-local
		return nil, fmt.Errorf("create pending folder for %q: %w", certID, err)
	}

	lockPath := filepath.Join(certDir, leaseLockName)

	lockFile, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, filePerm)
	if err != nil {
		<-local
		return nil, fmt.Errorf("create lock file for %q: %w", certID, err)
	}

	_ = lockFile.Close()

	fl := flock.New(lockPath)

	acquired, err := fl.TryLockContext(ctx, 250*time.Millisecond)
	if err != nil {
		<-local
		return nil, fmt.Errorf("acquire lock for %q: %w", certID, err)
	}

	if !acquired {
		<-local
		return nil, fmt.Errorf("acquire lock for %q: lock not available", certID)
	}

	return &CertificateLease{
		certID:  certID,
		storage: s,
		local:   local,
		flock:   fl,
	}, nil
}

// Release releases the lease. It is safe to call Release multiple times.
func (l *CertificateLease) Release() {
	l.releaseOnce.Do(func() {
		if l.flock != nil {
			_ = l.flock.Unlock()
		}

		<-l.local
	})
}

// Recover finalizes generations left in an in-flight state by a previous run.
// It returns true when at least one renewal was fully recovered.
//
// - phasePromoting: the promotion is completed forward; on failure it is rolled back.
// - phasePromoted: the deploy callback is retried once.
// - phaseDeployed: the generation is cleaned.
func (l *CertificateLease) Recover(ctx context.Context, deploy DeployFunc) (bool, error) {
	gens, err := l.storage.generations(l.certID)
	if err != nil {
		return false, err
	}

	finalized := false

	for _, g := range gens {
		switch g.Phase() {
		case phaseDeployed:
			err = g.remove()

		case phasePromoted:
			err = g.runDeploy(ctx, deploy)
			if err == nil {
				finalized = true
			}

		case phasePromoting:
			err = g.resumePromotion()
			if err != nil {
				break
			}

			err = g.runDeploy(ctx, deploy)
			if err == nil {
				finalized = true
			}

		default:
			continue
		}

		if err != nil {
			return finalized, err
		}
	}

	return finalized, nil
}

// Adopt returns a complete staged generation matching the requested domains and profile,
// completing its staging (OCSP retrieval and validation) when needed.
//
// Incomplete generations are discarded.
// Complete generations that do not match the requested configuration are discarded too.
// If several matching generations exist, only the newest one is kept.
func (l *CertificateLease) Adopt(ctx context.Context, domains []string, profile string, fetch OCSPFetcher) (*Generation, error) {
	gens, err := l.storage.generations(l.certID)
	if err != nil {
		return nil, err
	}

	candidates, err := l.collectCandidates(gens, domains, profile)
	if err != nil {
		return nil, err
	}

	if len(candidates) == 0 {
		return nil, nil
	}

	for _, g := range candidates[:len(candidates)-1] {
		if err = g.remove(); err != nil {
			return nil, err
		}
	}

	g := candidates[len(candidates)-1]

	err = g.Ready(ctx, fetch)
	if err != nil {
		return nil, err
	}

	return g, nil
}

// collectCandidates discards incomplete generations and returns the staged ones matching the request.
func (l *CertificateLease) collectCandidates(gens []*Generation, domains []string, profile string) ([]*Generation, error) {
	var candidates []*Generation

	for _, g := range gens {
		switch g.Phase() {
		case phaseStaging:
			if err := g.remove(); err != nil {
				return nil, err
			}

		case phaseStaged:
			candidate, err := g.classify(domains, profile)
			if err != nil {
				return nil, err
			}

			if candidate {
				candidates = append(candidates, g)
			}
		}
	}

	return candidates, nil
}

// classify reports whether the generation matches the requested domains and profile.
// A non-matching generation is removed.
func (g *Generation) classify(domains []string, profile string) (bool, error) {
	match, err := g.matches(domains, profile)
	if err != nil {
		return false, err
	}

	if match {
		return true, nil
	}

	if err := g.remove(); err != nil {
		return false, err
	}

	return false, nil
}

func (g *Generation) matches(domains []string, profile string) (bool, error) {
	certRaw, err := os.ReadFile(filepath.Join(g.dir, artifactCertificate))
	if err != nil {
		return false, fmt.Errorf("read certificate for generation %q: %w", g.id, err)
	}

	certs, err := certcrypto.ParsePEMBundle(certRaw)
	if err != nil {
		return false, fmt.Errorf("parse certificate for generation %q: %w", g.id, err)
	}

	if !sameDomains(certcrypto.ExtractDomains(certs[0]), domains) {
		return false, nil
	}

	res, err := g.Resource()
	if err != nil {
		return false, err
	}

	return res.Profile == profile, nil
}

// NewGeneration stages a new candidate generation for the certificate resource.
func (l *CertificateLease) NewGeneration(certRes *Certificate, opts *SaveOptions, metadata map[string]string) (*Generation, error) {
	res := certRes.Resource

	now := time.Now().UTC()

	id := newGenerationID(now)

	g := &Generation{
		storage: l.storage,
		certID:  res.ID,
		id:      id,
		dir:     filepath.Join(l.storage.pendingCertDir(res.ID), id),
	}

	err := os.MkdirAll(g.dir, 0o700)
	if err != nil {
		return nil, fmt.Errorf("create generation folder: %w", err)
	}

	base := SanitizedName(res.ID)

	state := &generationState{
		Phase:     phaseStaging,
		CertID:    res.ID,
		Created:   now,
		LiveFiles: make(map[string]string),
	}

	err = stageArtifact(g.dir, artifactCertificate, res.Certificate)
	if err != nil {
		return nil, fmt.Errorf("unable to save the certificate for %q: %w", res.ID, err)
	}

	state.LiveFiles[base+ExtCert] = artifactCertificate

	if len(res.IssuerCertificate) > 0 {
		err = stageArtifact(g.dir, artifactIssuer, res.IssuerCertificate)
		if err != nil {
			return nil, fmt.Errorf("unable to save the issuer certificate for %q: %w", res.ID, err)
		}

		state.LiveFiles[base+ExtIssuer] = artifactIssuer
	}

	// Keep the behavior of Save compatible:
	// PEM or PFX output without a private key is an error (probable usage of a CSR).
	if len(res.PrivateKey) == 0 && opts != nil && (opts.PEM || opts.PFX) {
		return nil, fmt.Errorf("unable to save PEM or PFX without the private key for %q: probable usage of a CSR", res.ID)
	}

	err = stagePrivateKeyArtifacts(g.dir, certRes, opts, base, state)
	if err != nil {
		return nil, err
	}

	err = stageResourceAndMetadata(g.dir, certRes, metadata, base, state)
	if err != nil {
		return nil, err
	}

	g.state = state

	err = g.persist()
	if err != nil {
		return nil, err
	}

	return g, nil
}

// stageArtifact writes an artifact file with the default permissions.
func stageArtifact(dir, artifact string, data []byte) error {
	return writeSynced(filepath.Join(dir, artifact), data, filePerm)
}

// stagePrivateKeyArtifacts writes the private key and, depending on the options,
// the PEM bundle and the PFX file.
func stagePrivateKeyArtifacts(dir string, certRes *Certificate, opts *SaveOptions, base string, state *generationState) error {
	res := certRes.Resource

	if len(res.PrivateKey) == 0 {
		return nil
	}

	err := stageArtifact(dir, artifactPrivateKey, res.PrivateKey)
	if err != nil {
		return fmt.Errorf("unable to save the private key for %q: %w", res.ID, err)
	}

	state.LiveFiles[base+ExtKey] = artifactPrivateKey

	if opts != nil && opts.PEM {
		pemData := bytes.Join([][]byte{res.Certificate, res.PrivateKey}, nil)

		err = stageArtifact(dir, artifactPEM, pemData)
		if err != nil {
			return fmt.Errorf("unable to save the PEM file: %w", err)
		}

		state.LiveFiles[base+ExtPEM] = artifactPEM
	}

	if opts != nil && opts.PFX {
		pfxData, errP := buildPFX(certRes, opts)
		if errP != nil {
			return fmt.Errorf("unable to save the PFX file: %w", errP)
		}

		err = stageArtifact(dir, artifactPFX, pfxData)
		if err != nil {
			return fmt.Errorf("unable to save the PFX file: %w", err)
		}

		state.LiveFiles[base+ExtPFX] = artifactPFX
	}

	return nil
}

// stageResourceAndMetadata writes the resource JSON, the deploy metadata,
// and records whether an OCSP response is required.
func stageResourceAndMetadata(dir string, certRes *Certificate, metadata map[string]string, base string, state *generationState) error {
	res := certRes.Resource

	// The resource JSON is identical to the one produced by Save.
	jsonBytes, err := json.MarshalIndent(certRes, "", "\t")
	if err != nil {
		return fmt.Errorf("unable to marshal the resource for %q: %w", res.ID, err)
	}

	err = stageArtifact(dir, artifactResource, jsonBytes)
	if err != nil {
		return fmt.Errorf("unable to save the resource for %q: %w", res.ID, err)
	}

	state.LiveFiles[base+ExtResource] = artifactResource

	// OCSP is required only for certificates advertising an OCSP server.
	leaf, err := certcrypto.ParsePEMCertificate(res.Certificate)
	if err != nil {
		return fmt.Errorf("parse certificate for %q: %w", res.ID, err)
	}

	state.OCSPRequired = len(leaf.OCSPServer) > 0

	metaBytes, err := json.MarshalIndent(metadata, "", "\t")
	if err != nil {
		return fmt.Errorf("marshal metadata for %q: %w", res.ID, err)
	}

	err = stageArtifact(dir, metadataFileName, metaBytes)
	if err != nil {
		return fmt.Errorf("write metadata for %q: %w", res.ID, err)
	}

	return nil
}

// Commit promotes the generation and runs the deploy callback.
//
// On promotion failure the generation is rolled back and removed.
// On deploy failure the generation is kept in phasePromoted
// and retried by the next run's Recover; a successful deploy is never rolled back.
func (l *CertificateLease) Commit(ctx context.Context, g *Generation, deploy DeployFunc) error {
	if g.Phase() != phaseStaged {
		return fmt.Errorf("generation %q for %q cannot be committed in phase %q", g.id, g.certID, g.Phase())
	}

	err := g.Promote()
	if err != nil {
		return err
	}

	return g.runDeploy(ctx, deploy)
}

func newGenerationID(now time.Time) string {
	return now.Format("20060102T150405.000000000") + "-" + strconv.FormatUint(uint64(rand.Uint32()), 36)
}

// writeSynced writes a file and flushes it to disk.
func writeSynced(path string, data []byte, perm os.FileMode) error {
	file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, perm)
	if err != nil {
		return err
	}

	_, err = file.Write(data)
	if err != nil {
		_ = file.Close()
		return err
	}

	err = file.Sync()
	if err != nil {
		_ = file.Close()
		return err
	}

	return file.Close()
}

// writeFileAtomic writes a file atomically (in the same directory) and syncs the directory.
func writeFileAtomic(dir, name string, data []byte, perm os.FileMode) error {
	tmp := filepath.Join(dir, "."+name+".tmp")

	err := writeSynced(tmp, data, perm)
	if err != nil {
		return err
	}

	err = os.Rename(tmp, filepath.Join(dir, name))
	if err != nil {
		_ = os.Remove(tmp)
		return err
	}

	return syncDir(dir)
}

// syncDir flushes a directory's metadata to disk.
func syncDir(path string) error {
	dir, err := os.Open(path)
	if err != nil {
		return err
	}

	defer func() { _ = dir.Close() }()

	return dir.Sync()
}

// fileEquals reports whether a live file has the same content as an artifact.
// A missing live file reports false.
func fileEquals(livePath, artifactPath string) (bool, error) {
	raw, err := os.ReadFile(livePath)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}

	if err != nil {
		return false, err
	}

	want, err := os.ReadFile(artifactPath)
	if err != nil {
		return false, err
	}

	return bytes.Equal(raw, want), nil
}

func statusString(status int) string {
	switch status {
	case ocsp.Good:
		return "good"
	case ocsp.Revoked:
		return "revoked"
	default:
		return "unknown"
	}
}

// sameDomains reports whether two domain lists contain the same domains.
func sameDomains(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}

	aClone := slices.Clone(a)
	sort.Strings(aClone)

	bClone := slices.Clone(b)
	sort.Strings(bClone)

	return slices.Equal(aClone, bClone)
}
