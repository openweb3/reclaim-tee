package tee

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/reclaimprotocol/reclaim-tee/tokenhive/internal/canonical"
)

// CredentialEnvelopeDomain separates the credential-envelope key derivation
// from every other digest in the TokenHive stack, so a shared secret can never
// be repurposed as a hash or signature input elsewhere.
const CredentialEnvelopeDomain = "TokenHive.CredentialEnvelope.v1"

// EncodeCanonical returns the deterministic CBOR encoding of the envelope, the
// form carried inside jobs.Spec.Credential. The Hub stores the envelope (as
// JSON, on its control plane) and canonical-encodes it onto every job it
// dispatches; the TEE decodes it back with DecodeEnvelope before opening it.
func (e Envelope) EncodeCanonical() ([]byte, error) {
	return canonical.Marshal(e)
}

// DecodeEnvelope parses an Envelope from its canonical-CBOR form as embedded
// in jobs.Spec.Credential.
func DecodeEnvelope(b []byte) (Envelope, error) {
	var e Envelope
	if err := canonical.Unmarshal(b, &e); err != nil {
		return Envelope{}, fmt.Errorf("decode credential envelope: %w", err)
	}
	return e, nil
}

// Envelope carries a provider's credential from its agent to the TEE through
// the Hub without the Hub ever seeing the plaintext. It is the wire form of a
// hybrid-encrypted secret: an ephemeral X25519 public key, an AES-GCM nonce,
// and the ciphertext of the credential payload, all bound to the inbox key it
// was encrypted for (KeyID).
//
// The Hub relays the envelope verbatim — as JSON in an AgentRegister, and as
// the canonical-CBOR body of a job's spec.Credential — and only the TEE holding
// the matching inbox private key can open it. The cbor tags are the in-spec
// wire form; the json tags are the agent-registration control-plane form.
type Envelope struct {
	// KeyID identifies the TEE inbox key the envelope was encrypted to.
	KeyID []byte `json:"key_id" cbor:"1,keyasint"`
	// Ephemeral is the sender's one-shot X25519 public key (raw 32 bytes).
	Ephemeral []byte `json:"ephemeral" cbor:"2,keyasint"`
	// Nonce is the AES-GCM nonce.
	Nonce []byte `json:"nonce" cbor:"3,keyasint"`
	// Ciphertext is the sealed credential payload.
	Ciphertext []byte `json:"ciphertext" cbor:"4,keyasint"`
}

// credentialPayload is the plaintext sealed inside an Envelope. Provider is
// bound inside the ciphertext so the Hub cannot re-route an envelope captured
// for one provider to another: the TEE opens it and compares the declared
// provider to the one the Hub named.
type credentialPayload struct {
	Provider string `json:"provider"`
	Secret   Secret `json:"secret"`
	IssuedAt int64  `json:"issued_at,omitempty"`
}

// InboxPublic is the publishable half of the TEE's credential inbox. It is
// what an agent encrypts to; KeyID lets the TEE reject envelopes minted for a
// previous inbox key.
type InboxPublic struct {
	// KeyID is SHA-256 over the PKIX DER public key.
	KeyID [32]byte
	// PublicKey is the X25519 public key in PKIX DER form.
	PublicKey []byte
}

// InboxKey is the TEE's private credential inbox key. The private half lives
// only in enclave memory for the life of the process; nothing about it is ever
// written to disk. A restarted TEE therefore generates a fresh key, and agents
// re-register their credentials the next time they dial in (they fetch the
// current public key first).
type InboxKey struct {
	priv *ecdh.PrivateKey
	pub  ecdh.PublicKey
	id   [32]byte
	der  []byte
}

// GenerateInboxKey creates a fresh X25519 credential inbox key.
func GenerateInboxKey() (*InboxKey, error) {
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate inbox key: %w", err)
	}
	der, err := x509.MarshalPKIXPublicKey(priv.PublicKey())
	if err != nil {
		return nil, fmt.Errorf("marshal inbox public key: %w", err)
	}
	return &InboxKey{
		priv: priv,
		pub:  *priv.PublicKey(),
		id:   sha256.Sum256(der),
		der:  der,
	}, nil
}

// Public returns the publishable half of the inbox key.
func (k *InboxKey) Public() InboxPublic {
	return InboxPublic{KeyID: k.id, PublicKey: append([]byte(nil), k.der...)}
}

// KeyID returns the identifier agents must echo back in their envelopes.
func (k *InboxKey) KeyID() [32]byte { return k.id }

// Open decrypts an envelope. It returns the registered Secret and the provider
// the envelope was bound to by its sender, so the caller can verify the two
// agree.
func (k *InboxKey) Open(env Envelope) (Secret, string, error) {
	if len(env.KeyID) != sha256.Size {
		return Secret{}, "", errors.New("envelope has no key ID")
	}
	if subtle.ConstantTimeCompare(env.KeyID, k.id[:]) != 1 {
		return Secret{}, "", errors.New("envelope was not encrypted for this inbox key")
	}
	if len(env.Ephemeral) != 32 {
		return Secret{}, "", errors.New("envelope has a malformed ephemeral key")
	}
	eph, err := ecdh.X25519().NewPublicKey(env.Ephemeral)
	if err != nil {
		return Secret{}, "", fmt.Errorf("parse ephemeral key: %w", err)
	}
	shared, err := k.priv.ECDH(eph)
	if err != nil {
		return Secret{}, "", fmt.Errorf("derive shared secret: %w", err)
	}

	key := deriveEnvelopeKey(k.id[:], env.Ephemeral, shared)
	aead, err := newGCM(key)
	if err != nil {
		return Secret{}, "", err
	}
	if len(env.Nonce) != aead.NonceSize() {
		return Secret{}, "", errors.New("envelope has a malformed nonce")
	}
	plain, err := aead.Open(nil, env.Nonce, env.Ciphertext, nil)
	if err != nil {
		return Secret{}, "", errors.New("envelope failed to decrypt (wrong key or tampered)")
	}

	var payload credentialPayload
	if err := json.Unmarshal(plain, &payload); err != nil {
		return Secret{}, "", fmt.Errorf("decode credential payload: %w", err)
	}
	return payload.Secret, payload.Provider, nil
}

// EncryptCredential seals a provider's secret to the given inbox public key.
// It is the sender half of the envelope — used by the provider agent (and by
// tests) so that a token can travel through the Hub as ciphertext only.
func EncryptCredential(pub InboxPublic, provider string, secret Secret) (Envelope, error) {
	parsed, err := x509.ParsePKIXPublicKey(pub.PublicKey)
	if err != nil {
		return Envelope{}, fmt.Errorf("parse inbox public key: %w", err)
	}
	theirKey, ok := parsed.(*ecdh.PublicKey)
	if !ok || theirKey.Curve() != ecdh.X25519() {
		return Envelope{}, errors.New("inbox public key is not an X25519 key")
	}
	computedID := sha256.Sum256(pub.PublicKey)
	if subtle.ConstantTimeCompare(pub.KeyID[:], computedID[:]) != 1 {
		return Envelope{}, errors.New("inbox key ID does not match its public key")
	}

	eph, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return Envelope{}, fmt.Errorf("generate ephemeral key: %w", err)
	}
	shared, err := eph.ECDH(theirKey)
	if err != nil {
		return Envelope{}, fmt.Errorf("derive shared secret: %w", err)
	}

	ephBytes := eph.PublicKey().Bytes()
	key := deriveEnvelopeKey(pub.KeyID[:], ephBytes, shared)
	aead, err := newGCM(key)
	if err != nil {
		return Envelope{}, err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return Envelope{}, fmt.Errorf("generate nonce: %w", err)
	}
	plain, err := json.Marshal(credentialPayload{
		Provider: provider,
		Secret:   secret,
		IssuedAt: time.Now().Unix(),
	})
	if err != nil {
		return Envelope{}, fmt.Errorf("encode credential payload: %w", err)
	}
	return Envelope{
		KeyID:      append([]byte(nil), pub.KeyID[:]...),
		Ephemeral:  ephBytes,
		Nonce:      nonce,
		Ciphertext: aead.Seal(nil, nonce, plain, nil),
	}, nil
}

// deriveEnvelopeKey derives the AES-256 key for one envelope from the ECDH
// shared secret and the public context that identifies the exchange.
func deriveEnvelopeKey(keyID, ephemeral, shared []byte) []byte {
	h := sha256.New()
	h.Write([]byte(CredentialEnvelopeDomain))
	h.Write(keyID)
	h.Write(ephemeral)
	h.Write(shared)
	return h.Sum(nil)
}

func newGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("build AES cipher: %w", err)
	}
	return cipher.NewGCM(block)
}

// credentialPublicJSON is the wire form of InboxPublic: base64 like every
// other byte field on this control plane.
type credentialPublicJSON struct {
	KeyID     string `json:"key_id"`
	PublicKey string `json:"public_key"`
}

// MarshalJSON renders the public inbox key for the /v1/credential-key
// endpoint.
func (p InboxPublic) MarshalJSON() ([]byte, error) {
	return json.Marshal(credentialPublicJSON{
		KeyID:     base64.StdEncoding.EncodeToString(p.KeyID[:]),
		PublicKey: base64.StdEncoding.EncodeToString(p.PublicKey),
	})
}

// UnmarshalJSON parses the published key an agent fetched.
func (p *InboxPublic) UnmarshalJSON(b []byte) error {
	var wire credentialPublicJSON
	if err := json.Unmarshal(b, &wire); err != nil {
		return err
	}
	id, err := base64.StdEncoding.DecodeString(wire.KeyID)
	if err != nil || len(id) != sha256.Size {
		return errors.New("credential key: malformed key ID")
	}
	der, err := base64.StdEncoding.DecodeString(wire.PublicKey)
	if err != nil {
		return errors.New("credential key: malformed public key")
	}
	copy(p.KeyID[:], id)
	p.PublicKey = der
	return nil
}

// CredentialKeyContentType labels the /v1/credential-key response. Both
// credential-plane endpoints speak JSON — this is control traffic, not the
// canonical-CBOR execution seam, and nothing here is hashed or signed.
const CredentialKeyContentType = "application/json"

// ServeCredentialKey publishes the TEE's inbox public key so provider agents
// can fetch it and encrypt their credentials to this exact enclave. The Hub
// relays it to agents; nothing about the private half ever leaves this process.
func ServeCredentialKey(key *InboxKey, w http.ResponseWriter, _ *http.Request) {
	if key == nil {
		http.Error(w, "no inbox key configured", http.StatusServiceUnavailable)
		return
	}
	enc, err := json.Marshal(key.Public())
	if err != nil {
		http.Error(w, "encode credential key: "+err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", CredentialKeyContentType)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(enc)
}

// CredentialKeyRequest is the helper a client (or agent) uses to fetch an
// inbox public key over HTTP.
//
// The one refusal a rotation is allowed to cause is retried here, once, on a
// connection the client's pool cannot supply. Covering it is not a convenience:
// this key is what a provider agent seals its token to, so a rotation that made
// it briefly unobtainable would surface as a registration failing for a reason
// the agent can neither see nor fix. The retry is safe by the same construction
// as /v1/execute's — the listener answers a retired connection before the
// handler runs — and this request is a plain read besides, with no sequence
// number, credential or provider exchange behind it.
func CredentialKeyRequest(ctx context.Context, client *http.Client, url string) (InboxPublic, error) {
	key, err := credentialKeyRequest(ctx, client, url, false)
	if !errors.Is(err, ErrEpochRetired) {
		return key, err
	}
	return credentialKeyRequest(ctx, client, url, true)
}

// credentialKeyRequest performs one fetch. freshConnection asks for a connection
// the pool has not handed over, which is what the retry above needs: every
// pooled connection to a rotating TEE is one a rotation may have retired, and
// the pool does not learn that until it tries to use them.
//
// That takes more than req.Close, which on HTTP/1 only decides whether the
// connection may be kept once the response is back — the pool is consulted on
// the way in without looking at it — so the pool is evicted as well. Eviction
// is what makes the retry dial, and so complete a handshake that postdates the
// rotation, on either protocol.
func credentialKeyRequest(ctx context.Context, client *http.Client, url string, freshConnection bool) (InboxPublic, error) {
	if client == nil {
		client = http.DefaultClient
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return InboxPublic{}, err
	}
	req.Close = freshConnection
	if freshConnection {
		client.CloseIdleConnections()
	}
	resp, err := client.Do(req)
	if err != nil {
		return InboxPublic{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		message := strings.TrimSpace(string(b))
		if resp.StatusCode == http.StatusServiceUnavailable && resp.Header.Get(EpochRetiredHeader) != "" {
			return InboxPublic{}, fmt.Errorf("%w: %s", ErrEpochRetired, message)
		}
		return InboxPublic{}, fmt.Errorf("credential key http %d: %s", resp.StatusCode, message)
	}
	var pub InboxPublic
	if err := json.NewDecoder(resp.Body).Decode(&pub); err != nil {
		return InboxPublic{}, fmt.Errorf("decode credential key: %w", err)
	}
	return pub, nil
}
