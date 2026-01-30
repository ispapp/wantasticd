package cipher

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"strconv"
	"time"
)

const (
	HeaderTimestamp = "x-wantastic-ts"
	HeaderSignature = "x-wantastic-sig"
	SharedSecret    = "Wantastic_v1_Rolling_Code_Secret"
)

// EncryptedCredentials implements credentials.PerRPCCredentials
// It adds HMAC-SHA256 signature to every request.
type EncryptedCredentials struct {
	secret []byte
}

func NewCredentials() *EncryptedCredentials {
	return &EncryptedCredentials{
		secret: []byte(SharedSecret),
	}
}

// GetRequestMetadata adds the timestamp and signature to the request metadata
func (c *EncryptedCredentials) GetRequestMetadata(ctx context.Context, uri ...string) (map[string]string, error) {
	timestamp := strconv.FormatInt(time.Now().Unix(), 10)

	mac := hmac.New(sha256.New, c.secret)
	mac.Write([]byte(timestamp))
	signature := hex.EncodeToString(mac.Sum(nil))

	return map[string]string{
		HeaderTimestamp: timestamp,
		HeaderSignature: signature,
	}, nil
}

// RequireTransportSecurity indicates whether TLS is required (Yes, highly recommended despite cipher)
func (c *EncryptedCredentials) RequireTransportSecurity() bool {
	return true
}
