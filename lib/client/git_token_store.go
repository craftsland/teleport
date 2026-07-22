/*
 * Teleport
 * Copyright (C) 2026  Gravitational, Inc.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

package client

import (
	"encoding/json"
	"os"
	"path/filepath"
	"time"

	"github.com/gravitational/trace"

	"github.com/gravitational/teleport/api/profile"
)

// UserSecretData holds double-encrypted secret data cached locally.
// The token is ECIES(KMS(plaintext)) -- both encryption layers intact.
// Decryption of the ECIES layer happens on demand via the encryption
// private key (regular tsh) or the encryption agent (beams).
type UserSecretData struct {
	// DoubleEncryptedToken is the ECIES-wrapped KMS-encrypted token.
	DoubleEncryptedToken []byte `json:"double_encrypted_token"`
	// AuthEncryptedToken is the KMS-encrypted token (ECIES layer stripped).
	// Deprecated: use DoubleEncryptedToken. Kept for backward compatibility
	// during migration.
	AuthEncryptedToken []byte    `json:"auth_encrypted_token,omitempty"`
	ExpiresAt          time.Time `json:"expires_at"`
	ResourceName       string    `json:"resource_name"`
}

// userSecretPath returns the path where the auth-encrypted secret is stored, e.g.
// ~/.tsh/user_secrets/example.com/mycluster/github-my-org.json
func userSecretPath(homePath, proxyHost, cluster, resourceName string) string {
	return filepath.Join(profile.FullProfilePath(homePath), "user_secrets", proxyHost, cluster, resourceName+".json")
}

// SaveUserSecret saves an auth-encrypted secret to the local profile.
func SaveUserSecret(homePath, proxyHost, cluster string, data *UserSecretData) error {
	path := userSecretPath(homePath, proxyHost, cluster, data.ResourceName)
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return trace.Wrap(err)
	}
	raw, err := json.Marshal(data)
	if err != nil {
		return trace.Wrap(err)
	}
	return trace.Wrap(os.WriteFile(path, raw, 0600))
}

// LoadUserSecret loads an auth-encrypted secret from the local profile.
// Returns nil if the secret doesn't exist or is expired.
func LoadUserSecret(homePath, proxyHost, cluster, resourceName string) (*UserSecretData, error) {
	path := userSecretPath(homePath, proxyHost, cluster, resourceName)
	raw, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, trace.Wrap(err)
	}
	var data UserSecretData
	if err := json.Unmarshal(raw, &data); err != nil {
		return nil, trace.Wrap(err)
	}
	return &data, nil
}

// DeleteUserSecret removes a cached secret.
func DeleteUserSecret(homePath, proxyHost, cluster, resourceName string) error {
	path := userSecretPath(homePath, proxyHost, cluster, resourceName)
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return trace.Wrap(err)
	}
	return nil
}
