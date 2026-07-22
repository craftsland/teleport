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

package local

import (
	"context"
	"log/slog"
	"time"

	"github.com/google/uuid"
	"github.com/gravitational/trace"

	userexternalsecretsv1 "github.com/gravitational/teleport/api/gen/proto/go/teleport/userexternalsecrets/v1"
	"github.com/gravitational/teleport/lib/backend"
	"github.com/gravitational/teleport/lib/services"
)

const userExternalSecretPrefix = "user_external_secret"

// EncryptionKeyIDFromPubKey derives a session encryption key ID from the
// public key bytes as a UUID v5.
func EncryptionKeyIDFromPubKey(pubKeyDER []byte) string {
	return uuid.NewSHA1(uuid.NameSpaceOID, pubKeyDER).String()
}

// UserExternalSecretService manages per-session double-encrypted secrets
// using the UserExternalSecret proto resource.
type UserExternalSecretService struct {
	backend backend.Backend
}

// NewUserExternalSecretService returns a new UserExternalSecretService.
func NewUserExternalSecretService(b backend.Backend) *UserExternalSecretService {
	return &UserExternalSecretService{backend: b}
}

// backend key: user_external_secret/<user>/<resource_name>/<encryption_key_id>
func (s *UserExternalSecretService) backendKey(user, resourceName, encryptionKeyID string) backend.Key {
	return backend.NewKey(userExternalSecretPrefix, user, resourceName, encryptionKeyID)
}

// Upsert creates or updates a UserExternalSecret. The metadata name must be
// set to the encryption key ID under which the secret is stored.
func (s *UserExternalSecretService) Upsert(ctx context.Context, secret *userexternalsecretsv1.UserExternalSecret) error {
	value, err := services.MarshalProtoResource(secret)
	if err != nil {
		return trace.Wrap(err)
	}

	spec := secret.GetSpec()
	encryptionKeyID := secret.GetMetadata().GetName()

	item := backend.Item{
		Key:   s.backendKey(spec.GetUser(), spec.GetClientId(), encryptionKeyID),
		Value: value,
	}
	if expires := secret.GetMetadata().GetExpires(); expires != nil && expires.IsValid() {
		expiry := expires.AsTime()
		if !expiry.IsZero() && expiry.After(time.Now()) {
			item.Expires = expiry
		}
	}
	_, err = s.backend.Put(ctx, item)
	return trace.Wrap(err)
}

// Get returns a UserExternalSecret by its identifiers.
func (s *UserExternalSecretService) Get(ctx context.Context, user, resourceName, encryptionKeyID string) (*userexternalsecretsv1.UserExternalSecret, error) {
	item, err := s.backend.Get(ctx, s.backendKey(user, resourceName, encryptionKeyID))
	if err != nil {
		return nil, trace.Wrap(err)
	}
	secret, err := services.UnmarshalProtoResource[*userexternalsecretsv1.UserExternalSecret](item.Value)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	return secret, nil
}

// Delete removes a UserExternalSecret.
func (s *UserExternalSecretService) Delete(ctx context.Context, user, resourceName, encryptionKeyID string) error {
	return trace.Wrap(s.backend.Delete(ctx, s.backendKey(user, resourceName, encryptionKeyID)))
}

// ListByUser returns all UserExternalSecrets for a given user.
func (s *UserExternalSecretService) ListByUser(ctx context.Context, user string) ([]*userexternalsecretsv1.UserExternalSecret, error) {
	startKey := backend.NewKey(userExternalSecretPrefix, user)
	items := s.backend.Items(ctx, backend.ItemsParams{
		StartKey: startKey,
		EndKey:   backend.RangeEnd(startKey),
	})

	var secrets []*userexternalsecretsv1.UserExternalSecret
	for item, err := range items {
		if err != nil {
			return nil, trace.Wrap(err)
		}
		secret, err := services.UnmarshalProtoResource[*userexternalsecretsv1.UserExternalSecret](item.Value)
		if err != nil {
			slog.WarnContext(ctx, "Failed to unmarshal user external secret", "key", item.Key.String(), "error", err)
			continue
		}
		secrets = append(secrets, secret)
	}
	return secrets, nil
}

// ListByUserAndResource returns all UserExternalSecrets for a given user and resource.
func (s *UserExternalSecretService) ListByUserAndResource(ctx context.Context, user, resourceName string) ([]*userexternalsecretsv1.UserExternalSecret, error) {
	startKey := backend.NewKey(userExternalSecretPrefix, user, resourceName)
	items := s.backend.Items(ctx, backend.ItemsParams{
		StartKey: startKey,
		EndKey:   backend.RangeEnd(startKey),
	})

	var secrets []*userexternalsecretsv1.UserExternalSecret
	for item, err := range items {
		if err != nil {
			return nil, trace.Wrap(err)
		}
		secret, err := services.UnmarshalProtoResource[*userexternalsecretsv1.UserExternalSecret](item.Value)
		if err != nil {
			slog.WarnContext(ctx, "Failed to unmarshal user external secret", "key", item.Key.String(), "error", err)
			continue
		}
		secrets = append(secrets, secret)
	}
	return secrets, nil
}
