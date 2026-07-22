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

package services

import (
	"context"
	"time"

	"github.com/gravitational/trace"
	"google.golang.org/protobuf/types/known/timestamppb"

	headerv1 "github.com/gravitational/teleport/api/gen/proto/go/teleport/header/v1"
	pb "github.com/gravitational/teleport/api/gen/proto/go/teleport/userexternalsecrets/v1"
)

const (
	// DefaultMaxEncryptionKeys is the default maximum number of encryption
	// keys a user can register.
	DefaultMaxEncryptionKeys = 50
)

// UserEncryptionKeys is the interface for managing per-user encryption keys.
type UserEncryptionKeys interface {
	// Get returns the encryption keys resource for a user.
	Get(ctx context.Context, user string) (*pb.UserEncryptionKeys, error)
	// Create creates a new encryption keys resource for a user.
	Create(ctx context.Context, resource *pb.UserEncryptionKeys) (*pb.UserEncryptionKeys, error)
	// Update updates an existing encryption keys resource with CAS.
	Update(ctx context.Context, resource *pb.UserEncryptionKeys) (*pb.UserEncryptionKeys, error)
	// Delete removes the encryption keys resource for a user.
	Delete(ctx context.Context, user string) error
	// GetKey returns a specific key by ID for the given user.
	GetKey(ctx context.Context, user, keyID string) (*pb.EncryptionKeyEntry, error)
}

// UpsertUserEncryptionKey adds or updates a single encryption key for a user.
// It handles the read-modify-write cycle with retry on conflict, expired key
// cleanup, and max key limit enforcement.
func UpsertUserEncryptionKey(ctx context.Context, svc UserEncryptionKeys, user string, entry *pb.EncryptionKeyEntry) error {
	const maxRetries = 5
	for i := range maxRetries {
		err := tryUpsertUserEncryptionKey(ctx, svc, user, entry)
		if err == nil {
			return nil
		}
		if !trace.IsCompareFailed(err) || i == maxRetries-1 {
			return trace.Wrap(err)
		}
	}
	return trace.LimitExceeded("too much contention updating encryption keys for user %s", user)
}

func tryUpsertUserEncryptionKey(ctx context.Context, svc UserEncryptionKeys, user string, entry *pb.EncryptionKeyEntry) error {
	now := time.Now()

	resource, err := svc.Get(ctx, user)
	isNew := trace.IsNotFound(err)
	if isNew {
		resource = pb.UserEncryptionKeys_builder{
			Kind:    "user_encryption_keys",
			Version: "v1",
			Metadata: &headerv1.Metadata{
				Name: user,
			},
			Spec: pb.UserEncryptionKeysSpec_builder{}.Build(),
		}.Build()
	} else if err != nil {
		return trace.Wrap(err)
	}

	// Drop expired keys and update/add the new key.
	var active []*pb.EncryptionKeyEntry
	found := false
	for _, k := range resource.GetSpec().GetKeys() {
		if exp := k.GetExpires(); exp != nil && exp.IsValid() && now.After(exp.AsTime()) {
			continue
		}
		if k.GetKeyId() == entry.GetKeyId() {
			active = append(active, entry)
			found = true
		} else {
			active = append(active, k)
		}
	}
	if !found {
		active = append(active, entry)
	}

	// Enforce max limit by evicting oldest keys.
	for len(active) > DefaultMaxEncryptionKeys {
		oldestIdx := 0
		for i, k := range active {
			if k.GetCreatedAt().AsTime().Before(active[oldestIdx].GetCreatedAt().AsTime()) {
				oldestIdx = i
			}
		}
		active = append(active[:oldestIdx], active[oldestIdx+1:]...)
	}

	resource.GetSpec().SetKeys(active)

	// Set resource TTL to the latest key expiry.
	var latestExpiry time.Time
	for _, k := range active {
		if exp := k.GetExpires(); exp != nil && exp.IsValid() {
			if t := exp.AsTime(); t.After(latestExpiry) {
				latestExpiry = t
			}
		}
	}
	if !latestExpiry.IsZero() {
		resource.GetMetadata().Expires = timestamppb.New(latestExpiry)
	}

	if isNew {
		_, err = svc.Create(ctx, resource)
		if trace.IsAlreadyExists(err) {
			return trace.CompareFailed("concurrent create")
		}
	} else {
		_, err = svc.Update(ctx, resource)
	}
	return trace.Wrap(err)
}
