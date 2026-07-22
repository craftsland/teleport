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

	"github.com/gravitational/trace"

	pb "github.com/gravitational/teleport/api/gen/proto/go/teleport/userexternalsecrets/v1"
	"github.com/gravitational/teleport/api/types"
	"github.com/gravitational/teleport/lib/backend"
	"github.com/gravitational/teleport/lib/services"
)

const userEncryptionKeyPrefix = "user_encryption_keys"

// UserEncryptionKeyService manages per-user encryption keys stored as a
// single RFD 153 resource per user.
type UserEncryptionKeyService struct {
	backend backend.Backend
}

// NewUserEncryptionKeyService returns a new UserEncryptionKeyService.
func NewUserEncryptionKeyService(b backend.Backend) *UserEncryptionKeyService {
	return &UserEncryptionKeyService{backend: b}
}

func (s *UserEncryptionKeyService) backendKey(user string) backend.Key {
	return backend.NewKey(userEncryptionKeyPrefix, user)
}

// Get returns the encryption keys resource for a user.
func (s *UserEncryptionKeyService) Get(ctx context.Context, user string) (*pb.UserEncryptionKeys, error) {
	item, err := s.backend.Get(ctx, s.backendKey(user))
	if err != nil {
		return nil, trace.Wrap(err)
	}
	resource, err := services.UnmarshalProtoResource[*pb.UserEncryptionKeys](item.Value)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	resource.GetMetadata().Revision = item.Revision
	return resource, nil
}

// Create creates a new encryption keys resource for a user. Returns
// AlreadyExists if one exists.
func (s *UserEncryptionKeyService) Create(ctx context.Context, resource *pb.UserEncryptionKeys) (*pb.UserEncryptionKeys, error) {
	value, err := services.MarshalProtoResource(resource)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	item := backend.Item{
		Key:   s.backendKey(resource.GetMetadata().GetName()),
		Value: value,
	}
	if exp := resource.GetMetadata().GetExpires(); exp != nil && exp.IsValid() {
		item.Expires = exp.AsTime()
	}
	lease, err := s.backend.Create(ctx, item)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	resource.GetMetadata().Revision = lease.Revision
	return resource, nil
}

// Update updates an existing encryption keys resource. Uses the revision
// for compare-and-swap. Returns CompareFailed on revision mismatch.
func (s *UserEncryptionKeyService) Update(ctx context.Context, resource *pb.UserEncryptionKeys) (*pb.UserEncryptionKeys, error) {
	value, err := services.MarshalProtoResource(resource)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	item := backend.Item{
		Key:      s.backendKey(resource.GetMetadata().GetName()),
		Value:    value,
		Revision: resource.GetMetadata().GetRevision(),
	}
	if exp := resource.GetMetadata().GetExpires(); exp != nil && exp.IsValid() {
		item.Expires = exp.AsTime()
	}
	lease, err := s.backend.ConditionalUpdate(ctx, item)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	resource.GetMetadata().Revision = lease.Revision
	return resource, nil
}

// Delete removes the encryption keys resource for a user.
func (s *UserEncryptionKeyService) Delete(ctx context.Context, user string) error {
	return trace.Wrap(s.backend.Delete(ctx, s.backendKey(user)))
}

func newUserEncryptionKeysParser(m map[string]string) (*userEncryptionKeysParser, error) {
	var filter types.UserEncryptionKeysFilter
	if err := filter.FromMap(m); err != nil {
		return nil, trace.Wrap(err)
	}
	return &userEncryptionKeysParser{
		baseParser: newBaseParser(backend.NewKey(userEncryptionKeyPrefix)),
		filter:     filter,
	}, nil
}

type userEncryptionKeysParser struct {
	baseParser
	filter types.UserEncryptionKeysFilter
}

func (p *userEncryptionKeysParser) parse(event backend.Event) (types.Resource, error) {
	switch event.Type {
	case types.OpDelete:
		components := event.Item.Key.Components()
		if len(components) < 2 {
			return nil, trace.NotFound("failed parsing %v", event.Item.Key.String())
		}
		return &types.ResourceHeader{
			Kind:    types.KindUserEncryptionKeys,
			Version: types.V1,
			Metadata: types.Metadata{
				Name: components[1],
			},
		}, nil
	case types.OpPut:
		resource, err := services.UnmarshalProtoResource[*pb.UserEncryptionKeys](event.Item.Value)
		if err != nil {
			return nil, trace.Wrap(err)
		}
		if !p.filter.Match(resource.GetMetadata().GetName()) {
			return nil, nil
		}
		return types.Resource153ToLegacy(resource), nil
	default:
		return nil, trace.BadParameter("event %v is not supported", event.Type)
	}
}

// GetKey returns a specific key by ID for the given user.
func (s *UserEncryptionKeyService) GetKey(ctx context.Context, user, keyID string) (*pb.EncryptionKeyEntry, error) {
	resource, err := s.Get(ctx, user)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	for _, k := range resource.GetSpec().GetKeys() {
		if k.GetKeyId() == keyID {
			return k, nil
		}
	}
	return nil, trace.NotFound("encryption key %s not found for user %s", keyID, user)
}
