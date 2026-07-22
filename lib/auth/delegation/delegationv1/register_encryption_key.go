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

package delegationv1

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/gravitational/trace"
	"google.golang.org/protobuf/types/known/timestamppb"

	delegationv1 "github.com/gravitational/teleport/api/gen/proto/go/teleport/delegation/v1"
	pb "github.com/gravitational/teleport/api/gen/proto/go/teleport/userexternalsecrets/v1"
	"github.com/gravitational/teleport/lib/services"
)

// RegisterEncryptionKey registers an ECIES P-256 encryption public key scoped
// to a delegation session. The key TTL matches the delegation session's expiry.
func (s *SessionService) RegisterEncryptionKey(
	ctx context.Context,
	req *delegationv1.RegisterEncryptionKeyRequest,
) (*delegationv1.RegisterEncryptionKeyResponse, error) {
	authCtx, err := s.authorizer.Authorize(ctx)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	if s.encryptionKeyWriter == nil {
		return nil, trace.NotImplemented("encryption key registration is not configured")
	}

	if len(req.GetPublicKey()) == 0 {
		return nil, trace.BadParameter("public_key is required")
	}
	if req.GetDelegationSessionId() == "" {
		return nil, trace.BadParameter("delegation_session_id is required")
	}

	session, err := s.sessionReader.GetDelegationSession(ctx, req.GetDelegationSessionId())
	switch {
	case trace.IsNotFound(err):
		return nil, ErrDelegationUnauthorized
	case err != nil:
		return nil, trace.Wrap(err)
	}

	if session.GetMetadata().GetExpires().AsTime().Add(ClockSkewAllowance).Before(time.Now()) {
		return nil, ErrDelegationUnauthorized
	}

	if err := s.authorizeSession(ctx, authCtx, session); err != nil {
		return nil, err
	}

	username := session.GetSpec().GetUser()
	identity := authCtx.Identity.GetIdentity()
	keyID := delegationEncryptionKeyID(identity.BotInstanceID, req.GetDelegationSessionId())

	encKey := pb.EncryptionKeyEntry_builder{
		KeyId:     keyID,
		PublicKey: req.GetPublicKey(),
		CreatedAt: timestamppb.Now(),
		Expires:   session.GetMetadata().GetExpires(),
	}.Build()

	if err := services.UpsertUserEncryptionKey(ctx, s.encryptionKeyWriter, username, encKey); err != nil {
		return nil, trace.Wrap(err)
	}

	s.logger.InfoContext(ctx, "Registered encryption key for delegation session",
		"user", username,
		"delegation_session_id", req.GetDelegationSessionId(),
		"encryption_key_id", keyID,
	)

	return &delegationv1.RegisterEncryptionKeyResponse{
		EncryptionKeyId: keyID,
	}, nil
}

// delegationEncryptionKeyID derives a deterministic encryption key ID from
// the bot instance ID and delegation session ID. This ensures one bot instance
// + one delegation session maps to exactly one encryption key.
func delegationEncryptionKeyID(botInstanceID, delegationSessionID string) string {
	return uuid.NewSHA1(uuid.NameSpaceOID, []byte(botInstanceID+"/"+delegationSessionID)).String()
}
