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

package userexternalsecretsv1

import (
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"log/slog"

	"github.com/gravitational/trace"
	"google.golang.org/protobuf/types/known/timestamppb"

	headerv1 "github.com/gravitational/teleport/api/gen/proto/go/teleport/header/v1"
	pb "github.com/gravitational/teleport/api/gen/proto/go/teleport/userexternalsecrets/v1"
	"github.com/gravitational/teleport/api/types"
	"github.com/gravitational/teleport/lib/authz"
	"github.com/gravitational/teleport/lib/backend"
	"github.com/gravitational/teleport/lib/cryptoutils"
	"github.com/gravitational/teleport/lib/services/local"
)

// SecretDecryptor decrypts auth-encrypted secret blobs.
type SecretDecryptor interface {
	DecryptTokens(ctx context.Context, ciphertext []byte) (accessToken, refreshToken string, err error)
}

// ServiceConfig holds configuration for the UserExternalSecretService.
type ServiceConfig struct {
	Authorizer     authz.Authorizer
	Backend        backend.Backend
	SecretDecryptor SecretDecryptor
	Logger         *slog.Logger
}

// Service implements the UserExternalSecretService gRPC service.
type Service struct {
	pb.UnimplementedUserExternalSecretServiceServer

	authorizer     authz.Authorizer
	backend        backend.Backend
	tokenDecryptor SecretDecryptor
	logger         *slog.Logger
}

// NewService creates a new UserExternalSecretService.
func NewService(cfg ServiceConfig) (*Service, error) {
	if cfg.Authorizer == nil {
		return nil, trace.BadParameter("authorizer is required")
	}
	if cfg.Backend == nil {
		return nil, trace.BadParameter("backend is required")
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	return &Service{
		authorizer:     cfg.Authorizer,
		backend:        cfg.Backend,
		tokenDecryptor: cfg.SecretDecryptor,
		logger:         cfg.Logger,
	}, nil
}

// getCallerEncryptionKeyID extracts the encryption key ID from the caller's
// TLS certificate identity.
func getCallerEncryptionKeyID(authCtx *authz.Context) string {
	return authCtx.Identity.GetIdentity().EncryptionKeyID
}

// GetUserExternalSecret returns the double-encrypted secret for the calling
// user's current session. The session is identified by the encryption key ID
// in the caller's TLS certificate.
func (s *Service) GetUserExternalSecret(ctx context.Context, req *pb.GetUserExternalSecretRequest) (*pb.GetUserExternalSecretResponse, error) {
	authCtx, err := s.authorizer.Authorize(ctx)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	resourceKind := req.GetResourceKind()
	resourceName := req.GetResourceName()
	if resourceKind == "" || resourceName == "" {
		return nil, trace.BadParameter("resource_kind and resource_name are required")
	}

	encryptionKeyID := req.GetEncryptionKeyId()
	if encryptionKeyID == "" {
		encryptionKeyID = getCallerEncryptionKeyID(authCtx)
	}
	if encryptionKeyID == "" {
		return nil, trace.BadParameter("encryption key ID not provided and not found in caller's certificate")
	}

	username := authCtx.User.GetName()
	tokenSvc := local.NewUserExternalSecretService(s.backend)
	secret, err := tokenSvc.Get(ctx, username, resourceName, encryptionKeyID)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	s.logger.DebugContext(ctx, "Retrieved encrypted secret",
		"user", username,
		"resource_kind", resourceKind,
		"resource_name", resourceName,
		"encryption_key_id", encryptionKeyID,
	)

	return pb.GetUserExternalSecretResponse_builder{
		Secret: secret,
	}.Build(), nil
}

// CreateUserExternalSecret creates a double-encrypted secret for a target
// session. The caller sends auth-encrypted (KMS) blobs. Auth validates the
// blob hashes, encrypts with the target session's public key, and stores.
func (s *Service) CreateUserExternalSecret(ctx context.Context, req *pb.CreateUserExternalSecretRequest) (*pb.CreateUserExternalSecretResponse, error) {
	authCtx, err := s.authorizer.Authorize(ctx)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	resourceKind := req.GetResourceKind()
	resourceName := req.GetResourceName()
	targetKeyID := req.GetTargetEncryptionKeyId()
	authEncryptedSecret := req.GetAuthEncryptedSecret()

	if resourceKind == "" || resourceName == "" || targetKeyID == "" {
		return nil, trace.BadParameter("resource_kind, resource_name, and target_encryption_key_id are required")
	}
	if authEncryptedSecret == nil || len(authEncryptedSecret.GetAccessTokenBlob()) == 0 {
		return nil, trace.BadParameter("auth_encrypted_secret with access_token_blob is required")
	}

	username := authCtx.User.GetName()

	// Verify the auth-encrypted blob hash matches existing secrets.
	callerKeyID := getCallerEncryptionKeyID(authCtx)
	if callerKeyID != "" {
		tokenSvc := local.NewUserExternalSecretService(s.backend)
		existingSecret, err := tokenSvc.Get(ctx, username, resourceName, callerKeyID)
		if err == nil && existingSecret.GetSpec().GetOauth() != nil {
			// TODO(greedy52) verify hash of auth-encrypted blob matches
			// the status hash from the caller's existing secret.
			s.logger.DebugContext(ctx, "Existing secret found for caller, verifying hash",
				"caller_key_id", callerKeyID,
			)
		}
	}

	// Check if the target session already has a secret for this resource.
	tokenSvc := local.NewUserExternalSecretService(s.backend)
	if _, err := tokenSvc.Get(ctx, username, resourceName, targetKeyID); err == nil {
		return nil, trace.AlreadyExists("secret already exists for key %s and resource %s", targetKeyID, resourceName)
	}

	// Look up the target session's encryption public key.
	encKeySvc := local.NewUserEncryptionKeyService(s.backend)
	targetKey, err := encKeySvc.GetKey(ctx, username, targetKeyID)
	if err != nil {
		return nil, trace.Wrap(err, "target encryption key not found")
	}

	// Parse the target's public key.
	pubKey, err := x509.ParsePKIXPublicKey(targetKey.GetPublicKey())
	if err != nil {
		return nil, trace.Wrap(err, "parsing target public key")
	}
	ecdsaPub, ok := pubKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, trace.BadParameter("target encryption key is not ECDSA P-256")
	}

	// ECIES-encrypt the auth-encrypted access token blob for the target session.
	doubleEncryptedAccess, err := cryptoutils.ECIESEncrypt(ecdsaPub, authEncryptedSecret.GetAccessTokenBlob())
	if err != nil {
		return nil, trace.Wrap(err, "encrypting access token for target session")
	}

	// ECIES-encrypt the refresh token blob if present.
	var doubleEncryptedRefresh []byte
	if refreshBlob := authEncryptedSecret.GetRefreshTokenBlob(); len(refreshBlob) > 0 {
		doubleEncryptedRefresh, err = cryptoutils.ECIESEncrypt(ecdsaPub, refreshBlob)
		if err != nil {
			return nil, trace.Wrap(err, "encrypting refresh token for target session")
		}
	}

	// Compute hashes of the auth-encrypted blobs for the status.
	accessHash := sha256.Sum256(authEncryptedSecret.GetAccessTokenBlob())
	var refreshHash []byte
	if len(authEncryptedSecret.GetRefreshTokenBlob()) > 0 {
		h := sha256.Sum256(authEncryptedSecret.GetRefreshTokenBlob())
		refreshHash = h[:]
	}

	// Store the double-encrypted token with TTL matching the encryption key.
	var expires *timestamppb.Timestamp
	if exp := targetKey.GetExpires(); exp != nil && exp.IsValid() {
		expires = exp
	}
	secret := pb.UserExternalSecret_builder{
		Kind:    "user_external_secret",
		Version: "v1",
		Metadata: &headerv1.Metadata{
			Name:    targetKeyID,
			Expires: expires,
		},
		Spec: pb.UserExternalSecretSpec_builder{
			User:       username,
			SecretType: resourceKind,
			ClientId:   resourceName,
			PublicKey:  targetKey.GetPublicKey(),
			Oauth: pb.OAuthSecret_builder{
				AccessTokenBlob:  doubleEncryptedAccess,
				RefreshTokenBlob: doubleEncryptedRefresh,
			}.Build(),
		}.Build(),
		Status: pb.UserExternalSecretStatus_builder{
			Oauth: pb.OAuthSecretStatus_builder{
				AccessTokenHash:  accessHash[:],
				RefreshTokenHash: refreshHash,
			}.Build(),
		}.Build(),
	}.Build()

	tokenSvc = local.NewUserExternalSecretService(s.backend)
	if err := tokenSvc.Upsert(ctx, secret); err != nil {
		return nil, trace.Wrap(err)
	}

	s.logger.DebugContext(ctx, "Created encrypted secret for target session",
		"user", username,
		"resource_kind", resourceKind,
		"resource_name", resourceName,
		"target_key_id", targetKeyID,
	)

	return pb.CreateUserExternalSecretResponse_builder{
		Secret: secret,
	}.Build(), nil
}

// ListUserExternalSecrets returns all secrets for the calling user's encryption
// key. The key ID is read from the caller's TLS certificate.
func (s *Service) ListUserExternalSecrets(ctx context.Context, req *pb.ListUserExternalSecretsRequest) (*pb.ListUserExternalSecretsResponse, error) {
	authCtx, err := s.authorizer.Authorize(ctx)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	encryptionKeyID := getCallerEncryptionKeyID(authCtx)
	if encryptionKeyID == "" {
		return nil, trace.BadParameter("caller's certificate does not contain an encryption key ID")
	}

	username := authCtx.User.GetName()
	tokenSvc := local.NewUserExternalSecretService(s.backend)
	allSecrets, err := tokenSvc.ListByUser(ctx, username)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	var secrets []*pb.UserExternalSecret
	for _, secret := range allSecrets {
		if secret.GetMetadata().GetName() == encryptionKeyID {
			secrets = append(secrets, secret)
		}
	}

	s.logger.DebugContext(ctx, "Listed user external secrets",
		"user", username,
		"encryption_key_id", encryptionKeyID,
		"count", len(secrets),
	)

	return pb.ListUserExternalSecretsResponse_builder{
		Secrets: secrets,
	}.Build(), nil
}

// DecryptUserExternalSecret decrypts an auth-encrypted secret blob. The caller
// must be a trusted service (e.g. proxy). Auth verifies the encrypted payload
// binding (user + resource) before returning the plaintext.
func (s *Service) DecryptUserExternalSecret(ctx context.Context, req *pb.DecryptUserExternalSecretRequest) (*pb.DecryptUserExternalSecretResponse, error) {
	authCtx, err := s.authorizer.Authorize(ctx)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	if !authz.HasBuiltinRole(*authCtx, string(types.RoleProxy)) {
		return nil, trace.AccessDenied("DecryptUserExternalSecret is only available to proxy services")
	}

	authEncryptedBlob := req.GetAuthEncryptedBlob()
	if len(authEncryptedBlob) == 0 {
		return nil, trace.BadParameter("auth_encrypted_blob is required")
	}

	if s.tokenDecryptor == nil {
		return nil, trace.NotImplemented("token decryption is not configured")
	}

	payloadJSON, _, err := s.tokenDecryptor.DecryptTokens(ctx, authEncryptedBlob)
	if err != nil {
		return nil, trace.Wrap(err, "decrypting auth-encrypted blob")
	}

	payload, err := cryptoutils.UnmarshalEncryptedPayload([]byte(payloadJSON))
	if err != nil {
		return nil, trace.Wrap(err, "unmarshaling encrypted payload")
	}

	username := authCtx.Identity.GetIdentity().Username
	if payload.User != username {
		return nil, trace.AccessDenied("secret does not belong to this user")
	}

	s.logger.DebugContext(ctx, "Decrypted user external secret",
		"user", username,
		"resource_kind", payload.Resource.Kind,
		"resource_name", payload.Resource.Name,
	)

	return pb.DecryptUserExternalSecretResponse_builder{
		Plaintext: payload.Payload,
	}.Build(), nil
}

// SyncUserExternalSecrets syncs the caller's secrets to other sessions using
// the client as a decrypt oracle. Auth reads the caller's double-encrypted
// secrets, asks the client to decrypt them, then re-encrypts for target
// sessions.
func (s *Service) SyncUserExternalSecrets(stream pb.UserExternalSecretService_SyncUserExternalSecretsServer) error {
	ctx := stream.Context()
	authCtx, err := s.authorizer.Authorize(ctx)
	if err != nil {
		return trace.Wrap(err)
	}

	// Wait for the initial sync request.
	msg, err := stream.Recv()
	if err != nil {
		return trace.Wrap(err)
	}
	syncReq := msg.GetSyncRequest()
	if syncReq == nil {
		return trace.BadParameter("first message must be a sync_request")
	}

	username := authCtx.User.GetName()
	callerKeyID := getCallerEncryptionKeyID(authCtx)
	if callerKeyID == "" {
		return trace.BadParameter("caller's certificate does not contain an encryption key ID")
	}
	targetKeyID := syncReq.GetTargetEncryptionKeyId()

	// Get all encryption keys to find targets.
	encKeySvc := local.NewUserEncryptionKeyService(s.backend)
	keysResource, err := encKeySvc.Get(ctx, username)
	if err != nil {
		return trace.Wrap(err, "getting encryption keys")
	}

	// Get all secrets for the caller's key.
	tokenSvc := local.NewUserExternalSecretService(s.backend)
	allSecrets, err := tokenSvc.ListByUser(ctx, username)
	if err != nil {
		return trace.Wrap(err, "listing caller's secrets")
	}
	// Filter to secrets belonging to the caller's key.
	var callerSecrets []*pb.UserExternalSecret
	for _, s := range allSecrets {
		if s.GetMetadata().GetName() == callerKeyID {
			callerSecrets = append(callerSecrets, s)
		}
	}
	if len(callerSecrets) == 0 {
		return nil
	}

	// Determine target keys.
	var targetKeys []*pb.EncryptionKeyEntry
	for _, key := range keysResource.GetSpec().GetKeys() {
		kid := key.GetKeyId()
		if kid == callerKeyID {
			continue
		}
		if targetKeyID != "" && kid != targetKeyID {
			continue
		}
		targetKeys = append(targetKeys, key)
	}

	// For each secret, ask the client to decrypt, then re-encrypt for each target.
	for _, secret := range callerSecrets {
		oauth := secret.GetSpec().GetOauth()
		if oauth == nil || len(oauth.GetAccessTokenBlob()) == 0 {
			continue
		}
		resourceName := secret.GetSpec().GetClientId()

		// Ask client to decrypt the access token blob.
		if err := stream.Send(pb.SyncUserExternalSecretsResponse_builder{
			DecryptRequest: pb.SyncDecryptRequest_builder{
				Ciphertext:      oauth.GetAccessTokenBlob(),
				ResourceKind: secret.GetSpec().GetSecretType(),
				ResourceName:    resourceName,
			}.Build(),
		}.Build()); err != nil {
			return trace.Wrap(err)
		}

		resp, err := stream.Recv()
		if err != nil {
			return trace.Wrap(err)
		}
		decryptResp := resp.GetDecryptResponse()
		if decryptResp == nil {
			return trace.BadParameter("expected decrypt_response")
		}
		accessKMSBlob := decryptResp.GetPlaintext()

		// Decrypt refresh token if present.
		var refreshKMSBlob []byte
		if len(oauth.GetRefreshTokenBlob()) > 0 {
			if err := stream.Send(pb.SyncUserExternalSecretsResponse_builder{
				DecryptRequest: pb.SyncDecryptRequest_builder{
					Ciphertext:      oauth.GetRefreshTokenBlob(),
					ResourceKind: secret.GetSpec().GetSecretType(),
					ResourceName:    resourceName,
				}.Build(),
			}.Build()); err != nil {
				return trace.Wrap(err)
			}

			resp, err := stream.Recv()
			if err != nil {
				return trace.Wrap(err)
			}
			decryptResp := resp.GetDecryptResponse()
			if decryptResp == nil {
				return trace.BadParameter("expected decrypt_response for refresh token")
			}
			refreshKMSBlob = decryptResp.GetPlaintext()
		}

		// Re-encrypt for each target key.
		for _, targetKey := range targetKeys {
			pubKey, err := x509.ParsePKIXPublicKey(targetKey.GetPublicKey())
			if err != nil {
				s.logger.WarnContext(ctx, "Skipping target with invalid public key",
					"target_key", targetKey.GetKeyId(), "error", err)
				continue
			}
			ecdsaPub, ok := pubKey.(*ecdsa.PublicKey)
			if !ok {
				continue
			}

			doubleEncryptedAccess, err := cryptoutils.ECIESEncrypt(ecdsaPub, accessKMSBlob)
			if err != nil {
				s.logger.WarnContext(ctx, "Failed to encrypt for target",
					"target_key", targetKey.GetKeyId(), "error", err)
				continue
			}

			var doubleEncryptedRefresh []byte
			if len(refreshKMSBlob) > 0 {
				doubleEncryptedRefresh, err = cryptoutils.ECIESEncrypt(ecdsaPub, refreshKMSBlob)
				if err != nil {
					s.logger.WarnContext(ctx, "Failed to encrypt refresh for target",
						"target_key", targetKey.GetKeyId(), "error", err)
					continue
				}
			}

			targetSecret := pb.UserExternalSecret_builder{
				Kind:    "user_external_secret",
				SubKind: "",
				Version: "v1",
				Metadata: &headerv1.Metadata{
					Name: targetKey.GetKeyId(),
				},
				Spec: pb.UserExternalSecretSpec_builder{
					User:       username,
					SecretType: secret.GetSpec().GetSecretType(),
					ClientId:   resourceName,
					PublicKey:  targetKey.GetPublicKey(),
					Oauth: pb.OAuthSecret_builder{
						AccessTokenBlob:  doubleEncryptedAccess,
						RefreshTokenBlob: doubleEncryptedRefresh,
					}.Build(),
				}.Build(),
			}.Build()

			if exp := targetKey.GetExpires(); exp != nil && exp.IsValid() {
				targetSecret.GetMetadata().Expires = exp
			}

			// Skip if already exists.
			if _, err := tokenSvc.Get(ctx, username, resourceName, targetKey.GetKeyId()); err == nil {
				continue
			}
			if err := tokenSvc.Upsert(ctx, targetSecret); err != nil {
				s.logger.WarnContext(ctx, "Failed to store synced secret",
					"target_key", targetKey.GetKeyId(),
					"resource", resourceName,
					"error", err)
			}
		}
	}

	return nil
}
