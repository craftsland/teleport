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

package common

import (
	"context"
	"fmt"
	"time"

	"github.com/alecthomas/kingpin/v2"
	"github.com/gravitational/trace"

	pb "github.com/gravitational/teleport/api/gen/proto/go/teleport/userexternalsecrets/v1"
	"github.com/gravitational/teleport/api/types"
	"github.com/gravitational/teleport/lib/client"
)

type credCommands struct {
	sync *credSyncCommand
}

func newCredCommands(app *kingpin.Application) credCommands {
	cred := app.Command("cred", "Credential management commands.").Hidden()
	return credCommands{
		sync: newCredSyncCommand(cred),
	}
}

type credSyncCommand struct {
	*kingpin.CmdClause
	targetEncryptionKeyID string
	watch                 bool
	timeout               time.Duration
}

func newCredSyncCommand(parent *kingpin.CmdClause) *credSyncCommand {
	cmd := &credSyncCommand{
		CmdClause: parent.Command("sync", "Sync encrypted credentials to other sessions."),
	}
	cmd.Arg("target-encryption-key-id", "Encryption key ID of a specific target session.").
		StringVar(&cmd.targetEncryptionKeyID)
	cmd.Flag("watch", "Watch for sessions and auto-sync credentials.").
		BoolVar(&cmd.watch)
	cmd.Flag("timeout", "Maximum time to watch (0 means until ctrl-c, only with --watch).").
		Default("0s").
		DurationVar(&cmd.timeout)
	return cmd
}

func (c *credSyncCommand) run(cf *CLIConf) error {
	switch {
	case c.watch:
		return c.runWatch(cf)
	case c.targetEncryptionKeyID != "":
		return c.runTarget(cf)
	default:
		return trace.BadParameter("specify a target key ID or --watch")
	}
}

func (c *credSyncCommand) runTarget(cf *CLIConf) error {
	tc, err := makeClient(cf)
	if err != nil {
		return trace.Wrap(err)
	}

	helper, err := getEncryptionHelper(cf.Context, tc)
	if err != nil {
		return trace.Wrap(err, "no encryption helper available")
	}

	synced, err := syncCredentialsToKey(cf, tc, helper, c.targetEncryptionKeyID)
	if err != nil {
		return trace.Wrap(err)
	}
	if synced == 0 {
		fmt.Fprintln(cf.Stdout(), "Session is up to date.")
	} else {
		fmt.Fprintf(cf.Stdout(), "Synced %d credential(s) to %s\n", synced, c.targetEncryptionKeyID)
	}
	return nil
}

func (c *credSyncCommand) runWatch(cf *CLIConf) error {
	tc, err := makeClient(cf)
	if err != nil {
		return trace.Wrap(err)
	}

	helper, err := getEncryptionHelper(cf.Context, tc)
	if err != nil {
		return trace.Wrap(err, "no encryption helper available")
	}

	profileStatus, err := tc.ProfileStatus()
	if err != nil {
		return trace.Wrap(err)
	}
	myKeyID := getEncryptionKeyID(profileStatus)
	if myKeyID == "" {
		return trace.BadParameter("no encryption key ID found in current profile")
	}

	logger.DebugContext(cf.Context, "Starting credential watcher",
		"my_key_id", myKeyID,
	)

	ctx := cf.Context
	if c.timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(cf.Context, c.timeout)
		defer cancel()
		fmt.Fprintf(cf.Stdout(), "Watching for new encryption keys (timeout %s)...\n", c.timeout)
	} else {
		fmt.Fprintln(cf.Stdout(), "Watching for new encryption keys (ctrl-c to stop)...")
	}

	startTime := time.Now()

	return client.RetryWithRelogin(cf.Context, tc, func() error {
		clusterClient, err := tc.ConnectToCluster(ctx)
		if err != nil {
			return trace.Wrap(err)
		}
		defer clusterClient.Close()

		filter := types.UserEncryptionKeysFilter{User: tc.Username}
		watcher, err := clusterClient.AuthClient.NewWatcher(ctx, types.Watch{
			Kinds: []types.WatchKind{{
				Kind:   types.KindUserEncryptionKeys,
				Filter: filter.IntoMap(),
			}},
		})
		if err != nil {
			return trace.Wrap(err)
		}
		defer watcher.Close()

		for {
			select {
			case event := <-watcher.Events():
				if event.Type != types.OpPut {
					continue
				}
				unwrapper, ok := event.Resource.(types.Resource153UnwrapperT[*pb.UserEncryptionKeys])
				if !ok {
					continue
				}
				keys := unwrapper.UnwrapT()
				for _, key := range keys.GetSpec().GetKeys() {
					keyID := key.GetKeyId()
					if keyID == myKeyID {
						continue
					}
					if createdAt := key.GetCreatedAt(); createdAt != nil && createdAt.AsTime().Before(startTime.Add(-10*time.Second)) {
						continue
					}
					fmt.Fprintf(cf.Stdout(), "New encryption key detected: %s\n", keyID)
					synced, syncErr := syncCredentialsToKey(cf, tc, helper, keyID)
					if syncErr != nil {
						fmt.Fprintf(cf.Stderr(), "Failed to sync to %s: %v\n", keyID, syncErr)
					} else {
						fmt.Fprintf(cf.Stdout(), "Synced %d credential(s) to %s\n", synced, keyID)
					}
				}
			case <-watcher.Done():
				if ctx.Err() != nil {
					fmt.Fprintln(cf.Stdout(), "Watch timeout reached.")
					return nil
				}
				return trace.ConnectionProblem(watcher.Error(), "watcher closed")
			case <-ctx.Done():
				fmt.Fprintln(cf.Stdout(), "Watch stopped.")
				return nil
			}
		}
	})
}

// syncCredentialsToKey lists the caller's secrets from the backend, decrypts
// each one, and creates them for the target session.
func syncCredentialsToKey(cf *CLIConf, tc *client.TeleportClient, helper encryptionHelper, targetKeyID string) (int, error) {
	var synced int
	err := client.RetryWithRelogin(cf.Context, tc, func() error {
		clusterClient, err := tc.ConnectToCluster(cf.Context)
		if err != nil {
			return trace.Wrap(err)
		}
		defer clusterClient.Close()

		secretClient := clusterClient.AuthClient.UserExternalSecretClient()

		// List secrets for this session from the backend.
		logger.DebugContext(cf.Context, "Listing secrets from backend")
		listResp, err := secretClient.ListUserExternalSecrets(cf.Context,
			pb.ListUserExternalSecretsRequest_builder{}.Build())
		if err != nil {
			return trace.Wrap(err, "listing secrets")
		}

		secrets := listResp.GetSecrets()
		if len(secrets) == 0 {
			logger.DebugContext(cf.Context, "No secrets to sync")
			return nil
		}

		logger.DebugContext(cf.Context, "Syncing credentials",
			"target_key", targetKeyID,
			"secrets", len(secrets),
		)

		for _, secret := range secrets {
			oauth := secret.GetSpec().GetOauth()
			if oauth == nil || len(oauth.GetAccessTokenBlob()) == 0 {
				continue
			}

			// Decrypt the ECIES layer to get the auth-encrypted blob.
			accessKMSBlob, err := helper.decrypt(cf.Context, oauth.GetAccessTokenBlob())
			if err != nil {
				logger.WarnContext(cf.Context, "Failed to decrypt access token for sync",
					"resource", secret.GetSpec().GetClientId(),
					"error", err,
				)
				continue
			}

			// Decrypt refresh token if present.
			var refreshKMSBlob []byte
			if len(oauth.GetRefreshTokenBlob()) > 0 {
				refreshKMSBlob, err = helper.decrypt(cf.Context, oauth.GetRefreshTokenBlob())
				if err != nil {
					logger.WarnContext(cf.Context, "Failed to decrypt refresh token for sync",
						"resource", secret.GetSpec().GetClientId(),
						"error", err,
					)
				}
			}

			authSecret := pb.OAuthSecret_builder{
				AccessTokenBlob: accessKMSBlob,
			}
			if len(refreshKMSBlob) > 0 {
				authSecret.RefreshTokenBlob = refreshKMSBlob
			}

			_, err = secretClient.CreateUserExternalSecret(cf.Context,
				pb.CreateUserExternalSecretRequest_builder{
					ResourceKind:          secret.GetSpec().GetSecretType(),
					ResourceName:          secret.GetSpec().GetClientId(),
					TargetEncryptionKeyId: targetKeyID,
					AuthEncryptedSecret:   authSecret.Build(),
				}.Build())
			if err != nil {
				if trace.IsAlreadyExists(err) {
					continue
				}
				logger.WarnContext(cf.Context, "Failed to sync credential",
					"resource", secret.GetSpec().GetClientId(),
					"error", err,
				)
				continue
			}
			synced++
		}
		return nil
	})
	return synced, trace.Wrap(err)
}
