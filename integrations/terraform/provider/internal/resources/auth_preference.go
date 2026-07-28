// Teleport
// Copyright (C) 2026 Gravitational, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

package resources

import (
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"

	"github.com/gravitational/teleport/api/types"
	apitypes "github.com/gravitational/teleport/api/types"

	"github.com/gravitational/teleport/integrations/terraform/provider/internal/teleport"
	"github.com/gravitational/teleport/integrations/terraform/provider/internal/tfdriver"
	"github.com/gravitational/teleport/integrations/terraform/tfschema"
)

// NewAuthPreferenceDataSourceType returns the cluster auth preference data source type.
func NewAuthPreferenceDataSourceType() tfdriver.DataSourceType[apitypes.AuthPreferenceV2, tfdriver.SingletonIdentifier] {
	return tfdriver.DataSourceType[apitypes.AuthPreferenceV2, tfdriver.SingletonIdentifier]{
		NewDataSourceClient: func(p tfsdk.Provider) tfdriver.DataSourceClient[apitypes.AuthPreferenceV2, tfdriver.SingletonIdentifier] {
			return teleport.NewAuthPreferenceClient(clientFromProvider(p))
		},
		Kind: apitypes.KindClusterAuthPreference,
		Codec: tfdriver.DataSourceCodecFuncs[apitypes.AuthPreferenceV2]{
			SchemaFunc:  tfschema.GenSchemaAuthPreferenceV2,
			ToStateFunc: tfschema.CopyAuthPreferenceV2ToTerraform,
		},
		Identifier: tfdriver.SingletonIdentifierFromName(types.MetaNameClusterAuthPreference),
	}
}

// NewAuthPreferenceResourceType returns the app resource type.
func NewAuthPreferenceResourceType() tfdriver.ResourceType[apitypes.AuthPreferenceV2, tfdriver.SingletonIdentifier] {
	return tfdriver.ResourceType[apitypes.AuthPreferenceV2, tfdriver.SingletonIdentifier]{
		NewResourceClient: func(p tfsdk.Provider) tfdriver.ResourceClient[apitypes.AuthPreferenceV2, tfdriver.SingletonIdentifier] {
			return teleport.NewAuthPreferenceClient(clientFromProvider(p))
		},
		Kind: apitypes.KindClusterAuthPreference,
		Codec: tfdriver.ResourceCodecFuncs[apitypes.AuthPreferenceV2]{
			SchemaFunc:   tfschema.GenSchemaAuthPreferenceV2,
			ToStateFunc:  tfschema.CopyAuthPreferenceV2ToTerraform,
			FromPlanFunc: tfschema.CopyAuthPreferenceV2FromTerraform,
		},
		Normalizer: tfdriver.CheckAndSetDefaults[apitypes.AuthPreferenceV2](),
		Identifier: tfdriver.SingletonIdentifierPolicy[apitypes.AuthPreferenceV2](types.MetaNameClusterAuthPreference),
		ResourceRevision: func(st *apitypes.AuthPreferenceV2) string {
			return st.GetMetadata().Revision
		},
	}
}
