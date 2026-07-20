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

package appresource

import (
	"strconv"
	"testing"

	"github.com/stretchr/testify/require"
)

func evaluate(t *testing.T, expr string, request Request, identity Identity) bool {
	t.Helper()
	where, err := CompileWhere(expr)
	require.NoError(t, err)
	got, err := where.Evaluate(request, identity)
	require.NoError(t, err)
	return got
}

func TestEnvBindings(t *testing.T) {
	identity := Identity{
		Name:   "alice",
		Roles:  []string{"dev", "access"},
		Traits: map[string][]string{"allowed_projects": {"acme", "widgets"}},
	}
	tests := []struct {
		expr string
		want bool
	}{
		{`true`, true},
		{`false`, false},
		{`user.name == "alice"`, true},
		{`user.name == "bob"`, false},
		{`contains(user.roles, "dev")`, true},
		{`contains(user.roles, "admin")`, false},
		{`contains(user.traits["allowed_projects"], "acme")`, true},
		{`contains(user.traits["allowed_projects"], "secret")`, false},
		{`contains(user.traits["missing"], "acme")`, false},
		{`contains(user.traits.allowed_projects, "acme")`, true},
		{`request.method == "GET"`, true},
		{`request.method != "GET"`, false},
		// A comparison against request.method is case-sensitive.
		{`request.method == "get"`, false},
		{`user.name == "alice" && request.method == "GET"`, true},
		{`user.name == "bob" || contains(user.roles, "access")`, true},
		{`!contains(user.roles, "admin")`, true},
		{`contains(set("alice", "bob"), user.name)`, true},
		{`contains(set(), user.name)`, false},
	}
	for _, tt := range tests {
		t.Run(tt.expr, func(t *testing.T) {
			require.Equal(t, tt.want, evaluate(t, tt.expr, Request{Method: "GET"}, identity))
		})
	}
}

// TestInvalidPredicateRejected pins that an identifier outside the where
// environment, a name outside its function set, an argument of the wrong
// type, and a malformed expression all fail at compile, so a typo cannot
// silently evaluate.
func TestInvalidPredicateRejected(t *testing.T) {
	for _, expr := range []string{
		// Bindings the where environment does not provide in this
		// version, including paths and the vars capture namespace.
		`request.path == "/api"`,
		`vars.project == "acme"`,
		`user.nope == "x"`,
		// Names outside the function set. Regular expressions are
		// excluded deliberately.
		`regex_match("a.*", user.name)`,
		`equals(user.name, "alice")`,
		// Arguments of the wrong type, and a predicate that yields
		// something other than a boolean.
		`has_prefix(user.roles, "svc-")`,
		`lower(user.roles)`,
		`set("dev") == "dev"`,
		`user.name`,
		// Malformed expressions, including the empty predicate, which
		// never stands for allow-everything.
		``,
		` `,
		`user.name ==`,
		`&& true`,
		`contains(user.roles, )`,
	} {
		t.Run(expr, func(t *testing.T) {
			_, err := CompileWhere(expr)
			require.ErrorContains(t, err, strconv.Quote(expr))
		})
	}
}

func TestLowerUpper(t *testing.T) {
	const lowered = `contains(set("get", "head"), lower(request.method))`
	const uppered = `contains(set("GET", "HEAD"), upper(request.method))`

	tests := []struct {
		method string
		want   bool
	}{
		{"GET", true},
		{"get", true},
		{"GeT", true},
		{"DELETE", false},
		{"delete", false},
	}
	for _, tt := range tests {
		t.Run(tt.method, func(t *testing.T) {
			require.Equal(t, tt.want, evaluate(t, lowered, Request{Method: tt.method}, Identity{}))
			require.Equal(t, tt.want, evaluate(t, uppered, Request{Method: tt.method}, Identity{}))
		})
	}

	// The lower function folds case the way strings.ToLower does, beyond ASCII.
	require.True(t, evaluate(t, `lower(user.name) == "münchen"`, Request{}, Identity{Name: "MÜNCHEN"}))
}

func TestContainsOnStringBinding(t *testing.T) {
	identity := Identity{Name: "alice"}
	require.True(t, evaluate(t, `contains(user.name, "alice")`, Request{}, identity))
	require.False(t, evaluate(t, `contains(user.name, "ali")`, Request{}, identity))
	require.True(t, evaluate(t, `has_substring(user.name, "ali")`, Request{}, identity))
}

func TestSubstringFuncs(t *testing.T) {
	identity := Identity{Name: "svc-ci-runner"}
	tests := []struct {
		expr string
		want bool
	}{
		{`has_prefix(user.name, "svc-")`, true},
		{`has_prefix(user.name, "usr-")`, false},
		{`has_suffix(user.name, "-runner")`, true},
		{`has_suffix(user.name, "-admin")`, false},
		{`has_substring(user.name, "-ci-")`, true},
		{`has_substring(user.name, "-qa-")`, false},
	}
	for _, tt := range tests {
		t.Run(tt.expr, func(t *testing.T) {
			require.Equal(t, tt.want, evaluate(t, tt.expr, Request{Method: "GET"}, identity))
		})
	}
}
