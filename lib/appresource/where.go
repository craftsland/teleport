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
	"slices"
	"strings"

	"github.com/gravitational/trace"

	"github.com/gravitational/teleport/lib/utils/typical"
)

// Request is the HTTP request a where clause is evaluated against. It
// is a struct rather than an *http.Request, because a clause can be
// checked against a role file without an HTTP request.
type Request struct {
	Method string
}

// Identity is the caller a where clause is evaluated against.
type Identity struct {
	Name   string
	Roles  []string
	Traits map[string][]string
}

// Where is a compiled where clause. Only CompileWhere returns a usable
// value, since the zero value holds no compiled clause. Evaluation
// writes nothing back to a Where, so one serves concurrent requests.
type Where struct {
	expression typical.Expression[env, bool]
}

// CompileWhere parses and type-checks a where clause.
func CompileWhere(expr string) (*Where, error) {
	expression, err := whereParser.Parse(expr)
	if err != nil {
		return nil, trace.BadParameter("compiling where clause %q: %v", expr, err)
	}
	return &Where{expression: expression}, nil
}

// Evaluate reports whether the where clause matches the request and
// the caller identity. On error it reports no match, so a caller that
// ignores the error denies rather than allows.
func (w *Where) Evaluate(request Request, identity Identity) (bool, error) {
	match, err := w.expression.Evaluate(env{request: request, user: identity})
	if err != nil {
		return false, trace.Wrap(err)
	}
	return match, nil
}

// env holds the values one where clause evaluation reads.
type env struct {
	request Request
	user    Identity
}

// whereParser is the shared cached parser for where clauses. It
// registers the app-access bindings on the generic typical parser.
var whereParser = mustNewWhereParser()

// mustNewWhereParser builds the where clause parser and panics if the
// spec is invalid, which can only be a mistake in the spec below.
func mustNewWhereParser() *typical.CachedParser[env, bool] {
	p, err := typical.NewCachedParser[env, bool](typical.ParserSpec[env]{
		Variables: map[string]typical.Variable{
			// true and false are bound because typical has no bool literal.
			"true":  true,
			"false": false,
			"user.name": typical.DynamicVariable(func(e env) (string, error) {
				return e.user.Name, nil
			}),
			"user.roles": typical.DynamicVariable(func(e env) ([]string, error) {
				return e.user.Roles, nil
			}),
			"user.traits": typical.DynamicMapFunction(func(e env, key string) ([]string, error) {
				return e.user.Traits[key], nil
			}),
			// request.method is the raw client method, so a comparison is
			// case-sensitive. Fold with lower or upper, negations included.
			"request.method": typical.DynamicVariable(func(e env) (string, error) {
				return e.request.Method, nil
			}),
		},
		Functions: map[string]typical.Function{
			// set is a collection of strings for contains membership
			// tests. Both match the functions of the same names in the
			// role where-clause language, services.NewWhereParser.
			"set": typical.UnaryVariadicFunction[env](func(args ...string) ([]string, error) {
				return args, nil
			}),
			// typical wraps a bare string argument in a one-element
			// list, so contains over a string binding such as user.name
			// tests equality rather than substring. has_substring is the
			// substring test.
			"contains": typical.BinaryFunction[env](func(list []string, item string) (bool, error) {
				return slices.Contains(list, item), nil
			}),
			// lower and upper support case-insensitive comparison in a
			// where clause.
			"lower": typical.UnaryFunction[env](func(s string) (string, error) {
				return strings.ToLower(s), nil
			}),
			"upper": typical.UnaryFunction[env](func(s string) (string, error) {
				return strings.ToUpper(s), nil
			}),
			// has_prefix, has_suffix, and has_substring search within a
			// string.
			"has_prefix": typical.BinaryFunction[env](func(s, prefix string) (bool, error) {
				return strings.HasPrefix(s, prefix), nil
			}),
			"has_suffix": typical.BinaryFunction[env](func(s, suffix string) (bool, error) {
				return strings.HasSuffix(s, suffix), nil
			}),
			"has_substring": typical.BinaryFunction[env](func(s, substr string) (bool, error) {
				return strings.Contains(s, substr), nil
			}),
		},
	})
	if err != nil {
		panic(trace.Wrap(err, "building the where clause parser (this is a bug)"))
	}
	return p
}
