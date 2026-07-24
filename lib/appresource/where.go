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
	match, err := w.expression.Evaluate(newEnv(request, identity))
	if err != nil {
		return false, trace.Wrap(err)
	}
	return match, nil
}

// env holds the values one where clause evaluation reads, and the
// state the audit wrappers record into.
type env struct {
	request Request
	user    Identity
	state   *evalState
}

// evalState holds the side effects of one evaluation for the caller. It
// is held by pointer so the same instance is observed across the whole
// expression tree, even though env is passed by value. On error the
// state may be partially populated and must be discarded. allowCode is
// meaningful only when the evaluation returned true, and denyHints only
// when it returned false.
type evalState struct {
	// allowCode and allowReason hold the last successful allow_code call.
	allowCode   string
	allowReason string
	// denyHints records deny_hint calls in evaluation order.
	denyHints []Hint
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
			// allow_code records an audit code and reason and returns the
			// wrapped boolean, so it never flips the result. The record is
			// committed only when the wrapped expression is true. When
			// several allow_code calls fire on one evaluation, the last one
			// wins.
			"allow_code": typical.TernaryFunctionWithEnv(func(e env, code, reason string, expr bool) (bool, error) {
				if err := validateAuditCode(code); err != nil {
					return false, trace.Wrap(err)
				}
				if expr {
					e.state.allowCode = code
					e.state.allowReason = reason
				}
				return expr, nil
			}),
			// deny_hint records a near-miss hint and returns the wrapped
			// boolean, so it never flips the result. The hint is committed
			// only when the call is reached and the wrapped expression is
			// false. Under &&, that is the near-miss where the conditions on
			// its left matched but this one did not.
			"deny_hint": typical.TernaryFunctionWithEnv(func(e env, code, reason string, expr bool) (bool, error) {
				if err := validateAuditCode(code); err != nil {
					return false, trace.Wrap(err)
				}
				if !expr {
					e.state.denyHints = append(e.state.denyHints, Hint{Code: code, Reason: reason})
				}
				return expr, nil
			}),
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

// predicate is a parsed, type-checked app-access predicate ready to
// evaluate. A rule lowers to one predicate, and an
// app_resources_expressions entry compiles to one directly.
type predicate = typical.Expression[env, bool]

// compilePredicate parses and type-checks a predicate, and runs the
// compile-time audit code validation. Unlike CompileWhere it accepts
// the full predicate language, including the audit wrappers.
func compilePredicate(expr string) (predicate, error) {
	pred, err := whereParser.Parse(expr)
	if err != nil {
		return nil, trace.BadParameter("compiling predicate %q: %v", expr, err)
	}
	if err := validateAuditCodes(expr); err != nil {
		return nil, trace.Wrap(err, "compiling predicate %q", expr)
	}
	return pred, nil
}

// newEnv builds a fresh evaluation environment for one request. The
// state is fresh per call, so concurrent evaluations never share
// recorded codes or hints.
func newEnv(request Request, identity Identity) env {
	return env{
		request: request,
		user:    identity,
		state:   &evalState{},
	}
}
