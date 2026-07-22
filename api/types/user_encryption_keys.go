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

package types

// UserEncryptionKeysFilter is a filter for watching user encryption keys.
type UserEncryptionKeysFilter struct {
	User string
}

const userEncryptionKeysFilterKeyUser = "user"

// IntoMap copies filter values into a map.
func (f *UserEncryptionKeysFilter) IntoMap() map[string]string {
	m := make(map[string]string)
	if f.User != "" {
		m[userEncryptionKeysFilterKeyUser] = f.User
	}
	return m
}

// FromMap copies filter values from a map.
func (f *UserEncryptionKeysFilter) FromMap(m map[string]string) error {
	f.User = m[userEncryptionKeysFilterKeyUser]
	return nil
}

// Match returns true if the resource matches the filter.
func (f *UserEncryptionKeysFilter) Match(name string) bool {
	if f.User == "" {
		return true
	}
	return f.User == name
}
