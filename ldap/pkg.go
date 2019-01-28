// Copyright 2019 Decipher Technology Studios
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package ldap

import (
	"crypto/tls"
	"fmt"

	"github.com/go-ldap/ldap"
	"github.com/pkg/errors"
)

// Connector provides a reusable means of establishing a connection to a server.
type Connector struct {
	host   string
	port   int
	secure bool
}

// NewConnector initializes and returns a Connector instance.
func NewConnector(host string, port int, secure bool) *Connector {
	return &Connector{
		host:   host,
		port:   port,
		secure: secure,
	}
}

// Connect connects to the server, binds with the provided distinguished name and password and returns the connection.
func (c *Connector) Connect(distinguishedName string, password string) (*ldap.Conn, error) {

	connection, err := ldap.Dial("tcp", fmt.Sprintf("%s:%d", c.host, c.port))
	if err != nil {
		return nil, errors.Wrapf(err, "error connecting to ldap://%s:%d/", c.host, c.port)
	}

	if c.secure {
		err = connection.StartTLS(&tls.Config{InsecureSkipVerify: true})
		if err != nil {
			return nil, errors.Wrapf(err, "error starting tls connection to ldap://%s:%d/", c.host, c.port)
		}
	}

	err = connection.Bind(distinguishedName, password)
	if err != nil {
		return nil, errors.Wrapf(err, "error binding with distinguished name %s", distinguishedName)
	}

	return connection, nil
}

// Resolver provides a means of resolving distinguished names from a filter template.
type Resolver struct {
	connector         *Connector
	base              string
	template          string
	distinguishedName string
	password          string
}

// NewResolver initializes and returns a Reslover instance.
func NewResolver(connector *Connector, base string, template string, distinguishedName string, password string) *Resolver {
	return &Resolver{
		connector:         connector,
		base:              base,
		template:          template,
		distinguishedName: distinguishedName,
		password:          password,
	}
}

// Resolve evaluates resolves the distinguished names for all entries that match the filter template.
func (r *Resolver) Resolve(values ...interface{}) ([]string, error) {

	connection, err := r.connector.Connect(r.distinguishedName, r.password)
	if err != nil {
		return []string{}, errors.Wrap(err, "error raised opening resolver connection")
	}

	defer connection.Close()

	request := ldap.NewSearchRequest(r.base, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false, fmt.Sprintf(r.template, values...), []string{"dn"}, nil)

	response, err := connection.Search(request)
	if err != nil {
		return []string{}, errors.Wrapf(err, "error raised resolving %s", fmt.Sprintf(r.template, values...))
	}

	distinguishedNames := make([]string, len(response.Entries))
	for index, entry := range response.Entries {
		distinguishedNames[index] = entry.DN
	}

	return distinguishedNames, nil
}

// ChangePassword changes the password for the provided distinguished name.
func ChangePassword(connector *Connector, distinguishedName string, oldPassword string, newPassword string) error {

	connection, err := connector.Connect(distinguishedName, oldPassword)
	if err != nil {
		return errors.Wrap(err, "error raised password change connection")
	}

	defer connection.Close()

	request := ldap.NewPasswordModifyRequest("", oldPassword, newPassword)

	_, err = connection.PasswordModify(request)
	if err != nil {
		return errors.Wrap(err, "error raised changing password")
	}

	return nil
}
