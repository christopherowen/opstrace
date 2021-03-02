// Copyright 2021 Opstrace, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"fmt"
	"io"
	"net/http"

	"github.com/gorilla/mux"
	log "github.com/sirupsen/logrus"
	"gopkg.in/yaml.v2"

	"github.com/opstrace/opstrace/go/pkg/graphql"
)

// Information about a credential. Custom type which omits the tenant field.
// This also given some extra protection that the value isn't disclosed,
// even if it was mistakenly added to the underlying graphql interface.
type CredentialInfo struct {
	Name      string `yaml:"name"`
	Type      string `yaml:"type,omitempty"`
	CreatedAt string `yaml:"created_at,omitempty"`
	UpdatedAt string `yaml:"updated_at,omitempty"`
}

func listCredentials(tenant string, w http.ResponseWriter, r *http.Request) {
	resp, err := credentialAccess.List(tenant)
	if err != nil {
		log.Warnf("Listing credentials failed: %s", err)
		http.Error(w, fmt.Sprintf("Listing credentials failed: %s", err), http.StatusInternalServerError)
		return
	}

	log.Debugf("Listing %d credentials", len(resp.Credential))

	encoder := yaml.NewEncoder(w)
	for _, credential := range resp.Credential {
		encoder.Encode(CredentialInfo{
			Name:      credential.Name,
			Type:      credential.Type,
			CreatedAt: credential.CreatedAt,
			UpdatedAt: credential.UpdatedAt,
		})
	}
}

// Full credential entry (with secret value) received from a POST request.
type Credential struct {
	Name  string      `yaml:"name"`
	Type  string      `yaml:"type"`
	Value interface{} `yaml:"value"` // nested yaml, or payload string, depending on type
}

func writeCredentials(tenant string, w http.ResponseWriter, r *http.Request) {
	decoder := yaml.NewDecoder(r.Body)
	// Return error for unrecognized or duplicate fields in the input
	decoder.SetStrict(true)

	// Collect list of existing names so that we can decide between insert vs update
	existingTypes := make(map[string]string)
	resp, err := credentialAccess.List(tenant)
	if err != nil {
		log.Warnf("Listing credentials failed: %s", err)
		http.Error(w, fmt.Sprintf("Listing credentials failed: %s", err), http.StatusInternalServerError)
		return
	}
	for _, credential := range resp.Credential {
		existingTypes[credential.Name] = credential.Type
	}

	now := nowTimestamp()

	var inserts []graphql.CredentialInsertInput
	var updates []graphql.UpdateCredentialVariables
	for {
		var yamlCredential Credential
		err := decoder.Decode(&yamlCredential)
		if err != nil {
			if err != io.EOF {
				log.Debugf("Decoding credential input at index=%d failed: %s", len(inserts)+len(updates), err)
				http.Error(w, fmt.Sprintf(
					"Decoding credential input at index=%d failed: %s", len(inserts)+len(updates), err,
				), http.StatusBadRequest)
				return
			}
			break
		}
		name := graphql.String(yamlCredential.Name)
		credType := graphql.String(yamlCredential.Type)
		value, err := convertCredValue(yamlCredential.Name, yamlCredential.Type, yamlCredential.Value)
		if err != nil {
			log.Debugf("Invalid credential value format: %s", err)
			http.Error(w, fmt.Sprintf("Credential format validation failed: %s", err), http.StatusBadRequest)
			return
		}
		if existingType, ok := existingTypes[yamlCredential.Name]; ok {
			// Explicitly check and complain if the user tries to change the credential type
			if yamlCredential.Type != "" && existingType != yamlCredential.Type {
				log.Debugf("Invalid credential '%s' type change", yamlCredential.Name)
				http.Error(w, fmt.Sprintf(
					"Credential '%s' type cannot be updated (current=%s, updated=%s)",
					yamlCredential.Name, existingType, yamlCredential.Type,
				), http.StatusBadRequest)
				return
			}
			// TODO check for no-op updates and skip them (and avoid unnecessary changes to UpdatedAt)
			updates = append(updates, graphql.UpdateCredentialVariables{
				Name:      name,
				Value:     *value,
				UpdatedAt: now,
			})
		} else {
			inserts = append(inserts, graphql.CredentialInsertInput{
				Name:      &name,
				Type:      &credType,
				Value:     value,
				CreatedAt: &now,
				UpdatedAt: &now,
			})
		}
	}

	if len(inserts)+len(updates) == 0 {
		log.Debugf("Writing credentials: No data provided")
		http.Error(w, "Missing credential YAML data in request body", http.StatusBadRequest)
		return
	}

	log.Debugf("Writing credentials: %d insert, %d update", len(inserts), len(updates))

	if len(inserts) != 0 {
		err := credentialAccess.Insert(tenant, inserts)
		if err != nil {
			log.Warnf("Insert: %d credentials failed: %s", len(inserts), err)
			http.Error(w, fmt.Sprintf("Creating %d credentials failed: %s", len(inserts), err), http.StatusInternalServerError)
			return
		}
	}
	if len(updates) != 0 {
		for _, update := range updates {
			err := credentialAccess.Update(tenant, update)
			if err != nil {
				log.Warnf("Update: Credential %s failed: %s", update.Name, err)
				http.Error(w, fmt.Sprintf("Updating credential %s failed: %s", update.Name, err), http.StatusInternalServerError)
				return
			}
		}
	}
}

func getCredential(tenant string, w http.ResponseWriter, r *http.Request) {
	name := mux.Vars(r)["name"]
	log.Debugf("Getting credential: %s", name)

	resp, err := credentialAccess.Get(tenant, name)
	if err != nil {
		log.Warnf("Get: Credential %s failed: %s", name, err)
		http.Error(w, fmt.Sprintf("Getting credential failed: %s", err), http.StatusInternalServerError)
		return
	}
	if resp == nil {
		log.Debugf("Get: Credential %s not found", name)
		http.Error(w, fmt.Sprintf("Credential not found: %s", name), http.StatusNotFound)
		return
	}

	encoder := yaml.NewEncoder(w)
	encoder.Encode(CredentialInfo{
		Name:      resp.CredentialByPk.Name,
		Type:      resp.CredentialByPk.Type,
		CreatedAt: resp.CredentialByPk.CreatedAt,
		UpdatedAt: resp.CredentialByPk.UpdatedAt,
	})
}

func deleteCredential(tenant string, w http.ResponseWriter, r *http.Request) {
	name := mux.Vars(r)["name"]
	log.Debugf("Deleting credential: %s", name)

	resp, err := credentialAccess.Delete(tenant, name)
	if err != nil {
		log.Warnf("Delete: Credential %s failed: %s", name, err)
		http.Error(w, fmt.Sprintf("Deleting credential failed: %s", err), http.StatusInternalServerError)
		return
	}
	if resp == nil {
		log.Debugf("Delete: Credential %s not found", name)
		http.Error(w, fmt.Sprintf("Credential not found: %s", name), http.StatusNotFound)
		return
	}

	encoder := yaml.NewEncoder(w)
	encoder.Encode(CredentialInfo{Name: resp.DeleteCredentialByPk.Name})
}
