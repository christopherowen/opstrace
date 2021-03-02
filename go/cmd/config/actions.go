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
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"

	log "github.com/sirupsen/logrus"
)

type ActionHandler struct {
	alertmanagerURL  *url.URL
	tenantHeaderName string
}

func NewActionHandler(alertmanagerURL *url.URL, tenantHeaderName string) ActionHandler {
	return ActionHandler{
		alertmanagerURL,
		tenantHeaderName,
	}
}

func (ah *ActionHandler) Handler(w http.ResponseWriter, r *http.Request) {
	var reqjson interface{}
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&reqjson); err != nil {
		http.Error(w, fmt.Sprintf("Invalid json body: %s", err), http.StatusBadRequest)
		log.Warnf("%s %s: Bad JSON payload", r.Method, r.URL.String())
		return
	}
	log.Infof("%s %s: %v", r.Method, r.URL.String(), reqjson)

	// TODO implement GetAlertmanagerConfig, SetAlertmanagerConfig: route to cortex GET,POST /api/v1/alerts: https://cortexmetrics.io/docs/api/#get-alertmanager-configuration
	// TODO implement ValidateCredential, ValidateExporter
}

func (ah *ActionHandler) getAlertmanagerConfig(tenant string) (string, error) {
	// TODO GET <alertmanagerURL>/api/v1/alerts
	return "", nil
}

func (ah *ActionHandler) setAlertmanagerConfig(tenant string, config string) error {
	// TODO POST <alertmanagerURL>/api/v1/alerts
	return nil
}

func (ah *ActionHandler) validateCredential(name string, credType string, value string) error {
	_, err := convertCredValue(name, credType, value)
	if err != nil {
		log.Debugf("Invalid credential value format: %s", err)
	}
	// TODO other validation in credential.go - checking existing credential type
	return err
}

func (ah *ActionHandler) validateExporter(name string, expType string, credential *string, value string) error {
	// TODO validation from exporter.go - involves checking for credentials and existing exporter type
	// TODO check existing exporter
	return nil
}
