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
	"flag"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/gorilla/mux"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	log "github.com/sirupsen/logrus"

	"github.com/opstrace/opstrace/go/pkg/config"
	"github.com/opstrace/opstrace/go/pkg/graphql"
	"github.com/opstrace/opstrace/go/pkg/middleware"
)

const actionSecretHeaderName string = "X-Action-Secret"
const cortexTenantHeaderName string = "X-Scope-OrgID"

var (
	credentialAccess         config.CredentialAccess
	exporterAccess           config.ExporterAccess
	disableAPIAuthentication bool
)

func main() {
	var loglevel string
	flag.StringVar(&loglevel, "loglevel", "info", "error|info|debug")
	var listenAddress string
	flag.StringVar(&listenAddress, "listen", "", "")
	var actionAddress string
	flag.StringVar(&actionAddress, "action", "", "")

	flag.BoolVar(&disableAPIAuthentication, "disable-api-authn", false, "")

	flag.Parse()

	level, lerr := log.ParseLevel(loglevel)
	if lerr != nil {
		log.Fatalf("bad --loglevel: %s", lerr)
	}
	log.SetLevel(level)

	if listenAddress == "" {
		log.Fatalf("missing required --listen")
	}
	log.Infof("listen address: %s", listenAddress)
	log.Infof("action hook address: %s", actionAddress)

	cortexDefault := "http://localhost"
	rulerURL := envEndpointURL("CORTEX_RULER_ENDPOINT", &cortexDefault)
	log.Infof("cortex ruler URL: %v", rulerURL)
	alertmanagerURL := envEndpointURL("CORTEX_ALERTMANAGER_ENDPOINT", &cortexDefault)
	log.Infof("cortex alertmanager URL: %v", alertmanagerURL)

	graphqlDefault := "http://localhost:8080/v1/graphql"
	graphqlURL := envEndpointURL("GRAPHQL_ENDPOINT", &graphqlDefault)
	log.Infof("graphql URL: %v", graphqlURL)

	graphqlSecret := os.Getenv("HASURA_GRAPHQL_ADMIN_SECRET")
	if graphqlSecret == "" {
		log.Fatalf("missing required HASURA_GRAPHQL_ADMIN_SECRET")
	}

	credentialAccess = config.NewCredentialAccess(graphqlURL, graphqlSecret)
	exporterAccess = config.NewExporterAccess(graphqlURL, graphqlSecret)

	if disableAPIAuthentication {
		log.Infof("authentication disabled, use '%s' header in requests to specify tenant", middleware.TestTenantHeader)
	} else {
		// Requires API_AUTHTOKEN_VERIFICATION_PUBKEY
		log.Info("authentication enabled")
		middleware.ReadAuthTokenVerificationKeyFromEnvOrCrash()
	}

	if actionAddress != "" {
		go func() {
			expectedSecret := os.Getenv("HASURA_ACTION_SECRET")
			handler := NewActionHandler(alertmanagerURL, cortexTenantHeaderName)
			err := http.ListenAndServe(actionAddress, actionRouter(&handler, expectedSecret))
			log.Fatalf("action listener terminated: %v", err)
		}()
	}
	err := http.ListenAndServe(listenAddress, apiRouter(rulerURL, alertmanagerURL))
	log.Fatalf("API listener terminated: %v", err)
}

func apiRouter(rulerURL *url.URL, alertmanagerURL *url.URL) http.Handler {
	router := mux.NewRouter()

	// Cortex config, see: https://github.com/cortexproject/cortex/blob/master/docs/api/_index.md

	// Cortex Ruler config
	rulerPathReplacement := func(requrl *url.URL) string {
		// Route /api/v1/ruler* requests to /ruler* on the backend
		// Note: /api/v1/rules does not need to change on the way to the backend.
		if replaced := replacePathPrefix(requrl, "/api/v1/ruler", "/ruler"); replaced != nil {
			return *replaced
		}
		return requrl.Path
	}
	rulerProxy := middleware.NewReverseProxyDynamicTenant(
		cortexTenantHeaderName,
		rulerURL,
		disableAPIAuthentication,
	).ReplacePaths(rulerPathReplacement)
	router.PathPrefix("/api/v1/ruler").HandlerFunc(rulerProxy.HandleWithProxy)
	router.PathPrefix("/api/v1/rules").HandlerFunc(rulerProxy.HandleWithProxy)

	// Cortex Alertmanager config
	alertmanagerPathReplacement := func(requrl *url.URL) string {
		// NOTE: We leave /api/v1/alertmanager for the Alertmanager UI as-is.
		// By default Cortex would serve it at /alertmanager, but we configure it via 'api.alertmanager-http-prefix'.
		// This avoids us needing to rewrite HTTP responses to fix e.g. any absolute img/href URLs.
		// SEE ALSO: controller/src/resources/cortex/index.ts

		// Route /api/v1/multitenant_alertmanager* requests to /multitenant_alertmanager* on the backend.
		// Unlike with /alertmanager, this doesn't appear to involve a UI and just has status endpoints.
		if replaced := replacePathPrefix(
			requrl,
			"/api/v1/multitenant_alertmanager",
			"/multitenant_alertmanager",
		); replaced != nil {
			return *replaced
		}
		return requrl.Path
	}
	alertmanagerProxy := middleware.NewReverseProxyDynamicTenant(
		cortexTenantHeaderName,
		alertmanagerURL,
		disableAPIAuthentication,
	).ReplacePaths(alertmanagerPathReplacement)
	router.PathPrefix("/api/v1/alerts").HandlerFunc(alertmanagerProxy.HandleWithProxy)
	router.PathPrefix("/api/v1/alertmanager").HandlerFunc(alertmanagerProxy.HandleWithProxy)
	router.PathPrefix("/api/v1/multitenant_alertmanager").HandlerFunc(alertmanagerProxy.HandleWithProxy)

	// Credentials/exporters: Specify exact paths, but manually allow with and without a trailing '/'
	credentials := router.PathPrefix("/api/v1/credentials").Subrouter()
	setupConfigAPI(credentials, listCredentials, writeCredentials, getCredential, deleteCredential)
	exporters := router.PathPrefix("/api/v1/exporters").Subrouter()
	setupConfigAPI(exporters, listExporters, writeExporters, getExporter, deleteExporter)

	return router
}

func replacePathPrefix(url *url.URL, from string, to string) *string {
	if strings.HasPrefix(url.Path, from) {
		replaced := strings.Replace(url.Path, from, to, 1)
		return &replaced
	}
	return nil
}

func envEndpointURL(envName string, defaultEndpoint *string) *url.URL {
	endpoint := os.Getenv(envName)
	if endpoint == "" {
		if defaultEndpoint == nil {
			log.Fatalf("missing required %s", envName)
		} else {
			// Try default (dev/testing)
			endpoint = *defaultEndpoint
			log.Warnf("missing %s, trying %s", envName, endpoint)
		}
	}

	endpointURL, uerr := url.Parse(endpoint)
	if uerr != nil {
		log.Fatalf("bad %s: %s", envName, uerr)
	}
	return endpointURL
}

// setupAPI configures GET/POST/DELETE endpoints for the provided handler callbacks.
// The paths are configured to be exact, with optional trailing slashes.
func setupConfigAPI(
	router *mux.Router,
	listFunc func(string, http.ResponseWriter, *http.Request),
	writeFunc func(string, http.ResponseWriter, *http.Request),
	getFunc func(string, http.ResponseWriter, *http.Request),
	deleteFunc func(string, http.ResponseWriter, *http.Request),
) {
	// Ensure that each call is authenticated before proceeding
	router.HandleFunc("", getTenantThenCall(listFunc)).Methods("GET")
	router.HandleFunc("/", getTenantThenCall(listFunc)).Methods("GET")
	router.HandleFunc("", getTenantThenCall(writeFunc)).Methods("POST")
	router.HandleFunc("/", getTenantThenCall(writeFunc)).Methods("POST")
	router.HandleFunc("/{name}", getTenantThenCall(getFunc)).Methods("GET")
	router.HandleFunc("/{name}/", getTenantThenCall(getFunc)).Methods("GET")
	router.HandleFunc("/{name}", getTenantThenCall(deleteFunc)).Methods("DELETE")
	router.HandleFunc("/{name}/", getTenantThenCall(deleteFunc)).Methods("DELETE")
}

// Wraps `f` in a preceding check that authenticates the request headers for the expected tenant name.
// The check is skipped if `disableAPIAuthentication` is true.
func getTenantThenCall(f func(string, http.ResponseWriter, *http.Request)) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		tenantName, ok := middleware.GetTenant(w, r, nil, disableAPIAuthentication)
		if !ok {
			return
		}
		f(tenantName, w, r)
	}
}

func actionRouter(handler *ActionHandler, expectedActionSecret string) http.Handler {
	router := mux.NewRouter()

	// Run metrics off of this separate endpoint so that it's not accessible via the public ingress
	router.Handle("/metrics", promhttp.Handler())

	if expectedActionSecret == "" {
		log.Infof("%s validation is disabled", actionSecretHeaderName)
	}
	router.PathPrefix("/").HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// If expectedSecret is empty, then the header isn't required
		gotSecret := r.Header.Get(actionSecretHeaderName)
		if expectedActionSecret != "" && gotSecret != expectedActionSecret {
			http.Error(w, fmt.Sprintf("Missing or invalid %s", actionSecretHeaderName), http.StatusUnauthorized)
			return
		}
		handler.Handler(w, r)
	})

	return router
}

// Returns a string representation of the current time in UTC, suitable for passing to Hasura as a timestamptz
// See also https://hasura.io/blog/postgres-date-time-data-types-on-graphql-fd926e86ee87/
func nowTimestamp() graphql.Timestamptz {
	return graphql.Timestamptz(time.Now().Format(time.RFC3339))
}
