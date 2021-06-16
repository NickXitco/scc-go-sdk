/**
 * (C) Copyright IBM Corp. 2021.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/*
 * IBM OpenAPI SDK Code Generator Version: 3.33.0-caf29bd0-20210603-225214
 */

// Package posturemanagementv1 : Operations and models for the PostureManagementV1 service
package posturemanagementv1

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"reflect"
	"time"

	"github.com/IBM/go-sdk-core/v5/core"
	common "github.com/IBM/scc-go-sdk/common"
	"github.com/go-openapi/strfmt"
)

// PostureManagementV1 : With IBM Cloud® Security and Compliance Center, you can embed checks into your every day
// workflows to help manage your current security and compliance posture. By monitoring for risks, you can identify
// security vulnerabilities and quickly work to mitigate the impact.
//
// Version: 1.0.0
type PostureManagementV1 struct {
	Service *core.BaseService

	// Your IBM Cloud account ID.
	AccountID *string
}

// DefaultServiceURL is the default URL to make service requests to.
const DefaultServiceURL = "https://us.compliance.cloud.ibm.com"

// DefaultServiceName is the default key used to find external configuration information.
const DefaultServiceName = "posture_management"

// PostureManagementV1Options : Service options
type PostureManagementV1Options struct {
	ServiceName   string
	URL           string
	Authenticator core.Authenticator

	// Your IBM Cloud account ID.
	AccountID *string `validate:"required"`
}

// NewPostureManagementV1UsingExternalConfig : constructs an instance of PostureManagementV1 with passed in options and external configuration.
func NewPostureManagementV1UsingExternalConfig(options *PostureManagementV1Options) (postureManagement *PostureManagementV1, err error) {
	if options.ServiceName == "" {
		options.ServiceName = DefaultServiceName
	}

	if options.Authenticator == nil {
		options.Authenticator, err = core.GetAuthenticatorFromEnvironment(options.ServiceName)
		if err != nil {
			return
		}
	}

	postureManagement, err = NewPostureManagementV1(options)
	if err != nil {
		return
	}

	err = postureManagement.Service.ConfigureService(options.ServiceName)
	if err != nil {
		return
	}

	if options.URL != "" {
		err = postureManagement.Service.SetServiceURL(options.URL)
	}
	return
}

// NewPostureManagementV1 : constructs an instance of PostureManagementV1 with passed in options.
func NewPostureManagementV1(options *PostureManagementV1Options) (service *PostureManagementV1, err error) {
	serviceOptions := &core.ServiceOptions{
		URL:           DefaultServiceURL,
		Authenticator: options.Authenticator,
	}

	err = core.ValidateStruct(options, "options")
	if err != nil {
		return
	}

	baseService, err := core.NewBaseService(serviceOptions)
	if err != nil {
		return
	}

	if options.URL != "" {
		err = baseService.SetServiceURL(options.URL)
		if err != nil {
			return
		}
	}

	service = &PostureManagementV1{
		Service:   baseService,
		AccountID: options.AccountID,
	}

	return
}

// GetServiceURLForRegion returns the service URL to be used for the specified region
func GetServiceURLForRegion(region string) (string, error) {
	return "", fmt.Errorf("service does not support regional URLs")
}

// Clone makes a copy of "postureManagement" suitable for processing requests.
func (postureManagement *PostureManagementV1) Clone() *PostureManagementV1 {
	if core.IsNil(postureManagement) {
		return nil
	}
	clone := *postureManagement
	clone.Service = postureManagement.Service.Clone()
	return &clone
}

// SetServiceURL sets the service URL
func (postureManagement *PostureManagementV1) SetServiceURL(url string) error {
	return postureManagement.Service.SetServiceURL(url)
}

// GetServiceURL returns the service URL
func (postureManagement *PostureManagementV1) GetServiceURL() string {
	return postureManagement.Service.GetServiceURL()
}

// SetDefaultHeaders sets HTTP headers to be sent in every request
func (postureManagement *PostureManagementV1) SetDefaultHeaders(headers http.Header) {
	postureManagement.Service.SetDefaultHeaders(headers)
}

// SetEnableGzipCompression sets the service's EnableGzipCompression field
func (postureManagement *PostureManagementV1) SetEnableGzipCompression(enableGzip bool) {
	postureManagement.Service.SetEnableGzipCompression(enableGzip)
}

// GetEnableGzipCompression returns the service's EnableGzipCompression field
func (postureManagement *PostureManagementV1) GetEnableGzipCompression() bool {
	return postureManagement.Service.GetEnableGzipCompression()
}

// EnableRetries enables automatic retries for requests invoked for this service instance.
// If either parameter is specified as 0, then a default value is used instead.
func (postureManagement *PostureManagementV1) EnableRetries(maxRetries int, maxRetryInterval time.Duration) {
	postureManagement.Service.EnableRetries(maxRetries, maxRetryInterval)
}

// DisableRetries disables automatic retries for requests invoked for this service instance.
func (postureManagement *PostureManagementV1) DisableRetries() {
	postureManagement.Service.DisableRetries()
}

// ListLatestScans : List latest scans
// List all of the latest scans that are available in your account. Lastest scans for every scope and profile
// combinations is populated.
func (postureManagement *PostureManagementV1) ListLatestScans(listLatestScansOptions *ListLatestScansOptions) (result *ScansList, response *core.DetailedResponse, err error) {
	return postureManagement.ListLatestScansWithContext(context.Background(), listLatestScansOptions)
}

// ListLatestScansWithContext is an alternate form of the ListLatestScans method which supports a Context parameter
func (postureManagement *PostureManagementV1) ListLatestScansWithContext(ctx context.Context, listLatestScansOptions *ListLatestScansOptions) (result *ScansList, response *core.DetailedResponse, err error) {
	err = core.ValidateStruct(listLatestScansOptions, "listLatestScansOptions")
	if err != nil {
		return
	}

	builder := core.NewRequestBuilder(core.GET)
	builder = builder.WithContext(ctx)
	builder.EnableGzipCompression = postureManagement.GetEnableGzipCompression()
	_, err = builder.ResolveRequestURL(postureManagement.Service.Options.URL, `/posture/v1/scans/validations/latest_scans`, nil)
	if err != nil {
		return
	}

	for headerName, headerValue := range listLatestScansOptions.Headers {
		builder.AddHeader(headerName, headerValue)
	}

	sdkHeaders := common.GetSdkHeaders("posture_management", "V1", "ListLatestScans")
	for headerName, headerValue := range sdkHeaders {
		builder.AddHeader(headerName, headerValue)
	}
	builder.AddHeader("Accept", "application/json")
	if listLatestScansOptions.TransactionID != nil {
		builder.AddHeader("Transaction-Id", fmt.Sprint(*listLatestScansOptions.TransactionID))
	}

	builder.AddQuery("account_id", fmt.Sprint(*postureManagement.AccountID))
	if listLatestScansOptions.Name != nil {
		builder.AddQuery("name", fmt.Sprint(*listLatestScansOptions.Name))
	}
	if listLatestScansOptions.Offset != nil {
		builder.AddQuery("offset", fmt.Sprint(*listLatestScansOptions.Offset))
	}
	if listLatestScansOptions.Limit != nil {
		builder.AddQuery("limit", fmt.Sprint(*listLatestScansOptions.Limit))
	}

	request, err := builder.Build()
	if err != nil {
		return
	}

	var rawResponse map[string]json.RawMessage
	response, err = postureManagement.Service.Request(request, &rawResponse)
	if err != nil {
		return
	}
	if rawResponse != nil {
		err = core.UnmarshalModel(rawResponse, "", &result, UnmarshalScansList)
		if err != nil {
			return
		}
		response.Result = result
	}

	return
}

// CreateValidation : Initiate a validation scan
// Validation scans determine a specified scope's adherence to regulatory controls by validating the configuration of
// the resources in your scope to the attached profile. To initiate a scan, you must have configured a collector,
// provided credentials, and completed both a fact collection and discovery scan. [Learn
// more](/docs/security-compliance?topic=security-compliance-schedule-scan).
func (postureManagement *PostureManagementV1) CreateValidation(createValidationOptions *CreateValidationOptions) (result *Result, response *core.DetailedResponse, err error) {
	return postureManagement.CreateValidationWithContext(context.Background(), createValidationOptions)
}

// CreateValidationWithContext is an alternate form of the CreateValidation method which supports a Context parameter
func (postureManagement *PostureManagementV1) CreateValidationWithContext(ctx context.Context, createValidationOptions *CreateValidationOptions) (result *Result, response *core.DetailedResponse, err error) {
	err = core.ValidateNotNil(createValidationOptions, "createValidationOptions cannot be nil")
	if err != nil {
		return
	}
	err = core.ValidateStruct(createValidationOptions, "createValidationOptions")
	if err != nil {
		return
	}

	builder := core.NewRequestBuilder(core.POST)
	builder = builder.WithContext(ctx)
	builder.EnableGzipCompression = postureManagement.GetEnableGzipCompression()
	_, err = builder.ResolveRequestURL(postureManagement.Service.Options.URL, `/posture/v1/scans/validations`, nil)
	if err != nil {
		return
	}

	for headerName, headerValue := range createValidationOptions.Headers {
		builder.AddHeader(headerName, headerValue)
	}

	sdkHeaders := common.GetSdkHeaders("posture_management", "V1", "CreateValidation")
	for headerName, headerValue := range sdkHeaders {
		builder.AddHeader(headerName, headerValue)
	}
	builder.AddHeader("Accept", "application/json")
	builder.AddHeader("Content-Type", "application/json")
	if createValidationOptions.TransactionID != nil {
		builder.AddHeader("Transaction-Id", fmt.Sprint(*createValidationOptions.TransactionID))
	}

	builder.AddQuery("account_id", fmt.Sprint(*postureManagement.AccountID))

	body := make(map[string]interface{})
	if createValidationOptions.ScopeID != nil {
		body["scope_id"] = createValidationOptions.ScopeID
	}
	if createValidationOptions.ProfileID != nil {
		body["profile_id"] = createValidationOptions.ProfileID
	}
	if createValidationOptions.GroupProfileID != nil {
		body["group_profile_id"] = createValidationOptions.GroupProfileID
	}
	_, err = builder.SetBodyContentJSON(body)
	if err != nil {
		return
	}

	request, err := builder.Build()
	if err != nil {
		return
	}

	var rawResponse map[string]json.RawMessage
	response, err = postureManagement.Service.Request(request, &rawResponse)
	if err != nil {
		return
	}
	if rawResponse != nil {
		err = core.UnmarshalModel(rawResponse, "", &result, UnmarshalResult)
		if err != nil {
			return
		}
		response.Result = result
	}

	return
}

// ScansSummary : Retrieve the summary of a specific scan
// Retrieve the results summary of a validation scan by specifying a scan and profile ID combination. To obtain your
// profile ID and scan ID for your most recent scan, make a GET request to the
// "/posture/v1/scans/validations/latest_scans" endpoint.
func (postureManagement *PostureManagementV1) ScansSummary(scansSummaryOptions *ScansSummaryOptions) (result *Summary, response *core.DetailedResponse, err error) {
	return postureManagement.ScansSummaryWithContext(context.Background(), scansSummaryOptions)
}

// ScansSummaryWithContext is an alternate form of the ScansSummary method which supports a Context parameter
func (postureManagement *PostureManagementV1) ScansSummaryWithContext(ctx context.Context, scansSummaryOptions *ScansSummaryOptions) (result *Summary, response *core.DetailedResponse, err error) {
	err = core.ValidateNotNil(scansSummaryOptions, "scansSummaryOptions cannot be nil")
	if err != nil {
		return
	}
	err = core.ValidateStruct(scansSummaryOptions, "scansSummaryOptions")
	if err != nil {
		return
	}

	pathParamsMap := map[string]string{
		"scan_id": *scansSummaryOptions.ScanID,
	}

	builder := core.NewRequestBuilder(core.GET)
	builder = builder.WithContext(ctx)
	builder.EnableGzipCompression = postureManagement.GetEnableGzipCompression()
	_, err = builder.ResolveRequestURL(postureManagement.Service.Options.URL, `/posture/v1/scans/validations/{scan_id}/summary`, pathParamsMap)
	if err != nil {
		return
	}

	for headerName, headerValue := range scansSummaryOptions.Headers {
		builder.AddHeader(headerName, headerValue)
	}

	sdkHeaders := common.GetSdkHeaders("posture_management", "V1", "ScansSummary")
	for headerName, headerValue := range sdkHeaders {
		builder.AddHeader(headerName, headerValue)
	}
	builder.AddHeader("Accept", "application/json")
	if scansSummaryOptions.TransactionID != nil {
		builder.AddHeader("Transaction-Id", fmt.Sprint(*scansSummaryOptions.TransactionID))
	}

	builder.AddQuery("account_id", fmt.Sprint(*postureManagement.AccountID))
	if scansSummaryOptions.ProfileID != nil {
		builder.AddQuery("profile_id", fmt.Sprint(*scansSummaryOptions.ProfileID))
	}
	if scansSummaryOptions.Name != nil {
		builder.AddQuery("name", fmt.Sprint(*scansSummaryOptions.Name))
	}

	request, err := builder.Build()
	if err != nil {
		return
	}

	var rawResponse map[string]json.RawMessage
	response, err = postureManagement.Service.Request(request, &rawResponse)
	if err != nil {
		return
	}
	if rawResponse != nil {
		err = core.UnmarshalModel(rawResponse, "", &result, UnmarshalSummary)
		if err != nil {
			return
		}
		response.Result = result
	}

	return
}

// ScanSummaries : List the validation summaries for a scan
// List all of the historical and current validation summaries for a specific scan.
func (postureManagement *PostureManagementV1) ScanSummaries(scanSummariesOptions *ScanSummariesOptions) (result *SummariesList, response *core.DetailedResponse, err error) {
	return postureManagement.ScanSummariesWithContext(context.Background(), scanSummariesOptions)
}

// ScanSummariesWithContext is an alternate form of the ScanSummaries method which supports a Context parameter
func (postureManagement *PostureManagementV1) ScanSummariesWithContext(ctx context.Context, scanSummariesOptions *ScanSummariesOptions) (result *SummariesList, response *core.DetailedResponse, err error) {
	err = core.ValidateNotNil(scanSummariesOptions, "scanSummariesOptions cannot be nil")
	if err != nil {
		return
	}
	err = core.ValidateStruct(scanSummariesOptions, "scanSummariesOptions")
	if err != nil {
		return
	}

	builder := core.NewRequestBuilder(core.GET)
	builder = builder.WithContext(ctx)
	builder.EnableGzipCompression = postureManagement.GetEnableGzipCompression()
	_, err = builder.ResolveRequestURL(postureManagement.Service.Options.URL, `/posture/v1/scans/validations/summaries`, nil)
	if err != nil {
		return
	}

	for headerName, headerValue := range scanSummariesOptions.Headers {
		builder.AddHeader(headerName, headerValue)
	}

	sdkHeaders := common.GetSdkHeaders("posture_management", "V1", "ScanSummaries")
	for headerName, headerValue := range sdkHeaders {
		builder.AddHeader(headerName, headerValue)
	}
	builder.AddHeader("Accept", "application/json")
	if scanSummariesOptions.TransactionID != nil {
		builder.AddHeader("Transaction-Id", fmt.Sprint(*scanSummariesOptions.TransactionID))
	}

	builder.AddQuery("scope_id", fmt.Sprint(*scanSummariesOptions.ScopeID))
	builder.AddQuery("account_id", fmt.Sprint(*postureManagement.AccountID))
	if scanSummariesOptions.ProfileID != nil {
		builder.AddQuery("profile_id", fmt.Sprint(*scanSummariesOptions.ProfileID))
	}
	if scanSummariesOptions.GroupProfileID != nil {
		builder.AddQuery("group_profile_id", fmt.Sprint(*scanSummariesOptions.GroupProfileID))
	}
	if scanSummariesOptions.Offset != nil {
		builder.AddQuery("offset", fmt.Sprint(*scanSummariesOptions.Offset))
	}
	if scanSummariesOptions.Limit != nil {
		builder.AddQuery("limit", fmt.Sprint(*scanSummariesOptions.Limit))
	}

	request, err := builder.Build()
	if err != nil {
		return
	}

	var rawResponse map[string]json.RawMessage
	response, err = postureManagement.Service.Request(request, &rawResponse)
	if err != nil {
		return
	}
	if rawResponse != nil {
		err = core.UnmarshalModel(rawResponse, "", &result, UnmarshalSummariesList)
		if err != nil {
			return
		}
		response.Result = result
	}

	return
}

// ListProfiles : List profiles
// List all of the profiles that are available in your account. To view a specific profile, you can filter by name.
func (postureManagement *PostureManagementV1) ListProfiles(listProfilesOptions *ListProfilesOptions) (result *ProfilesList, response *core.DetailedResponse, err error) {
	return postureManagement.ListProfilesWithContext(context.Background(), listProfilesOptions)
}

// ListProfilesWithContext is an alternate form of the ListProfiles method which supports a Context parameter
func (postureManagement *PostureManagementV1) ListProfilesWithContext(ctx context.Context, listProfilesOptions *ListProfilesOptions) (result *ProfilesList, response *core.DetailedResponse, err error) {
	err = core.ValidateStruct(listProfilesOptions, "listProfilesOptions")
	if err != nil {
		return
	}

	builder := core.NewRequestBuilder(core.GET)
	builder = builder.WithContext(ctx)
	builder.EnableGzipCompression = postureManagement.GetEnableGzipCompression()
	_, err = builder.ResolveRequestURL(postureManagement.Service.Options.URL, `/posture/v1/profiles`, nil)
	if err != nil {
		return
	}

	for headerName, headerValue := range listProfilesOptions.Headers {
		builder.AddHeader(headerName, headerValue)
	}

	sdkHeaders := common.GetSdkHeaders("posture_management", "V1", "ListProfiles")
	for headerName, headerValue := range sdkHeaders {
		builder.AddHeader(headerName, headerValue)
	}
	builder.AddHeader("Accept", "application/json")
	if listProfilesOptions.TransactionID != nil {
		builder.AddHeader("Transaction-Id", fmt.Sprint(*listProfilesOptions.TransactionID))
	}

	builder.AddQuery("account_id", fmt.Sprint(*postureManagement.AccountID))
	if listProfilesOptions.Name != nil {
		builder.AddQuery("name", fmt.Sprint(*listProfilesOptions.Name))
	}
	if listProfilesOptions.Offset != nil {
		builder.AddQuery("offset", fmt.Sprint(*listProfilesOptions.Offset))
	}
	if listProfilesOptions.Limit != nil {
		builder.AddQuery("limit", fmt.Sprint(*listProfilesOptions.Limit))
	}

	request, err := builder.Build()
	if err != nil {
		return
	}

	var rawResponse map[string]json.RawMessage
	response, err = postureManagement.Service.Request(request, &rawResponse)
	if err != nil {
		return
	}
	if rawResponse != nil {
		err = core.UnmarshalModel(rawResponse, "", &result, UnmarshalProfilesList)
		if err != nil {
			return
		}
		response.Result = result
	}

	return
}

// CreateScope : Create a scope
// Creating a scope lets you determine your security and compliance score across a specific area of your business.
func (postureManagement *PostureManagementV1) CreateScope(createScopeOptions *CreateScopeOptions) (result *Scope, response *core.DetailedResponse, err error) {
	return postureManagement.CreateScopeWithContext(context.Background(), createScopeOptions)
}

// CreateScopeWithContext is an alternate form of the CreateScope method which supports a Context parameter
func (postureManagement *PostureManagementV1) CreateScopeWithContext(ctx context.Context, createScopeOptions *CreateScopeOptions) (result *Scope, response *core.DetailedResponse, err error) {
	err = core.ValidateNotNil(createScopeOptions, "createScopeOptions cannot be nil")
	if err != nil {
		return
	}
	err = core.ValidateStruct(createScopeOptions, "createScopeOptions")
	if err != nil {
		return
	}

	builder := core.NewRequestBuilder(core.POST)
	builder = builder.WithContext(ctx)
	builder.EnableGzipCompression = postureManagement.GetEnableGzipCompression()
	_, err = builder.ResolveRequestURL(postureManagement.Service.Options.URL, `/posture/v1/scopes`, nil)
	if err != nil {
		return
	}

	for headerName, headerValue := range createScopeOptions.Headers {
		builder.AddHeader(headerName, headerValue)
	}

	sdkHeaders := common.GetSdkHeaders("posture_management", "V1", "CreateScope")
	for headerName, headerValue := range sdkHeaders {
		builder.AddHeader(headerName, headerValue)
	}
	builder.AddHeader("Accept", "application/json")
	builder.AddHeader("Content-Type", "application/json")
	if createScopeOptions.TransactionID != nil {
		builder.AddHeader("Transaction-Id", fmt.Sprint(*createScopeOptions.TransactionID))
	}

	builder.AddQuery("account_id", fmt.Sprint(*postureManagement.AccountID))

	body := make(map[string]interface{})
	if createScopeOptions.ScopeName != nil {
		body["scope_name"] = createScopeOptions.ScopeName
	}
	if createScopeOptions.ScopeDescription != nil {
		body["scope_description"] = createScopeOptions.ScopeDescription
	}
	if createScopeOptions.CollectorIds != nil {
		body["collector_ids"] = createScopeOptions.CollectorIds
	}
	if createScopeOptions.CredentialID != nil {
		body["credential_id"] = createScopeOptions.CredentialID
	}
	if createScopeOptions.EnvironmentType != nil {
		body["environment_type"] = createScopeOptions.EnvironmentType
	}
	_, err = builder.SetBodyContentJSON(body)
	if err != nil {
		return
	}

	request, err := builder.Build()
	if err != nil {
		return
	}

	var rawResponse map[string]json.RawMessage
	response, err = postureManagement.Service.Request(request, &rawResponse)
	if err != nil {
		return
	}
	if rawResponse != nil {
		err = core.UnmarshalModel(rawResponse, "", &result, UnmarshalScope)
		if err != nil {
			return
		}
		response.Result = result
	}

	return
}

// ListScopes : List scopes
// List all of the scopes that are available in your account. To view a specific scope, you can filter by name.
func (postureManagement *PostureManagementV1) ListScopes(listScopesOptions *ListScopesOptions) (result *ScopesList, response *core.DetailedResponse, err error) {
	return postureManagement.ListScopesWithContext(context.Background(), listScopesOptions)
}

// ListScopesWithContext is an alternate form of the ListScopes method which supports a Context parameter
func (postureManagement *PostureManagementV1) ListScopesWithContext(ctx context.Context, listScopesOptions *ListScopesOptions) (result *ScopesList, response *core.DetailedResponse, err error) {
	err = core.ValidateStruct(listScopesOptions, "listScopesOptions")
	if err != nil {
		return
	}

	builder := core.NewRequestBuilder(core.GET)
	builder = builder.WithContext(ctx)
	builder.EnableGzipCompression = postureManagement.GetEnableGzipCompression()
	_, err = builder.ResolveRequestURL(postureManagement.Service.Options.URL, `/posture/v1/scopes`, nil)
	if err != nil {
		return
	}

	for headerName, headerValue := range listScopesOptions.Headers {
		builder.AddHeader(headerName, headerValue)
	}

	sdkHeaders := common.GetSdkHeaders("posture_management", "V1", "ListScopes")
	for headerName, headerValue := range sdkHeaders {
		builder.AddHeader(headerName, headerValue)
	}
	builder.AddHeader("Accept", "application/json")
	if listScopesOptions.TransactionID != nil {
		builder.AddHeader("Transaction-Id", fmt.Sprint(*listScopesOptions.TransactionID))
	}

	builder.AddQuery("account_id", fmt.Sprint(*postureManagement.AccountID))
	if listScopesOptions.Name != nil {
		builder.AddQuery("name", fmt.Sprint(*listScopesOptions.Name))
	}

	request, err := builder.Build()
	if err != nil {
		return
	}

	var rawResponse map[string]json.RawMessage
	response, err = postureManagement.Service.Request(request, &rawResponse)
	if err != nil {
		return
	}
	if rawResponse != nil {
		err = core.UnmarshalModel(rawResponse, "", &result, UnmarshalScopesList)
		if err != nil {
			return
		}
		response.Result = result
	}

	return
}

// CreateCollector : Create a collector
// Create a collector to fetch the configuration of your cloud environment and perform a validation afterwards.
func (postureManagement *PostureManagementV1) CreateCollector(createCollectorOptions *CreateCollectorOptions) (result *Collector, response *core.DetailedResponse, err error) {
	return postureManagement.CreateCollectorWithContext(context.Background(), createCollectorOptions)
}

// CreateCollectorWithContext is an alternate form of the CreateCollector method which supports a Context parameter
func (postureManagement *PostureManagementV1) CreateCollectorWithContext(ctx context.Context, createCollectorOptions *CreateCollectorOptions) (result *Collector, response *core.DetailedResponse, err error) {
	err = core.ValidateNotNil(createCollectorOptions, "createCollectorOptions cannot be nil")
	if err != nil {
		return
	}
	err = core.ValidateStruct(createCollectorOptions, "createCollectorOptions")
	if err != nil {
		return
	}

	builder := core.NewRequestBuilder(core.POST)
	builder = builder.WithContext(ctx)
	builder.EnableGzipCompression = postureManagement.GetEnableGzipCompression()
	_, err = builder.ResolveRequestURL(postureManagement.Service.Options.URL, `/posture/v1/collectors`, nil)
	if err != nil {
		return
	}

	for headerName, headerValue := range createCollectorOptions.Headers {
		builder.AddHeader(headerName, headerValue)
	}

	sdkHeaders := common.GetSdkHeaders("posture_management", "V1", "CreateCollector")
	for headerName, headerValue := range sdkHeaders {
		builder.AddHeader(headerName, headerValue)
	}
	builder.AddHeader("Accept", "application/json")
	builder.AddHeader("Content-Type", "application/json")
	if createCollectorOptions.TransactionID != nil {
		builder.AddHeader("Transaction-Id", fmt.Sprint(*createCollectorOptions.TransactionID))
	}

	builder.AddQuery("account_id", fmt.Sprint(*postureManagement.AccountID))

	body := make(map[string]interface{})
	if createCollectorOptions.CollectorName != nil {
		body["collector_name"] = createCollectorOptions.CollectorName
	}
	if createCollectorOptions.CollectorDescription != nil {
		body["collector_description"] = createCollectorOptions.CollectorDescription
	}
	if createCollectorOptions.IsPublic != nil {
		body["is_public"] = createCollectorOptions.IsPublic
	}
	if createCollectorOptions.ManagedBy != nil {
		body["managed_by"] = createCollectorOptions.ManagedBy
	}
	if createCollectorOptions.PassPhrase != nil {
		body["pass_phrase"] = createCollectorOptions.PassPhrase
	}
	_, err = builder.SetBodyContentJSON(body)
	if err != nil {
		return
	}

	request, err := builder.Build()
	if err != nil {
		return
	}

	var rawResponse map[string]json.RawMessage
	response, err = postureManagement.Service.Request(request, &rawResponse)
	if err != nil {
		return
	}
	if rawResponse != nil {
		err = core.UnmarshalModel(rawResponse, "", &result, UnmarshalCollector)
		if err != nil {
			return
		}
		response.Result = result
	}

	return
}

// CreateCredential : Create a credential
// Create a credential that can be used by a collector to gather information about your resource configurations, assess
// them, and initiate any remediation where possible.
func (postureManagement *PostureManagementV1) CreateCredential(createCredentialOptions *CreateCredentialOptions) (result *Credential, response *core.DetailedResponse, err error) {
	return postureManagement.CreateCredentialWithContext(context.Background(), createCredentialOptions)
}

// CreateCredentialWithContext is an alternate form of the CreateCredential method which supports a Context parameter
func (postureManagement *PostureManagementV1) CreateCredentialWithContext(ctx context.Context, createCredentialOptions *CreateCredentialOptions) (result *Credential, response *core.DetailedResponse, err error) {
	err = core.ValidateNotNil(createCredentialOptions, "createCredentialOptions cannot be nil")
	if err != nil {
		return
	}
	err = core.ValidateStruct(createCredentialOptions, "createCredentialOptions")
	if err != nil {
		return
	}

	builder := core.NewRequestBuilder(core.POST)
	builder = builder.WithContext(ctx)
	builder.EnableGzipCompression = postureManagement.GetEnableGzipCompression()
	_, err = builder.ResolveRequestURL(postureManagement.Service.Options.URL, `/posture/v1/credentials`, nil)
	if err != nil {
		return
	}

	for headerName, headerValue := range createCredentialOptions.Headers {
		builder.AddHeader(headerName, headerValue)
	}

	sdkHeaders := common.GetSdkHeaders("posture_management", "V1", "CreateCredential")
	for headerName, headerValue := range sdkHeaders {
		builder.AddHeader(headerName, headerValue)
	}
	builder.AddHeader("Accept", "application/json")
	if createCredentialOptions.TransactionID != nil {
		builder.AddHeader("Transaction-Id", fmt.Sprint(*createCredentialOptions.TransactionID))
	}

	builder.AddQuery("account_id", fmt.Sprint(*postureManagement.AccountID))

	builder.AddFormData("credential_data_file", "filename",
		"application/json", createCredentialOptions.CredentialDataFile)
	if createCredentialOptions.PemFile != nil {
		builder.AddFormData("pem_file", "filename",
			"text/plain", createCredentialOptions.PemFile)
	}

	request, err := builder.Build()
	if err != nil {
		return
	}

	var rawResponse map[string]json.RawMessage
	response, err = postureManagement.Service.Request(request, &rawResponse)
	if err != nil {
		return
	}
	if rawResponse != nil {
		err = core.UnmarshalModel(rawResponse, "", &result, UnmarshalCredential)
		if err != nil {
			return
		}
		response.Result = result
	}

	return
}

// ValidateResults : Validate exchange protocol results
// Validate exchange protocol results.
func (postureManagement *PostureManagementV1) ValidateResults(validateResultsOptions *ValidateResultsOptions) (result *ExchangeProtocolValidationResponse, response *core.DetailedResponse, err error) {
	return postureManagement.ValidateResultsWithContext(context.Background(), validateResultsOptions)
}

// ValidateResultsWithContext is an alternate form of the ValidateResults method which supports a Context parameter
func (postureManagement *PostureManagementV1) ValidateResultsWithContext(ctx context.Context, validateResultsOptions *ValidateResultsOptions) (result *ExchangeProtocolValidationResponse, response *core.DetailedResponse, err error) {
	err = core.ValidateNotNil(validateResultsOptions, "validateResultsOptions cannot be nil")
	if err != nil {
		return
	}
	err = core.ValidateStruct(validateResultsOptions, "validateResultsOptions")
	if err != nil {
		return
	}

	pathParamsMap := map[string]string{
		"scope_uuid": *validateResultsOptions.ScopeUUID,
	}

	builder := core.NewRequestBuilder(core.POST)
	builder = builder.WithContext(ctx)
	builder.EnableGzipCompression = postureManagement.GetEnableGzipCompression()
	_, err = builder.ResolveRequestURL(postureManagement.Service.Options.URL, `/exchangeprotocol/v1/scope/{scope_uuid}/results`, pathParamsMap)
	if err != nil {
		return
	}

	for headerName, headerValue := range validateResultsOptions.Headers {
		builder.AddHeader(headerName, headerValue)
	}

	sdkHeaders := common.GetSdkHeaders("posture_management", "V1", "ValidateResults")
	for headerName, headerValue := range sdkHeaders {
		builder.AddHeader(headerName, headerValue)
	}
	builder.AddHeader("Accept", "text/plain")
	builder.AddHeader("Content-Type", "application/json")
	if validateResultsOptions.TransactionID != nil {
		builder.AddHeader("Transaction-Id", fmt.Sprint(*validateResultsOptions.TransactionID))
	}

	builder.AddQuery("account_id", fmt.Sprint(*postureManagement.AccountID))
	builder.AddQuery("result_type", fmt.Sprint(*validateResultsOptions.ResultType))

	body := make(map[string]interface{})
	if validateResultsOptions.ComputerName != nil {
		body["Computer Name"] = validateResultsOptions.ComputerName
	}
	if validateResultsOptions.TaniumClientIPAddress != nil {
		body["Tanium Client IP Address"] = validateResultsOptions.TaniumClientIPAddress
	}
	if validateResultsOptions.IPAddress != nil {
		body["IP Address"] = validateResultsOptions.IPAddress
	}
	if validateResultsOptions.ComplyComplianceFindings != nil {
		body["Comply - Compliance Findings"] = validateResultsOptions.ComplyComplianceFindings
	}
	if validateResultsOptions.Count != nil {
		body["Count"] = validateResultsOptions.Count
	}
	_, err = builder.SetBodyContentJSON(body)
	if err != nil {
		return
	}

	request, err := builder.Build()
	if err != nil {
		return
	}

	var rawResponse map[string]json.RawMessage
	response, err = postureManagement.Service.Request(request, &rawResponse)
	if err != nil {
		return
	}
	if rawResponse != nil {
		err = core.UnmarshalModel(rawResponse, "", &result, UnmarshalExchangeProtocolValidationResponse)
		if err != nil {
			return
		}
		response.Result = result
	}

	return
}

// ApplicabilityCriteria : The criteria that defines how a profile applies.
type ApplicabilityCriteria struct {
	// A list of environments that a profile can be applied to.
	Environment []string `json:"environment,omitempty"`

	// A list of resources that a profile can be used with.
	Resource []string `json:"resource,omitempty"`

	// The type of environment that a profile is able to be applied to.
	EnvironmentCategory []string `json:"environment_category,omitempty"`

	// The type of resource that a profile is able to be applied to.
	ResourceCategory []string `json:"resource_category,omitempty"`

	// The resource type that the profile applies to.
	ResourceType []string `json:"resource_type,omitempty"`

	// The software that the profile applies to.
	SoftwareDetails interface{} `json:"software_details,omitempty"`

	// The operatoring system that the profile applies to.
	OsDetails interface{} `json:"os_details,omitempty"`

	// Any additional details about the profile.
	AdditionalDetails interface{} `json:"additional_details,omitempty"`

	// The type of environment that your scope is targeted to.
	EnvironmentCategoryDescription map[string]string `json:"environment_category_description,omitempty"`

	// The environment that your scope is targeted to.
	EnvironmentDescription map[string]string `json:"environment_description,omitempty"`

	// The type of resource that your scope is targeted to.
	ResourceCategoryDescription map[string]string `json:"resource_category_description,omitempty"`

	// A further classification of the type of resource that your scope is targeted to.
	ResourceTypeDescription map[string]string `json:"resource_type_description,omitempty"`

	// The resource that is scanned as part of your scope.
	ResourceDescription map[string]string `json:"resource_description,omitempty"`
}

// UnmarshalApplicabilityCriteria unmarshals an instance of ApplicabilityCriteria from the specified map of raw messages.
func UnmarshalApplicabilityCriteria(m map[string]json.RawMessage, result interface{}) (err error) {
	obj := new(ApplicabilityCriteria)
	err = core.UnmarshalPrimitive(m, "environment", &obj.Environment)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "resource", &obj.Resource)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "environment_category", &obj.EnvironmentCategory)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "resource_category", &obj.ResourceCategory)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "resource_type", &obj.ResourceType)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "software_details", &obj.SoftwareDetails)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "os_details", &obj.OsDetails)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "additional_details", &obj.AdditionalDetails)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "environment_category_description", &obj.EnvironmentCategoryDescription)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "environment_description", &obj.EnvironmentDescription)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "resource_category_description", &obj.ResourceCategoryDescription)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "resource_type_description", &obj.ResourceTypeDescription)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "resource_description", &obj.ResourceDescription)
	if err != nil {
		return
	}
	reflect.ValueOf(result).Elem().Set(reflect.ValueOf(obj))
	return
}

// Collector : The instance of the collector.
type Collector struct {
	// An identifier of the collector.
	CollectorID *string `json:"collector_id,omitempty"`
}

// UnmarshalCollector unmarshals an instance of Collector from the specified map of raw messages.
func UnmarshalCollector(m map[string]json.RawMessage, result interface{}) (err error) {
	obj := new(Collector)
	err = core.UnmarshalPrimitive(m, "collector_id", &obj.CollectorID)
	if err != nil {
		return
	}
	reflect.ValueOf(result).Elem().Set(reflect.ValueOf(obj))
	return
}

// Controls : A scans summary controls.
type Controls struct {
	// The scan summary control ID.
	ControlID *string `json:"control_id,omitempty"`

	// The control status.
	Status *string `json:"status,omitempty"`

	// The external control ID.
	ExternalControlID *string `json:"external_control_id,omitempty"`

	// The scan profile name.
	ControlDesciption *string `json:"control_desciption,omitempty"`

	// The list of goals on the control.
	Goals []Goals `json:"goals,omitempty"`

	// A scans summary controls.
	ResourceStatistics *ResourceStatistics `json:"resource_statistics,omitempty"`
}

// UnmarshalControls unmarshals an instance of Controls from the specified map of raw messages.
func UnmarshalControls(m map[string]json.RawMessage, result interface{}) (err error) {
	obj := new(Controls)
	err = core.UnmarshalPrimitive(m, "control_id", &obj.ControlID)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "status", &obj.Status)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "external_control_id", &obj.ExternalControlID)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "control_desciption", &obj.ControlDesciption)
	if err != nil {
		return
	}
	err = core.UnmarshalModel(m, "goals", &obj.Goals, UnmarshalGoals)
	if err != nil {
		return
	}
	err = core.UnmarshalModel(m, "resource_statistics", &obj.ResourceStatistics, UnmarshalResourceStatistics)
	if err != nil {
		return
	}
	reflect.ValueOf(result).Elem().Set(reflect.ValueOf(obj))
	return
}

// CreateCollectorOptions : The CreateCollector options.
type CreateCollectorOptions struct {
	// A unique name for your collector.
	CollectorName *string

	// A detailed description of the collector.
	CollectorDescription *string

	// Determines whether the collector endpoint is accessible on a public network. If set to `true`, the collector
	// connects to resources in your account over a public network. If set to `false`, the collector connects to resources
	// by using a private IP that is accessible only through the IBM Cloud private network.
	IsPublic *bool

	// Determines whether the collector is an IBM or customer-managed virtual machine. Use `ibm` to allow Security and
	// Compliance Center to create, install, and manage the collector on your behalf. The collector is installed in an
	// OpenShift cluster and approved automatically for use. Use `customer` if you would like to install the collector by
	// using your own virtual machine. For more information, check out the
	// [docs](https://cloud.ibm.com/docs/security-compliance?topic=security-compliance-collector).
	ManagedBy *string

	// To protect the credentials that you add to the service, a passphrase is used to generate a data encryption key. The
	// key is used to securely store your credentials and prevent anyone from accessing them.
	PassPhrase *string

	// The unique identifier that is used to trace an entire request. If you omit this field, the service generates and
	// sends a transaction ID as a response header of the request.
	TransactionID *string

	// Allows users to set headers on API requests
	Headers map[string]string
}

// Constants associated with the CreateCollectorOptions.ManagedBy property.
// Determines whether the collector is an IBM or customer-managed virtual machine. Use `ibm` to allow Security and
// Compliance Center to create, install, and manage the collector on your behalf. The collector is installed in an
// OpenShift cluster and approved automatically for use. Use `customer` if you would like to install the collector by
// using your own virtual machine. For more information, check out the
// [docs](https://cloud.ibm.com/docs/security-compliance?topic=security-compliance-collector).
const (
	CreateCollectorOptionsManagedByCustomerConst = "customer"
	CreateCollectorOptionsManagedByIBMConst      = "ibm"
)

// NewCreateCollectorOptions : Instantiate CreateCollectorOptions
func (*PostureManagementV1) NewCreateCollectorOptions() *CreateCollectorOptions {
	return &CreateCollectorOptions{}
}

// SetCollectorName : Allow user to set CollectorName
func (_options *CreateCollectorOptions) SetCollectorName(collectorName string) *CreateCollectorOptions {
	_options.CollectorName = core.StringPtr(collectorName)
	return _options
}

// SetCollectorDescription : Allow user to set CollectorDescription
func (_options *CreateCollectorOptions) SetCollectorDescription(collectorDescription string) *CreateCollectorOptions {
	_options.CollectorDescription = core.StringPtr(collectorDescription)
	return _options
}

// SetIsPublic : Allow user to set IsPublic
func (_options *CreateCollectorOptions) SetIsPublic(isPublic bool) *CreateCollectorOptions {
	_options.IsPublic = core.BoolPtr(isPublic)
	return _options
}

// SetManagedBy : Allow user to set ManagedBy
func (_options *CreateCollectorOptions) SetManagedBy(managedBy string) *CreateCollectorOptions {
	_options.ManagedBy = core.StringPtr(managedBy)
	return _options
}

// SetPassPhrase : Allow user to set PassPhrase
func (_options *CreateCollectorOptions) SetPassPhrase(passPhrase string) *CreateCollectorOptions {
	_options.PassPhrase = core.StringPtr(passPhrase)
	return _options
}

// SetTransactionID : Allow user to set TransactionID
func (_options *CreateCollectorOptions) SetTransactionID(transactionID string) *CreateCollectorOptions {
	_options.TransactionID = core.StringPtr(transactionID)
	return _options
}

// SetHeaders : Allow user to set Headers
func (options *CreateCollectorOptions) SetHeaders(param map[string]string) *CreateCollectorOptions {
	options.Headers = param
	return options
}

// CreateCredentialOptions : The CreateCredential options.
type CreateCredentialOptions struct {
	// The credential data file that you want to use to allow a collector to access and scan your IT resources. Depending
	// on the type of resources that you want to scan, you might provide an API key, an access key file, or a username and
	// password to a specific resource. For more information, see the
	// [docs](https://cloud.ibm.com/docs/security-compliance?topic=security-compliance-credentials).
	CredentialDataFile io.ReadCloser `validate:"required"`

	// A PEM file to associate with the credential data file.
	PemFile io.ReadCloser

	// The unique identifier that is used to trace an entire request. If you omit this field, the service generates and
	// sends a transaction ID as a response header of the request.
	TransactionID *string

	// Allows users to set headers on API requests
	Headers map[string]string
}

// NewCreateCredentialOptions : Instantiate CreateCredentialOptions
func (*PostureManagementV1) NewCreateCredentialOptions(credentialDataFile io.ReadCloser) *CreateCredentialOptions {
	return &CreateCredentialOptions{
		CredentialDataFile: credentialDataFile,
	}
}

// SetCredentialDataFile : Allow user to set CredentialDataFile
func (_options *CreateCredentialOptions) SetCredentialDataFile(credentialDataFile io.ReadCloser) *CreateCredentialOptions {
	_options.CredentialDataFile = credentialDataFile
	return _options
}

// SetPemFile : Allow user to set PemFile
func (_options *CreateCredentialOptions) SetPemFile(pemFile io.ReadCloser) *CreateCredentialOptions {
	_options.PemFile = pemFile
	return _options
}

// SetTransactionID : Allow user to set TransactionID
func (_options *CreateCredentialOptions) SetTransactionID(transactionID string) *CreateCredentialOptions {
	_options.TransactionID = core.StringPtr(transactionID)
	return _options
}

// SetHeaders : Allow user to set Headers
func (options *CreateCredentialOptions) SetHeaders(param map[string]string) *CreateCredentialOptions {
	options.Headers = param
	return options
}

// CreateScopeOptions : The CreateScope options.
type CreateScopeOptions struct {
	// A unique name for your scope.
	ScopeName *string

	// A detailed description of the scope.
	ScopeDescription *string

	// The unique IDs of the collectors that are attached to the scope.
	CollectorIds []string

	// The unique identifier of the credential.
	CredentialID *string

	// The environment that the scope is targeted to.
	EnvironmentType *string

	// The unique identifier that is used to trace an entire request. If you omit this field, the service generates and
	// sends a transaction ID as a response header of the request.
	TransactionID *string

	// Allows users to set headers on API requests
	Headers map[string]string
}

// Constants associated with the CreateScopeOptions.EnvironmentType property.
// The environment that the scope is targeted to.
const (
	CreateScopeOptionsEnvironmentTypeAwsConst       = "aws"
	CreateScopeOptionsEnvironmentTypeAzureConst     = "azure"
	CreateScopeOptionsEnvironmentTypeGcpConst       = "gcp"
	CreateScopeOptionsEnvironmentTypeHostedConst    = "hosted"
	CreateScopeOptionsEnvironmentTypeIBMConst       = "ibm"
	CreateScopeOptionsEnvironmentTypeOnPremiseConst = "on_premise"
	CreateScopeOptionsEnvironmentTypeOpenstackConst = "openstack"
	CreateScopeOptionsEnvironmentTypeServicesConst  = "services"
)

// NewCreateScopeOptions : Instantiate CreateScopeOptions
func (*PostureManagementV1) NewCreateScopeOptions() *CreateScopeOptions {
	return &CreateScopeOptions{}
}

// SetScopeName : Allow user to set ScopeName
func (_options *CreateScopeOptions) SetScopeName(scopeName string) *CreateScopeOptions {
	_options.ScopeName = core.StringPtr(scopeName)
	return _options
}

// SetScopeDescription : Allow user to set ScopeDescription
func (_options *CreateScopeOptions) SetScopeDescription(scopeDescription string) *CreateScopeOptions {
	_options.ScopeDescription = core.StringPtr(scopeDescription)
	return _options
}

// SetCollectorIds : Allow user to set CollectorIds
func (_options *CreateScopeOptions) SetCollectorIds(collectorIds []string) *CreateScopeOptions {
	_options.CollectorIds = collectorIds
	return _options
}

// SetCredentialID : Allow user to set CredentialID
func (_options *CreateScopeOptions) SetCredentialID(credentialID string) *CreateScopeOptions {
	_options.CredentialID = core.StringPtr(credentialID)
	return _options
}

// SetEnvironmentType : Allow user to set EnvironmentType
func (_options *CreateScopeOptions) SetEnvironmentType(environmentType string) *CreateScopeOptions {
	_options.EnvironmentType = core.StringPtr(environmentType)
	return _options
}

// SetTransactionID : Allow user to set TransactionID
func (_options *CreateScopeOptions) SetTransactionID(transactionID string) *CreateScopeOptions {
	_options.TransactionID = core.StringPtr(transactionID)
	return _options
}

// SetHeaders : Allow user to set Headers
func (options *CreateScopeOptions) SetHeaders(param map[string]string) *CreateScopeOptions {
	options.Headers = param
	return options
}

// CreateValidationOptions : The CreateValidation options.
type CreateValidationOptions struct {
	// The unique ID of the scope.
	ScopeID *string

	// The unique ID of the profile.
	ProfileID *string

	// The ID of the profile group.
	GroupProfileID *string

	// The unique identifier that is used to trace an entire request. If you omit this field, the service generates and
	// sends a transaction ID as a response header of the request.
	TransactionID *string

	// Allows users to set headers on API requests
	Headers map[string]string
}

// NewCreateValidationOptions : Instantiate CreateValidationOptions
func (*PostureManagementV1) NewCreateValidationOptions() *CreateValidationOptions {
	return &CreateValidationOptions{}
}

// SetScopeID : Allow user to set ScopeID
func (_options *CreateValidationOptions) SetScopeID(scopeID string) *CreateValidationOptions {
	_options.ScopeID = core.StringPtr(scopeID)
	return _options
}

// SetProfileID : Allow user to set ProfileID
func (_options *CreateValidationOptions) SetProfileID(profileID string) *CreateValidationOptions {
	_options.ProfileID = core.StringPtr(profileID)
	return _options
}

// SetGroupProfileID : Allow user to set GroupProfileID
func (_options *CreateValidationOptions) SetGroupProfileID(groupProfileID string) *CreateValidationOptions {
	_options.GroupProfileID = core.StringPtr(groupProfileID)
	return _options
}

// SetTransactionID : Allow user to set TransactionID
func (_options *CreateValidationOptions) SetTransactionID(transactionID string) *CreateValidationOptions {
	_options.TransactionID = core.StringPtr(transactionID)
	return _options
}

// SetHeaders : Allow user to set Headers
func (options *CreateValidationOptions) SetHeaders(param map[string]string) *CreateValidationOptions {
	options.Headers = param
	return options
}

// Credential : The details of the created credential.
type Credential struct {
	// The unique ID of the credential.
	CredentialID *string `json:"credential_id,omitempty"`

	// The name of the credential.
	CredentialName *string `json:"credential_name,omitempty"`

	// The creation time of the credential.
	CreatedTime *strfmt.DateTime `json:"created_time,omitempty"`
}

// UnmarshalCredential unmarshals an instance of Credential from the specified map of raw messages.
func UnmarshalCredential(m map[string]json.RawMessage, result interface{}) (err error) {
	obj := new(Credential)
	err = core.UnmarshalPrimitive(m, "credential_id", &obj.CredentialID)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "credential_name", &obj.CredentialName)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "created_time", &obj.CreatedTime)
	if err != nil {
		return
	}
	reflect.ValueOf(result).Elem().Set(reflect.ValueOf(obj))
	return
}

// ExchangeProtocolValidationResponse : loren ipsum.
type ExchangeProtocolValidationResponse struct {
	// loren ipsum.
	Success *string `json:"success,omitempty"`

	// loren ipsum.
	Message *string `json:"message,omitempty"`
}

// UnmarshalExchangeProtocolValidationResponse unmarshals an instance of ExchangeProtocolValidationResponse from the specified map of raw messages.
func UnmarshalExchangeProtocolValidationResponse(m map[string]json.RawMessage, result interface{}) (err error) {
	obj := new(ExchangeProtocolValidationResponse)
	err = core.UnmarshalPrimitive(m, "success", &obj.Success)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "message", &obj.Message)
	if err != nil {
		return
	}
	reflect.ValueOf(result).Elem().Set(reflect.ValueOf(obj))
	return
}

// GoalApplicabilityCriteria : The criteria that defines how a profile applies.
type GoalApplicabilityCriteria struct {
	// A list of environments that a profile can be applied to.
	Environment []string `json:"environment,omitempty"`

	// A list of resources that a profile can be used with.
	Resource []string `json:"resource,omitempty"`

	// The type of environment that a profile is able to be applied to.
	EnvironmentCategory []string `json:"environment_category,omitempty"`

	// The type of resource that a profile is able to be applied to.
	ResourceCategory []string `json:"resource_category,omitempty"`

	// The resource type that the profile applies to.
	ResourceType []string `json:"resource_type,omitempty"`

	// The software that the profile applies to.
	SoftwareDetails interface{} `json:"software_details,omitempty"`

	// The operating system that the profile applies to.
	OsDetails interface{} `json:"os_details,omitempty"`

	// Any additional details about the profile.
	AdditionalDetails interface{} `json:"additional_details,omitempty"`

	// The type of environment that your scope is targeted to.
	EnvironmentCategoryDescription map[string]string `json:"environment_category_description,omitempty"`

	// The environment that your scope is targeted to.
	EnvironmentDescription map[string]string `json:"environment_description,omitempty"`

	// The type of resource that your scope is targeted to.
	ResourceCategoryDescription map[string]string `json:"resource_category_description,omitempty"`

	// A further classification of the type of resource that your scope is targeted to.
	ResourceTypeDescription map[string]string `json:"resource_type_description,omitempty"`

	// The resource that is scanned as part of your scope.
	ResourceDescription map[string]string `json:"resource_description,omitempty"`
}

// UnmarshalGoalApplicabilityCriteria unmarshals an instance of GoalApplicabilityCriteria from the specified map of raw messages.
func UnmarshalGoalApplicabilityCriteria(m map[string]json.RawMessage, result interface{}) (err error) {
	obj := new(GoalApplicabilityCriteria)
	err = core.UnmarshalPrimitive(m, "environment", &obj.Environment)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "resource", &obj.Resource)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "environment_category", &obj.EnvironmentCategory)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "resource_category", &obj.ResourceCategory)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "resource_type", &obj.ResourceType)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "software_details", &obj.SoftwareDetails)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "os_details", &obj.OsDetails)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "additional_details", &obj.AdditionalDetails)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "environment_category_description", &obj.EnvironmentCategoryDescription)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "environment_description", &obj.EnvironmentDescription)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "resource_category_description", &obj.ResourceCategoryDescription)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "resource_type_description", &obj.ResourceTypeDescription)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "resource_description", &obj.ResourceDescription)
	if err != nil {
		return
	}
	reflect.ValueOf(result).Elem().Set(reflect.ValueOf(obj))
	return
}

// Goals : The goals on goals list.
type Goals struct {
	// The description of the goal.
	GoalDescription *string `json:"goal_description,omitempty"`

	// The goal ID.
	GoalID *string `json:"goal_id,omitempty"`

	// The goal status.
	Status *string `json:"status,omitempty"`

	// The severity of the goal.
	Severity *string `json:"severity,omitempty"`

	// The report completed time.
	CompletedTime *strfmt.DateTime `json:"completed_time,omitempty"`

	// The error on goal validation.
	Error *string `json:"error,omitempty"`

	// The list of resource results.
	ResourceResult []ResourceResult `json:"resource_result,omitempty"`

	// The criteria that defines how a profile applies.
	GoalApplicabilityCriteria *GoalApplicabilityCriteria `json:"goal_applicability_criteria,omitempty"`
}

// UnmarshalGoals unmarshals an instance of Goals from the specified map of raw messages.
func UnmarshalGoals(m map[string]json.RawMessage, result interface{}) (err error) {
	obj := new(Goals)
	err = core.UnmarshalPrimitive(m, "goal_description", &obj.GoalDescription)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "goal_id", &obj.GoalID)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "status", &obj.Status)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "severity", &obj.Severity)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "completed_time", &obj.CompletedTime)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "error", &obj.Error)
	if err != nil {
		return
	}
	err = core.UnmarshalModel(m, "resource_result", &obj.ResourceResult, UnmarshalResourceResult)
	if err != nil {
		return
	}
	err = core.UnmarshalModel(m, "goal_applicability_criteria", &obj.GoalApplicabilityCriteria, UnmarshalGoalApplicabilityCriteria)
	if err != nil {
		return
	}
	reflect.ValueOf(result).Elem().Set(reflect.ValueOf(obj))
	return
}

// GroupProfileResult : The result of a group profile.
type GroupProfileResult struct {
	// The group ID of profile.
	GroupProfileID *string `json:"group_profile_id,omitempty"`

	// The group name of the profile.
	GroupProfileName *string `json:"group_profile_name,omitempty"`

	// The type of profile. To learn more about profile types, check out the [docs]
	// (https://cloud.ibm.com/docs/security-compliance?topic=security-compliance-profiles).
	ProfileType *string `json:"profile_type,omitempty"`

	// The result of a scan.
	ValidationResult *ScanResult `json:"validation_result,omitempty"`

	// The result of a each profile in group profile.
	Profiles []ProfilesResult `json:"profiles,omitempty"`
}

// Constants associated with the GroupProfileResult.ProfileType property.
// The type of profile. To learn more about profile types, check out the [docs]
// (https://cloud.ibm.com/docs/security-compliance?topic=security-compliance-profiles).
const (
	GroupProfileResultProfileTypeAuthoredConst            = "authored"
	GroupProfileResultProfileTypeCustomConst              = "custom"
	GroupProfileResultProfileTypeStandardConst            = "standard"
	GroupProfileResultProfileTypeStandardCertificateConst = "standard_certificate"
	GroupProfileResultProfileTypeStandardCvConst          = "standard_cv"
	GroupProfileResultProfileTypeTemmplategroupConst      = "temmplategroup"
)

// UnmarshalGroupProfileResult unmarshals an instance of GroupProfileResult from the specified map of raw messages.
func UnmarshalGroupProfileResult(m map[string]json.RawMessage, result interface{}) (err error) {
	obj := new(GroupProfileResult)
	err = core.UnmarshalPrimitive(m, "group_profile_id", &obj.GroupProfileID)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "group_profile_name", &obj.GroupProfileName)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "profile_type", &obj.ProfileType)
	if err != nil {
		return
	}
	err = core.UnmarshalModel(m, "validation_result", &obj.ValidationResult, UnmarshalScanResult)
	if err != nil {
		return
	}
	err = core.UnmarshalModel(m, "profiles", &obj.Profiles, UnmarshalProfilesResult)
	if err != nil {
		return
	}
	reflect.ValueOf(result).Elem().Set(reflect.ValueOf(obj))
	return
}

// ListLatestScansOptions : The ListLatestScans options.
type ListLatestScansOptions struct {
	// The unique identifier that is used to trace an entire request. If you omit this field, the service generates and
	// sends a transaction ID as a response header of the request.
	TransactionID *string

	// The name of the scan.
	Name *string

	// The offset of the profiles.
	Offset *int64

	// The number of profiles that are included per page?.
	Limit *int64

	// Allows users to set headers on API requests
	Headers map[string]string
}

// NewListLatestScansOptions : Instantiate ListLatestScansOptions
func (*PostureManagementV1) NewListLatestScansOptions() *ListLatestScansOptions {
	return &ListLatestScansOptions{}
}

// SetTransactionID : Allow user to set TransactionID
func (_options *ListLatestScansOptions) SetTransactionID(transactionID string) *ListLatestScansOptions {
	_options.TransactionID = core.StringPtr(transactionID)
	return _options
}

// SetName : Allow user to set Name
func (_options *ListLatestScansOptions) SetName(name string) *ListLatestScansOptions {
	_options.Name = core.StringPtr(name)
	return _options
}

// SetOffset : Allow user to set Offset
func (_options *ListLatestScansOptions) SetOffset(offset int64) *ListLatestScansOptions {
	_options.Offset = core.Int64Ptr(offset)
	return _options
}

// SetLimit : Allow user to set Limit
func (_options *ListLatestScansOptions) SetLimit(limit int64) *ListLatestScansOptions {
	_options.Limit = core.Int64Ptr(limit)
	return _options
}

// SetHeaders : Allow user to set Headers
func (options *ListLatestScansOptions) SetHeaders(param map[string]string) *ListLatestScansOptions {
	options.Headers = param
	return options
}

// ListProfilesOptions : The ListProfiles options.
type ListProfilesOptions struct {
	// The unique identifier that is used to trace an entire request. If you omit this field, the service generates and
	// sends a transaction ID as a response header of the request.
	TransactionID *string

	// The name of the profile to be filtered.
	Name *string

	// The offset of the profiles.
	Offset *int64

	// The number of profiles that are included per page?.
	Limit *int64

	// Allows users to set headers on API requests
	Headers map[string]string
}

// NewListProfilesOptions : Instantiate ListProfilesOptions
func (*PostureManagementV1) NewListProfilesOptions() *ListProfilesOptions {
	return &ListProfilesOptions{}
}

// SetTransactionID : Allow user to set TransactionID
func (_options *ListProfilesOptions) SetTransactionID(transactionID string) *ListProfilesOptions {
	_options.TransactionID = core.StringPtr(transactionID)
	return _options
}

// SetName : Allow user to set Name
func (_options *ListProfilesOptions) SetName(name string) *ListProfilesOptions {
	_options.Name = core.StringPtr(name)
	return _options
}

// SetOffset : Allow user to set Offset
func (_options *ListProfilesOptions) SetOffset(offset int64) *ListProfilesOptions {
	_options.Offset = core.Int64Ptr(offset)
	return _options
}

// SetLimit : Allow user to set Limit
func (_options *ListProfilesOptions) SetLimit(limit int64) *ListProfilesOptions {
	_options.Limit = core.Int64Ptr(limit)
	return _options
}

// SetHeaders : Allow user to set Headers
func (options *ListProfilesOptions) SetHeaders(param map[string]string) *ListProfilesOptions {
	options.Headers = param
	return options
}

// ListScopesOptions : The ListScopes options.
type ListScopesOptions struct {
	// The unique identifier that is used to trace an entire request. If you omit this field, the service generates and
	// sends a transaction ID as a response header of the request.
	TransactionID *string

	// The name of the scope.
	Name *string

	// Allows users to set headers on API requests
	Headers map[string]string
}

// NewListScopesOptions : Instantiate ListScopesOptions
func (*PostureManagementV1) NewListScopesOptions() *ListScopesOptions {
	return &ListScopesOptions{}
}

// SetTransactionID : Allow user to set TransactionID
func (_options *ListScopesOptions) SetTransactionID(transactionID string) *ListScopesOptions {
	_options.TransactionID = core.StringPtr(transactionID)
	return _options
}

// SetName : Allow user to set Name
func (_options *ListScopesOptions) SetName(name string) *ListScopesOptions {
	_options.Name = core.StringPtr(name)
	return _options
}

// SetHeaders : Allow user to set Headers
func (options *ListScopesOptions) SetHeaders(param map[string]string) *ListScopesOptions {
	options.Headers = param
	return options
}

// ProfileItem : Profile.
type ProfileItem struct {
	// The name of the profile.
	Name *string `json:"name,omitempty"`

	// A description of the profile.
	Description *string `json:"description,omitempty"`

	// The version of the profile.
	Version *int64 `json:"version,omitempty"`

	// The user who created the profile.
	CreatedBy *string `json:"created_by,omitempty"`

	// The user who last modified the profile.
	ModifiedBy *string `json:"modified_by,omitempty"`

	// A reason that you want to delete a profile.
	ReasonForDelete *string `json:"reason_for_delete,omitempty"`

	// The criteria that defines how a profile applies.
	ApplicabilityCriteria *ApplicabilityCriteria `json:"applicability_criteria,omitempty"`

	// An auto-generated unique identifying number of the profile.
	ProfileID *string `json:"profile_id,omitempty"`

	// The base profile that the controls are pulled from.
	BaseProfile *string `json:"base_profile,omitempty"`

	// The type of profile.
	ProfileType *string `json:"profile_type,omitempty"`

	// The time that the profile was created in UTC.
	CreatedTime *strfmt.DateTime `json:"created_time,omitempty"`

	// The time that the profile was most recently modified in UTC.
	ModifiedTime *strfmt.DateTime `json:"modified_time,omitempty"`

	// The profile status. If the profile is enabled, the value is true. If the profile is disabled, the value is false.
	Enabled *bool `json:"enabled,omitempty"`
}

// Constants associated with the ProfileItem.ProfileType property.
// The type of profile.
const (
	ProfileItemProfileTypeCustomConst        = "custom"
	ProfileItemProfileTypePredefinedConst    = "predefined"
	ProfileItemProfileTypeTemplateGroupConst = "template_group"
)

// UnmarshalProfileItem unmarshals an instance of ProfileItem from the specified map of raw messages.
func UnmarshalProfileItem(m map[string]json.RawMessage, result interface{}) (err error) {
	obj := new(ProfileItem)
	err = core.UnmarshalPrimitive(m, "name", &obj.Name)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "description", &obj.Description)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "version", &obj.Version)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "created_by", &obj.CreatedBy)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "modified_by", &obj.ModifiedBy)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "reason_for_delete", &obj.ReasonForDelete)
	if err != nil {
		return
	}
	err = core.UnmarshalModel(m, "applicability_criteria", &obj.ApplicabilityCriteria, UnmarshalApplicabilityCriteria)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "profile_id", &obj.ProfileID)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "base_profile", &obj.BaseProfile)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "profile_type", &obj.ProfileType)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "created_time", &obj.CreatedTime)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "modified_time", &obj.ModifiedTime)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "enabled", &obj.Enabled)
	if err != nil {
		return
	}
	reflect.ValueOf(result).Elem().Set(reflect.ValueOf(obj))
	return
}

// ProfileResult : The result of a profile.
type ProfileResult struct {
	// The ID of the profile.
	ProfileID *string `json:"profile_id,omitempty"`

	// The name of the profile.
	ProfileName *string `json:"profile_name,omitempty"`

	// The type of profile. To learn more about profile types, check out the [docs]
	// (https://cloud.ibm.com/docs/security-compliance?topic=security-compliance-profiles).
	ProfileType *string `json:"profile_type,omitempty"`

	// The result of a scan.
	ValidationResult *ScanResult `json:"validation_result,omitempty"`
}

// Constants associated with the ProfileResult.ProfileType property.
// The type of profile. To learn more about profile types, check out the [docs]
// (https://cloud.ibm.com/docs/security-compliance?topic=security-compliance-profiles).
const (
	ProfileResultProfileTypeAuthoredConst            = "authored"
	ProfileResultProfileTypeCustomConst              = "custom"
	ProfileResultProfileTypeStandardConst            = "standard"
	ProfileResultProfileTypeStandardCertificateConst = "standard_certificate"
	ProfileResultProfileTypeStandardCvConst          = "standard_cv"
	ProfileResultProfileTypeTemmplategroupConst      = "temmplategroup"
)

// UnmarshalProfileResult unmarshals an instance of ProfileResult from the specified map of raw messages.
func UnmarshalProfileResult(m map[string]json.RawMessage, result interface{}) (err error) {
	obj := new(ProfileResult)
	err = core.UnmarshalPrimitive(m, "profile_id", &obj.ProfileID)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "profile_name", &obj.ProfileName)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "profile_type", &obj.ProfileType)
	if err != nil {
		return
	}
	err = core.UnmarshalModel(m, "validation_result", &obj.ValidationResult, UnmarshalScanResult)
	if err != nil {
		return
	}
	reflect.ValueOf(result).Elem().Set(reflect.ValueOf(obj))
	return
}

// ProfilesList : A list of profiles.
type ProfilesList struct {
	// The offset of the page.
	Offset *int64 `json:"offset" validate:"required"`

	// The number of profiles displayed per page.
	Limit *int64 `json:"limit" validate:"required"`

	// The total number of profiles.
	TotalCount *int64 `json:"total_count,omitempty"`

	// The URL of the first page of profiles.
	First *ProfilesListFirst `json:"first,omitempty"`

	// The URL of the last page of profiles.
	Last *ProfilesListLast `json:"last,omitempty"`

	// The URL of the previous page of profiles.
	Previous *ProfilesListPrevious `json:"previous,omitempty"`

	// The URL of the next page of profiles.
	Next *ProfilesListNext `json:"next,omitempty"`

	// Profiles.
	Profiles []ProfileItem `json:"profiles,omitempty"`
}

// UnmarshalProfilesList unmarshals an instance of ProfilesList from the specified map of raw messages.
func UnmarshalProfilesList(m map[string]json.RawMessage, result interface{}) (err error) {
	obj := new(ProfilesList)
	err = core.UnmarshalPrimitive(m, "offset", &obj.Offset)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "limit", &obj.Limit)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "total_count", &obj.TotalCount)
	if err != nil {
		return
	}
	err = core.UnmarshalModel(m, "first", &obj.First, UnmarshalProfilesListFirst)
	if err != nil {
		return
	}
	err = core.UnmarshalModel(m, "last", &obj.Last, UnmarshalProfilesListLast)
	if err != nil {
		return
	}
	err = core.UnmarshalModel(m, "previous", &obj.Previous, UnmarshalProfilesListPrevious)
	if err != nil {
		return
	}
	err = core.UnmarshalModel(m, "next", &obj.Next, UnmarshalProfilesListNext)
	if err != nil {
		return
	}
	err = core.UnmarshalModel(m, "profiles", &obj.Profiles, UnmarshalProfileItem)
	if err != nil {
		return
	}
	reflect.ValueOf(result).Elem().Set(reflect.ValueOf(obj))
	return
}

// ProfilesListFirst : The URL of the first page of profiles.
type ProfilesListFirst struct {
	// The URL of the first page of profiles.
	Href *string `json:"href,omitempty"`
}

// UnmarshalProfilesListFirst unmarshals an instance of ProfilesListFirst from the specified map of raw messages.
func UnmarshalProfilesListFirst(m map[string]json.RawMessage, result interface{}) (err error) {
	obj := new(ProfilesListFirst)
	err = core.UnmarshalPrimitive(m, "href", &obj.Href)
	if err != nil {
		return
	}
	reflect.ValueOf(result).Elem().Set(reflect.ValueOf(obj))
	return
}

// ProfilesListLast : The URL of the last page of profiles.
type ProfilesListLast struct {
	// The URL of the last page of profiles.
	Href *string `json:"href,omitempty"`
}

// UnmarshalProfilesListLast unmarshals an instance of ProfilesListLast from the specified map of raw messages.
func UnmarshalProfilesListLast(m map[string]json.RawMessage, result interface{}) (err error) {
	obj := new(ProfilesListLast)
	err = core.UnmarshalPrimitive(m, "href", &obj.Href)
	if err != nil {
		return
	}
	reflect.ValueOf(result).Elem().Set(reflect.ValueOf(obj))
	return
}

// ProfilesListNext : The URL of the next page of profiles.
type ProfilesListNext struct {
	// The URL of the next page of profiles.
	Href *string `json:"href,omitempty"`
}

// UnmarshalProfilesListNext unmarshals an instance of ProfilesListNext from the specified map of raw messages.
func UnmarshalProfilesListNext(m map[string]json.RawMessage, result interface{}) (err error) {
	obj := new(ProfilesListNext)
	err = core.UnmarshalPrimitive(m, "href", &obj.Href)
	if err != nil {
		return
	}
	reflect.ValueOf(result).Elem().Set(reflect.ValueOf(obj))
	return
}

// ProfilesListPrevious : The URL of the previous page of profiles.
type ProfilesListPrevious struct {
	// The URL of the previous page of profiles.
	Href *string `json:"href,omitempty"`
}

// UnmarshalProfilesListPrevious unmarshals an instance of ProfilesListPrevious from the specified map of raw messages.
func UnmarshalProfilesListPrevious(m map[string]json.RawMessage, result interface{}) (err error) {
	obj := new(ProfilesListPrevious)
	err = core.UnmarshalPrimitive(m, "href", &obj.Href)
	if err != nil {
		return
	}
	reflect.ValueOf(result).Elem().Set(reflect.ValueOf(obj))
	return
}

// ProfilesResult : The result of a each profile data in group profile.
type ProfilesResult struct {
	// The ID of the profile.
	ProfileID *string `json:"profile_id,omitempty"`

	// The name of the profile.
	ProfileName *string `json:"profile_name,omitempty"`

	// The type of profile. To learn more about profile types, check out the [docs]
	// (https://cloud.ibm.com/docs/security-compliance?topic=security-compliance-profiles).
	ProfileType *string `json:"profile_type,omitempty"`

	// The result of a scan.
	ValidationResult *Results `json:"validation_result,omitempty"`
}

// Constants associated with the ProfilesResult.ProfileType property.
// The type of profile. To learn more about profile types, check out the [docs]
// (https://cloud.ibm.com/docs/security-compliance?topic=security-compliance-profiles).
const (
	ProfilesResultProfileTypeAuthoredConst            = "authored"
	ProfilesResultProfileTypeCustomConst              = "custom"
	ProfilesResultProfileTypeStandardConst            = "standard"
	ProfilesResultProfileTypeStandardCertificateConst = "standard_certificate"
	ProfilesResultProfileTypeStandardCvConst          = "standard_cv"
	ProfilesResultProfileTypeTemmplategroupConst      = "temmplategroup"
)

// UnmarshalProfilesResult unmarshals an instance of ProfilesResult from the specified map of raw messages.
func UnmarshalProfilesResult(m map[string]json.RawMessage, result interface{}) (err error) {
	obj := new(ProfilesResult)
	err = core.UnmarshalPrimitive(m, "profile_id", &obj.ProfileID)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "profile_name", &obj.ProfileName)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "profile_type", &obj.ProfileType)
	if err != nil {
		return
	}
	err = core.UnmarshalModel(m, "validation_result", &obj.ValidationResult, UnmarshalResults)
	if err != nil {
		return
	}
	reflect.ValueOf(result).Elem().Set(reflect.ValueOf(obj))
	return
}

// ResourceResult : The resource results.
type ResourceResult struct {
	// The resource name.
	ResourceName *string `json:"resource_name,omitempty"`

	// The resource type.
	ResourcType *string `json:"resourc_type,omitempty"`

	// The resource control result status.
	ResourceStatus *string `json:"resource_status,omitempty"`

	// The expected results of a resource.
	DisplayExpectedValue *string `json:"display_expected_value,omitempty"`

	// The actual results of a resource.
	ActualValue *string `json:"actual_value,omitempty"`

	// The results information.
	ResultsInfo *string `json:"results_info,omitempty"`

	// The reason for goal not applicable for a resource.
	NaReason *string `json:"na_reason,omitempty"`
}

// UnmarshalResourceResult unmarshals an instance of ResourceResult from the specified map of raw messages.
func UnmarshalResourceResult(m map[string]json.RawMessage, result interface{}) (err error) {
	obj := new(ResourceResult)
	err = core.UnmarshalPrimitive(m, "resource_name", &obj.ResourceName)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "resourc_type", &obj.ResourcType)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "resource_status", &obj.ResourceStatus)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "display_expected_value", &obj.DisplayExpectedValue)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "actual_value", &obj.ActualValue)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "results_info", &obj.ResultsInfo)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "na_reason", &obj.NaReason)
	if err != nil {
		return
	}
	reflect.ValueOf(result).Elem().Set(reflect.ValueOf(obj))
	return
}

// ResourceStatistics : A scans summary controls.
type ResourceStatistics struct {
	// The resource count of pass controls.
	ResourcePassCount *int64 `json:"resource_pass_count,omitempty"`

	// The resource count of fail controls.
	ResourceFailCount *int64 `json:"resource_fail_count,omitempty"`

	// The resource count of unable to perform(u2p) controls.
	ResourceU2pCount *int64 `json:"resource_u2p_count,omitempty"`

	// The resource count of not applicable(na) controls.
	ResourceNaCount *int64 `json:"resource_na_count,omitempty"`
}

// UnmarshalResourceStatistics unmarshals an instance of ResourceStatistics from the specified map of raw messages.
func UnmarshalResourceStatistics(m map[string]json.RawMessage, result interface{}) (err error) {
	obj := new(ResourceStatistics)
	err = core.UnmarshalPrimitive(m, "resource_pass_count", &obj.ResourcePassCount)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "resource_fail_count", &obj.ResourceFailCount)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "resource_u2p_count", &obj.ResourceU2pCount)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "resource_na_count", &obj.ResourceNaCount)
	if err != nil {
		return
	}
	reflect.ValueOf(result).Elem().Set(reflect.ValueOf(obj))
	return
}

// Result : Result.
type Result struct {
	// Result.
	Result *bool `json:"result,omitempty"`

	// A message is returned.
	Message *string `json:"message,omitempty"`
}

// UnmarshalResult unmarshals an instance of Result from the specified map of raw messages.
func UnmarshalResult(m map[string]json.RawMessage, result interface{}) (err error) {
	obj := new(Result)
	err = core.UnmarshalPrimitive(m, "result", &obj.Result)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "message", &obj.Message)
	if err != nil {
		return
	}
	reflect.ValueOf(result).Elem().Set(reflect.ValueOf(obj))
	return
}

// Results : The result of a scan.
type Results struct {
	// The number of controls that passed the scan.
	ControlsPassCount *int64 `json:"controls_pass_count,omitempty"`

	// The number of controls that failed the scan.
	ControlsFailCount *int64 `json:"controls_fail_count,omitempty"`

	// The number of _Not applicable_ (na) controls. A control is evaluated as 'Not applicable' when its associated
	// resource can't be found.
	ControlsNaCount *int64 `json:"controls_na_count,omitempty"`

	// The number of _Unable to perform_ (u2p) controls. A control is evaluated as 'Unable to perform' when information
	// about its associated resource can't be collected.
	ControlsU2pCount *int64 `json:"controls_u2p_count,omitempty"`

	// The total number of controls that were included in the scan.
	ControlsTotalCount *int64 `json:"controls_total_count,omitempty"`
}

// UnmarshalResults unmarshals an instance of Results from the specified map of raw messages.
func UnmarshalResults(m map[string]json.RawMessage, result interface{}) (err error) {
	obj := new(Results)
	err = core.UnmarshalPrimitive(m, "controls_pass_count", &obj.ControlsPassCount)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "controls_fail_count", &obj.ControlsFailCount)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "controls_na_count", &obj.ControlsNaCount)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "controls_u2p_count", &obj.ControlsU2pCount)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "controls_total_count", &obj.ControlsTotalCount)
	if err != nil {
		return
	}
	reflect.ValueOf(result).Elem().Set(reflect.ValueOf(obj))
	return
}

// Scan : Scan.
type Scan struct {
	// An auto-generated unique identifier for the scan.
	ScanID *string `json:"scan_id,omitempty"`

	// An auto-generated unique identifier for discovery.
	DiscoverID *string `json:"discover_id,omitempty"`

	// The status of the collector as it completes a scan.
	Status *string `json:"status,omitempty"`

	// The current status of the collector.
	StatusMessage *string `json:"status_message,omitempty"`
}

// Constants associated with the Scan.Status property.
// The status of the collector as it completes a scan.
const (
	ScanStatusAbortTaskRequestCompletedConst       = "abort_task_request_completed"
	ScanStatusAbortTaskRequestFailedConst          = "abort_task_request_failed"
	ScanStatusAbortTaskRequestReceivedConst        = "abort_task_request_received"
	ScanStatusControllerAbortedConst               = "controller_aborted"
	ScanStatusDiscoveryCompletedConst              = "discovery_completed"
	ScanStatusDiscoveryInProgressConst             = "discovery_in_progress"
	ScanStatusDiscoveryResultPostedNoErrorConst    = "discovery_result_posted_no_error"
	ScanStatusDiscoveryResultPostedWithErrorConst  = "discovery_result_posted_with_error"
	ScanStatusDiscoveryStartedConst                = "discovery_started"
	ScanStatusErrorInAbortTaskRequestConst         = "error_in_abort_task_request"
	ScanStatusErrorInDiscoveryConst                = "error_in_discovery"
	ScanStatusErrorInFactCollectionConst           = "error_in_fact_collection"
	ScanStatusErrorInFactValidationConst           = "error_in_fact_validation"
	ScanStatusErrorInInventoryConst                = "error_in_inventory"
	ScanStatusErrorInRemediationConst              = "error_in_remediation"
	ScanStatusErrorInValidationConst               = "error_in_validation"
	ScanStatusFactCollectionCompletedConst         = "fact_collection_completed"
	ScanStatusFactCollectionInProgressConst        = "fact_collection_in_progress"
	ScanStatusFactCollectionStartedConst           = "fact_collection_started"
	ScanStatusFactValidationCompletedConst         = "fact_validation_completed"
	ScanStatusFactValidationInProgressConst        = "fact_validation_in_progress"
	ScanStatusFactValidationStartedConst           = "fact_validation_started"
	ScanStatusGatewayAbortedConst                  = "gateway_aborted"
	ScanStatusInventoryCompletedConst              = "inventory_completed"
	ScanStatusInventoryCompletedWithErrorConst     = "inventory_completed_with_error"
	ScanStatusInventoryInProgressConst             = "inventory_in_progress"
	ScanStatusInventoryStartedConst                = "inventory_started"
	ScanStatusNotAcceptedConst                     = "not_accepted"
	ScanStatusPendingConst                         = "pending"
	ScanStatusRemediationCompletedConst            = "remediation_completed"
	ScanStatusRemediationInProgressConst           = "remediation_in_progress"
	ScanStatusRemediationStartedConst              = "remediation_started"
	ScanStatusSentToCollectorConst                 = "sent_to_collector"
	ScanStatusUserAbortedConst                     = "user_aborted"
	ScanStatusValidationCompletedConst             = "validation_completed"
	ScanStatusValidationInProgressConst            = "validation_in_progress"
	ScanStatusValidationResultPostedNoErrorConst   = "validation_result_posted_no_error"
	ScanStatusValidationResultPostedWithErrorConst = "validation_result_posted_with_error"
	ScanStatusValidationStartedConst               = "validation_started"
	ScanStatusWaitingForRefineConst                = "waiting_for_refine"
)

// UnmarshalScan unmarshals an instance of Scan from the specified map of raw messages.
func UnmarshalScan(m map[string]json.RawMessage, result interface{}) (err error) {
	obj := new(Scan)
	err = core.UnmarshalPrimitive(m, "scan_id", &obj.ScanID)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "discover_id", &obj.DiscoverID)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "status", &obj.Status)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "status_message", &obj.StatusMessage)
	if err != nil {
		return
	}
	reflect.ValueOf(result).Elem().Set(reflect.ValueOf(obj))
	return
}

// ScanItem : The details of a scan.
type ScanItem struct {
	// The ID of the scan.
	ScanID *string `json:"scan_id,omitempty"`

	// The name of the scan.
	ScanName *string `json:"scan_name,omitempty"`

	// The ID of the scan.
	ScopeID *string `json:"scope_id,omitempty"`

	// The name of the scope.
	ScopeName *string `json:"scope_name,omitempty"`

	// The ID of the profile.
	ProfileID *string `json:"profile_id,omitempty"`

	// The name of the profile.
	ProfileName *string `json:"profile_name,omitempty"`

	// The type of profile. To learn more about profile types, check out the [docs]
	// (https://cloud.ibm.com/docs/security-compliance?topic=security-compliance-profiles).
	ProfileType *string `json:"profile_type,omitempty"`

	// The group ID of profile.
	GroupProfileID *string `json:"group_profile_id,omitempty"`

	// The group name of the profile.
	GroupProfileName *string `json:"group_profile_name,omitempty"`

	// The entity that ran the report.
	ReportRunBy *string `json:"report_run_by,omitempty"`

	// The date and time the scan was run.
	StartedTime *strfmt.DateTime `json:"started_time,omitempty"`

	// The date and time the scan completed.
	EndTime *strfmt.DateTime `json:"end_time,omitempty"`

	// The result of a scan.
	Result *ScanResult `json:"result,omitempty"`
}

// Constants associated with the ScanItem.ProfileType property.
// The type of profile. To learn more about profile types, check out the [docs]
// (https://cloud.ibm.com/docs/security-compliance?topic=security-compliance-profiles).
const (
	ScanItemProfileTypeAuthoredConst            = "authored"
	ScanItemProfileTypeCustomConst              = "custom"
	ScanItemProfileTypeStandardConst            = "standard"
	ScanItemProfileTypeStandardCertificateConst = "standard_certificate"
	ScanItemProfileTypeStandardCvConst          = "standard_cv"
	ScanItemProfileTypeTemmplategroupConst      = "temmplategroup"
)

// UnmarshalScanItem unmarshals an instance of ScanItem from the specified map of raw messages.
func UnmarshalScanItem(m map[string]json.RawMessage, result interface{}) (err error) {
	obj := new(ScanItem)
	err = core.UnmarshalPrimitive(m, "scan_id", &obj.ScanID)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "scan_name", &obj.ScanName)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "scope_id", &obj.ScopeID)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "scope_name", &obj.ScopeName)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "profile_id", &obj.ProfileID)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "profile_name", &obj.ProfileName)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "profile_type", &obj.ProfileType)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "group_profile_id", &obj.GroupProfileID)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "group_profile_name", &obj.GroupProfileName)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "report_run_by", &obj.ReportRunBy)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "started_time", &obj.StartedTime)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "end_time", &obj.EndTime)
	if err != nil {
		return
	}
	err = core.UnmarshalModel(m, "result", &obj.Result, UnmarshalScanResult)
	if err != nil {
		return
	}
	reflect.ValueOf(result).Elem().Set(reflect.ValueOf(obj))
	return
}

// ScanResult : The result of a scan.
type ScanResult struct {
	// The number of goals that passed the scan.
	GoalsPassCount *int64 `json:"goals_pass_count,omitempty"`

	// The number of _Unable to perform_ (u2p) goals. A goal is evaluated as 'Unable to perform' when information about its
	// associated resource can't be collected.
	GoalsU2pCount *int64 `json:"goals_u2p_count,omitempty"`

	// The number of _Not applicable_ (na) goals. A goal is evaluated as 'Not applicable' when its associated resource
	// can't be found.
	GoalsNaCount *int64 `json:"goals_na_count,omitempty"`

	// The number of goals that failed the scan.
	GoalsFailCount *int64 `json:"goals_fail_count,omitempty"`

	// The total number of goals that were included in the scan.
	GoalsTotalCount *int64 `json:"goals_total_count,omitempty"`

	// The number of controls that passed the scan.
	ControlsPassCount *int64 `json:"controls_pass_count,omitempty"`

	// The number of controls that failed the scan.
	ControlsFailCount *int64 `json:"controls_fail_count,omitempty"`

	// The number of _Not applicable_ (na) controls. A control is evaluated as 'Not applicable' when its associated
	// resource can't be found.
	ControlsNaCount *int64 `json:"controls_na_count,omitempty"`

	// The number of _Unable to perform_ (u2p) controls. A control is evaluated as 'Unable to perform' when information
	// about its associated resource can't be collected.
	ControlsU2pCount *int64 `json:"controls_u2p_count,omitempty"`

	// The total number of controls that were included in the scan.
	ControlsTotalCount *int64 `json:"controls_total_count,omitempty"`
}

// UnmarshalScanResult unmarshals an instance of ScanResult from the specified map of raw messages.
func UnmarshalScanResult(m map[string]json.RawMessage, result interface{}) (err error) {
	obj := new(ScanResult)
	err = core.UnmarshalPrimitive(m, "goals_pass_count", &obj.GoalsPassCount)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "goals_u2p_count", &obj.GoalsU2pCount)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "goals_na_count", &obj.GoalsNaCount)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "goals_fail_count", &obj.GoalsFailCount)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "goals_total_count", &obj.GoalsTotalCount)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "controls_pass_count", &obj.ControlsPassCount)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "controls_fail_count", &obj.ControlsFailCount)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "controls_na_count", &obj.ControlsNaCount)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "controls_u2p_count", &obj.ControlsU2pCount)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "controls_total_count", &obj.ControlsTotalCount)
	if err != nil {
		return
	}
	reflect.ValueOf(result).Elem().Set(reflect.ValueOf(obj))
	return
}

// ScanSummariesOptions : The ScanSummaries options.
type ScanSummariesOptions struct {
	// The scope ID. This can be obtained from the Security and Compliance Center UI by clicking on the scope name. The URL
	// contains the ID.
	ScopeID *string `validate:"required"`

	// The unique identifier that is used to trace an entire request. If you omit this field, the service generates and
	// sends a transaction ID as a response header of the request.
	TransactionID *string

	// The profile ID. This can be obtained from the Security and Compliance Center UI by clicking on the profile name. The
	// URL contains the ID.
	ProfileID *string

	// The group profile ID. This can be obtained from the Security and Compliance Center UI by clicking on the group
	// profile name. The URL contains the ID.
	GroupProfileID *string

	// The offset of the profiles.
	Offset *int64

	// The number of profiles that are included per page?.
	Limit *int64

	// Allows users to set headers on API requests
	Headers map[string]string
}

// NewScanSummariesOptions : Instantiate ScanSummariesOptions
func (*PostureManagementV1) NewScanSummariesOptions(scopeID string) *ScanSummariesOptions {
	return &ScanSummariesOptions{
		ScopeID: core.StringPtr(scopeID),
	}
}

// SetScopeID : Allow user to set ScopeID
func (_options *ScanSummariesOptions) SetScopeID(scopeID string) *ScanSummariesOptions {
	_options.ScopeID = core.StringPtr(scopeID)
	return _options
}

// SetTransactionID : Allow user to set TransactionID
func (_options *ScanSummariesOptions) SetTransactionID(transactionID string) *ScanSummariesOptions {
	_options.TransactionID = core.StringPtr(transactionID)
	return _options
}

// SetProfileID : Allow user to set ProfileID
func (_options *ScanSummariesOptions) SetProfileID(profileID string) *ScanSummariesOptions {
	_options.ProfileID = core.StringPtr(profileID)
	return _options
}

// SetGroupProfileID : Allow user to set GroupProfileID
func (_options *ScanSummariesOptions) SetGroupProfileID(groupProfileID string) *ScanSummariesOptions {
	_options.GroupProfileID = core.StringPtr(groupProfileID)
	return _options
}

// SetOffset : Allow user to set Offset
func (_options *ScanSummariesOptions) SetOffset(offset int64) *ScanSummariesOptions {
	_options.Offset = core.Int64Ptr(offset)
	return _options
}

// SetLimit : Allow user to set Limit
func (_options *ScanSummariesOptions) SetLimit(limit int64) *ScanSummariesOptions {
	_options.Limit = core.Int64Ptr(limit)
	return _options
}

// SetHeaders : Allow user to set Headers
func (options *ScanSummariesOptions) SetHeaders(param map[string]string) *ScanSummariesOptions {
	options.Headers = param
	return options
}

// ScansList : A list of scans.
type ScansList struct {
	// The offset of the page.
	Offset *int64 `json:"offset" validate:"required"`

	// The number of scans displayed per page.
	Limit *int64 `json:"limit" validate:"required"`

	// The total number of scans in the list.
	TotalCount *int64 `json:"total_count,omitempty"`

	// The URL of the first page of scans.
	First *ScansListFirst `json:"first,omitempty"`

	// The URL of the last page of scans.
	Last *ScansListLast `json:"last,omitempty"`

	// The URL of the previous page of scans.
	Previous *ScansListPrevious `json:"previous,omitempty"`

	// The URL of the next page of scans.
	Next *ScansListNext `json:"next,omitempty"`

	// The details of a scan.
	LatestScans []ScanItem `json:"latest_scans,omitempty"`
}

// UnmarshalScansList unmarshals an instance of ScansList from the specified map of raw messages.
func UnmarshalScansList(m map[string]json.RawMessage, result interface{}) (err error) {
	obj := new(ScansList)
	err = core.UnmarshalPrimitive(m, "offset", &obj.Offset)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "limit", &obj.Limit)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "total_count", &obj.TotalCount)
	if err != nil {
		return
	}
	err = core.UnmarshalModel(m, "first", &obj.First, UnmarshalScansListFirst)
	if err != nil {
		return
	}
	err = core.UnmarshalModel(m, "last", &obj.Last, UnmarshalScansListLast)
	if err != nil {
		return
	}
	err = core.UnmarshalModel(m, "previous", &obj.Previous, UnmarshalScansListPrevious)
	if err != nil {
		return
	}
	err = core.UnmarshalModel(m, "next", &obj.Next, UnmarshalScansListNext)
	if err != nil {
		return
	}
	err = core.UnmarshalModel(m, "latest_scans", &obj.LatestScans, UnmarshalScanItem)
	if err != nil {
		return
	}
	reflect.ValueOf(result).Elem().Set(reflect.ValueOf(obj))
	return
}

// ScansListFirst : The URL of the first page of scans.
type ScansListFirst struct {
	// The URL of the first page of scans.
	Href *string `json:"href,omitempty"`
}

// UnmarshalScansListFirst unmarshals an instance of ScansListFirst from the specified map of raw messages.
func UnmarshalScansListFirst(m map[string]json.RawMessage, result interface{}) (err error) {
	obj := new(ScansListFirst)
	err = core.UnmarshalPrimitive(m, "href", &obj.Href)
	if err != nil {
		return
	}
	reflect.ValueOf(result).Elem().Set(reflect.ValueOf(obj))
	return
}

// ScansListLast : The URL of the last page of scans.
type ScansListLast struct {
	// The URL of the last page of scans.
	Href *string `json:"href,omitempty"`
}

// UnmarshalScansListLast unmarshals an instance of ScansListLast from the specified map of raw messages.
func UnmarshalScansListLast(m map[string]json.RawMessage, result interface{}) (err error) {
	obj := new(ScansListLast)
	err = core.UnmarshalPrimitive(m, "href", &obj.Href)
	if err != nil {
		return
	}
	reflect.ValueOf(result).Elem().Set(reflect.ValueOf(obj))
	return
}

// ScansListNext : The URL of the next page of scans.
type ScansListNext struct {
	// The URL of the next page of scans.
	Href *string `json:"href,omitempty"`
}

// UnmarshalScansListNext unmarshals an instance of ScansListNext from the specified map of raw messages.
func UnmarshalScansListNext(m map[string]json.RawMessage, result interface{}) (err error) {
	obj := new(ScansListNext)
	err = core.UnmarshalPrimitive(m, "href", &obj.Href)
	if err != nil {
		return
	}
	reflect.ValueOf(result).Elem().Set(reflect.ValueOf(obj))
	return
}

// ScansListPrevious : The URL of the previous page of scans.
type ScansListPrevious struct {
	// The URL of the previous page of scans.
	Href *string `json:"href,omitempty"`
}

// UnmarshalScansListPrevious unmarshals an instance of ScansListPrevious from the specified map of raw messages.
func UnmarshalScansListPrevious(m map[string]json.RawMessage, result interface{}) (err error) {
	obj := new(ScansListPrevious)
	err = core.UnmarshalPrimitive(m, "href", &obj.Href)
	if err != nil {
		return
	}
	reflect.ValueOf(result).Elem().Set(reflect.ValueOf(obj))
	return
}

// ScansSummaryOptions : The ScansSummary options.
type ScansSummaryOptions struct {
	// Your Scan ID.
	ScanID *string `validate:"required,ne="`

	// The profile ID. This can be obtained from the Security and Compliance Center UI by clicking on the profile name. The
	// URL contains the ID.
	ProfileID *string

	// The unique identifier that is used to trace an entire request. If you omit this field, the service generates and
	// sends a transaction ID as a response header of the request.
	TransactionID *string

	// The name of the scan summary.
	Name *string

	// Allows users to set headers on API requests
	Headers map[string]string
}

// NewScansSummaryOptions : Instantiate ScansSummaryOptions
func (*PostureManagementV1) NewScansSummaryOptions(scanID string) *ScansSummaryOptions {
	return &ScansSummaryOptions{
		ScanID: core.StringPtr(scanID),
	}
}

// SetScanID : Allow user to set ScanID
func (_options *ScansSummaryOptions) SetScanID(scanID string) *ScansSummaryOptions {
	_options.ScanID = core.StringPtr(scanID)
	return _options
}

// SetProfileID : Allow user to set ProfileID
func (_options *ScansSummaryOptions) SetProfileID(profileID string) *ScansSummaryOptions {
	_options.ProfileID = core.StringPtr(profileID)
	return _options
}

// SetTransactionID : Allow user to set TransactionID
func (_options *ScansSummaryOptions) SetTransactionID(transactionID string) *ScansSummaryOptions {
	_options.TransactionID = core.StringPtr(transactionID)
	return _options
}

// SetName : Allow user to set Name
func (_options *ScansSummaryOptions) SetName(name string) *ScansSummaryOptions {
	_options.Name = core.StringPtr(name)
	return _options
}

// SetHeaders : Allow user to set Headers
func (options *ScansSummaryOptions) SetHeaders(param map[string]string) *ScansSummaryOptions {
	options.Headers = param
	return options
}

// Scope : Create Scope Response.
type Scope struct {
	// A unique identifier for your scope.
	ScopeID *string `json:"scope_id,omitempty"`

	// A unique name for your scope.
	ScopeName *string `json:"scope_name,omitempty"`

	// A detailed description of the scope.
	ScopeDescription *string `json:"scope_description,omitempty"`

	// The unique IDs of the collectors that are attached to the scope.
	CollectorIds []string `json:"collector_ids,omitempty"`

	// The unique identifier of the credential.
	CredentialID *string `json:"credential_id,omitempty"`

	// The environment that the scope is targeted to.
	EnvironmentType *string `json:"environment_type,omitempty"`

	// The time that the scope was created in UTC.
	CreatedTime *strfmt.DateTime `json:"created_time,omitempty"`

	// The time that the scope was last modified in UTC.
	ModifiedTime *strfmt.DateTime `json:"modified_time,omitempty"`
}

// Constants associated with the Scope.EnvironmentType property.
// The environment that the scope is targeted to.
const (
	ScopeEnvironmentTypeAwsConst       = "aws"
	ScopeEnvironmentTypeAzureConst     = "azure"
	ScopeEnvironmentTypeGcpConst       = "gcp"
	ScopeEnvironmentTypeHostedConst    = "hosted"
	ScopeEnvironmentTypeIBMConst       = "ibm"
	ScopeEnvironmentTypeOnPremiseConst = "on_premise"
	ScopeEnvironmentTypeOpenstackConst = "openstack"
	ScopeEnvironmentTypeServicesConst  = "services"
)

// UnmarshalScope unmarshals an instance of Scope from the specified map of raw messages.
func UnmarshalScope(m map[string]json.RawMessage, result interface{}) (err error) {
	obj := new(Scope)
	err = core.UnmarshalPrimitive(m, "scope_id", &obj.ScopeID)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "scope_name", &obj.ScopeName)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "scope_description", &obj.ScopeDescription)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "collector_ids", &obj.CollectorIds)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "credential_id", &obj.CredentialID)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "environment_type", &obj.EnvironmentType)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "created_time", &obj.CreatedTime)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "modified_time", &obj.ModifiedTime)
	if err != nil {
		return
	}
	reflect.ValueOf(result).Elem().Set(reflect.ValueOf(obj))
	return
}

// ScopeItem : Scope.
type ScopeItem struct {
	// A detailed description of the scope.
	Description *string `json:"description,omitempty"`

	// The user who created the scope.
	CreatedBy *string `json:"created_by,omitempty"`

	// The user who most recently modified the scope.
	ModifiedBy *string `json:"modified_by,omitempty"`

	// An auto-generated unique identifier for the scope.
	ScopeID *string `json:"scope_id,omitempty"`

	// A unique name for your scope.
	Name *string `json:"name,omitempty"`

	// Indicates whether scope is enabled/disabled.
	Enabled *bool `json:"enabled,omitempty"`

	// The environment that the scope is targeted to.
	EnvironmentType *string `json:"environment_type,omitempty"`

	// The time that the scope was created in UTC.
	CreatedTime *strfmt.DateTime `json:"created_time,omitempty"`

	// The time that the scope was last modified in UTC.
	ModifiedTime *strfmt.DateTime `json:"modified_time,omitempty"`

	// The last type of scan that was run on the scope.
	LastScanType *string `json:"last_scan_type,omitempty"`

	// A description of the last scan type.
	LastScanTypeDescription *string `json:"last_scan_type_description,omitempty"`

	// The last time that a scan status for a scope was updated in UTC.
	LastScanStatusUpdatedTime *strfmt.DateTime `json:"last_scan_status_updated_time,omitempty"`

	// The unique IDs of the collectors that are attached to the scope.
	CollectorsID []string `json:"collectors_id,omitempty"`

	// A list of the scans that have been run on the scope.
	Scans []Scan `json:"scans,omitempty"`
}

// Constants associated with the ScopeItem.EnvironmentType property.
// The environment that the scope is targeted to.
const (
	ScopeItemEnvironmentTypeAwsConst       = "aws"
	ScopeItemEnvironmentTypeAzureConst     = "azure"
	ScopeItemEnvironmentTypeGcpConst       = "gcp"
	ScopeItemEnvironmentTypeHostedConst    = "hosted"
	ScopeItemEnvironmentTypeIBMConst       = "ibm"
	ScopeItemEnvironmentTypeOnPremiseConst = "on_premise"
	ScopeItemEnvironmentTypeOpenstackConst = "openstack"
	ScopeItemEnvironmentTypeServicesConst  = "services"
)

// Constants associated with the ScopeItem.LastScanType property.
// The last type of scan that was run on the scope.
const (
	ScopeItemLastScanTypeAbortTasksConst     = "abort_tasks"
	ScopeItemLastScanTypeDiscoveryConst      = "discovery"
	ScopeItemLastScanTypeEvidenceConst       = "evidence"
	ScopeItemLastScanTypeFactCollectionConst = "fact_collection"
	ScopeItemLastScanTypeFactValidationConst = "fact_validation"
	ScopeItemLastScanTypeInventoryConst      = "inventory"
	ScopeItemLastScanTypeRemediationConst    = "remediation"
	ScopeItemLastScanTypeScriptConst         = "script"
	ScopeItemLastScanTypeValidationConst     = "validation"
)

// UnmarshalScopeItem unmarshals an instance of ScopeItem from the specified map of raw messages.
func UnmarshalScopeItem(m map[string]json.RawMessage, result interface{}) (err error) {
	obj := new(ScopeItem)
	err = core.UnmarshalPrimitive(m, "description", &obj.Description)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "created_by", &obj.CreatedBy)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "modified_by", &obj.ModifiedBy)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "scope_id", &obj.ScopeID)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "name", &obj.Name)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "enabled", &obj.Enabled)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "environment_type", &obj.EnvironmentType)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "created_time", &obj.CreatedTime)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "modified_time", &obj.ModifiedTime)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "last_scan_type", &obj.LastScanType)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "last_scan_type_description", &obj.LastScanTypeDescription)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "last_scan_status_updated_time", &obj.LastScanStatusUpdatedTime)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "collectors_id", &obj.CollectorsID)
	if err != nil {
		return
	}
	err = core.UnmarshalModel(m, "scans", &obj.Scans, UnmarshalScan)
	if err != nil {
		return
	}
	reflect.ValueOf(result).Elem().Set(reflect.ValueOf(obj))
	return
}

// ScopesList : Scopes list.
type ScopesList struct {
	// Scopes.
	Scopes []ScopeItem `json:"scopes,omitempty"`
}

// UnmarshalScopesList unmarshals an instance of ScopesList from the specified map of raw messages.
func UnmarshalScopesList(m map[string]json.RawMessage, result interface{}) (err error) {
	obj := new(ScopesList)
	err = core.UnmarshalModel(m, "scopes", &obj.Scopes, UnmarshalScopeItem)
	if err != nil {
		return
	}
	reflect.ValueOf(result).Elem().Set(reflect.ValueOf(obj))
	return
}

// SummariesList : A list of scan summaries.
type SummariesList struct {
	// The offset of the page.
	Offset *int64 `json:"offset" validate:"required"`

	// The number of scans displayed per page.
	Limit *int64 `json:"limit" validate:"required"`

	// The total number of scans available in the list of summaries.
	TotalCount *int64 `json:"total_count,omitempty"`

	// he URL of the first scan summary.
	First *SummariesListFirst `json:"first,omitempty"`

	// The URL of the last scan summary.
	Last *SummariesListLast `json:"last,omitempty"`

	// The URL of the previous scan summary.
	Previous *SummariesListPrevious `json:"previous,omitempty"`

	// The URL of the previous scan summary.
	Next *SummariesListNext `json:"next,omitempty"`

	// Summaries.
	Summaries []SummaryItem `json:"summaries,omitempty"`
}

// UnmarshalSummariesList unmarshals an instance of SummariesList from the specified map of raw messages.
func UnmarshalSummariesList(m map[string]json.RawMessage, result interface{}) (err error) {
	obj := new(SummariesList)
	err = core.UnmarshalPrimitive(m, "offset", &obj.Offset)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "limit", &obj.Limit)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "total_count", &obj.TotalCount)
	if err != nil {
		return
	}
	err = core.UnmarshalModel(m, "first", &obj.First, UnmarshalSummariesListFirst)
	if err != nil {
		return
	}
	err = core.UnmarshalModel(m, "last", &obj.Last, UnmarshalSummariesListLast)
	if err != nil {
		return
	}
	err = core.UnmarshalModel(m, "previous", &obj.Previous, UnmarshalSummariesListPrevious)
	if err != nil {
		return
	}
	err = core.UnmarshalModel(m, "next", &obj.Next, UnmarshalSummariesListNext)
	if err != nil {
		return
	}
	err = core.UnmarshalModel(m, "summaries", &obj.Summaries, UnmarshalSummaryItem)
	if err != nil {
		return
	}
	reflect.ValueOf(result).Elem().Set(reflect.ValueOf(obj))
	return
}

// SummariesListFirst : he URL of the first scan summary.
type SummariesListFirst struct {
	// The URL of the first scan summary.
	Href *string `json:"href,omitempty"`
}

// UnmarshalSummariesListFirst unmarshals an instance of SummariesListFirst from the specified map of raw messages.
func UnmarshalSummariesListFirst(m map[string]json.RawMessage, result interface{}) (err error) {
	obj := new(SummariesListFirst)
	err = core.UnmarshalPrimitive(m, "href", &obj.Href)
	if err != nil {
		return
	}
	reflect.ValueOf(result).Elem().Set(reflect.ValueOf(obj))
	return
}

// SummariesListLast : The URL of the last scan summary.
type SummariesListLast struct {
	// The URL of the last scan summary.
	Href *string `json:"href,omitempty"`
}

// UnmarshalSummariesListLast unmarshals an instance of SummariesListLast from the specified map of raw messages.
func UnmarshalSummariesListLast(m map[string]json.RawMessage, result interface{}) (err error) {
	obj := new(SummariesListLast)
	err = core.UnmarshalPrimitive(m, "href", &obj.Href)
	if err != nil {
		return
	}
	reflect.ValueOf(result).Elem().Set(reflect.ValueOf(obj))
	return
}

// SummariesListNext : The URL of the previous scan summary.
type SummariesListNext struct {
	// The URL of the next scan summary.
	Href *string `json:"href,omitempty"`
}

// UnmarshalSummariesListNext unmarshals an instance of SummariesListNext from the specified map of raw messages.
func UnmarshalSummariesListNext(m map[string]json.RawMessage, result interface{}) (err error) {
	obj := new(SummariesListNext)
	err = core.UnmarshalPrimitive(m, "href", &obj.Href)
	if err != nil {
		return
	}
	reflect.ValueOf(result).Elem().Set(reflect.ValueOf(obj))
	return
}

// SummariesListPrevious : The URL of the previous scan summary.
type SummariesListPrevious struct {
	// The URL of the previous scan summary.
	Href *string `json:"href,omitempty"`
}

// UnmarshalSummariesListPrevious unmarshals an instance of SummariesListPrevious from the specified map of raw messages.
func UnmarshalSummariesListPrevious(m map[string]json.RawMessage, result interface{}) (err error) {
	obj := new(SummariesListPrevious)
	err = core.UnmarshalPrimitive(m, "href", &obj.Href)
	if err != nil {
		return
	}
	reflect.ValueOf(result).Elem().Set(reflect.ValueOf(obj))
	return
}

// Summary : A list of  scans summary.
type Summary struct {
	// The scan ID.
	ScanID *string `json:"scan_id,omitempty"`

	// The scan discovery ID.
	DiscoveryID *string `json:"discovery_id,omitempty"`

	// The scan profile ID.
	ProfileID *string `json:"profile_id,omitempty"`

	// The scan profile name.
	ProfileName *string `json:"profile_name,omitempty"`

	// The scan summary scope ID.
	ScopeID *string `json:"scope_id,omitempty"`

	// The list of controls on the scan summary.
	Controls []Controls `json:"controls,omitempty"`
}

// UnmarshalSummary unmarshals an instance of Summary from the specified map of raw messages.
func UnmarshalSummary(m map[string]json.RawMessage, result interface{}) (err error) {
	obj := new(Summary)
	err = core.UnmarshalPrimitive(m, "scan_id", &obj.ScanID)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "discovery_id", &obj.DiscoveryID)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "profile_id", &obj.ProfileID)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "profile_name", &obj.ProfileName)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "scope_id", &obj.ScopeID)
	if err != nil {
		return
	}
	err = core.UnmarshalModel(m, "controls", &obj.Controls, UnmarshalControls)
	if err != nil {
		return
	}
	reflect.ValueOf(result).Elem().Set(reflect.ValueOf(obj))
	return
}

// SummaryItem : The result of a scan summeries.
type SummaryItem struct {
	// The ID of the scan.
	ScanID *string `json:"scan_id,omitempty"`

	// The name of the scan.
	ScanName *string `json:"scan_name,omitempty"`

	// The ID of the scan.
	ScopeID *string `json:"scope_id,omitempty"`

	// The name of the scope.
	ScopeName *string `json:"scope_name,omitempty"`

	// The entity that ran the report.
	ReportRunBy *string `json:"report_run_by,omitempty"`

	// The date and time the scan was run.
	StartedTime *strfmt.DateTime `json:"started_time,omitempty"`

	// The date and time the scan completed.
	EndTime *strfmt.DateTime `json:"end_time,omitempty"`

	// The status of the collector as it completes a scan.
	Status *string `json:"status,omitempty"`

	// The result of a profile.
	Profile *ProfileResult `json:"profile,omitempty"`

	// The result of a group profile.
	GroupProfiles *GroupProfileResult `json:"group_profiles,omitempty"`
}

// Constants associated with the SummaryItem.Status property.
// The status of the collector as it completes a scan.
const (
	SummaryItemStatusAbortTaskRequestCompletedConst       = "abort_task_request_completed"
	SummaryItemStatusAbortTaskRequestFailedConst          = "abort_task_request_failed"
	SummaryItemStatusAbortTaskRequestReceivedConst        = "abort_task_request_received"
	SummaryItemStatusControllerAbortedConst               = "controller_aborted"
	SummaryItemStatusDiscoveryCompletedConst              = "discovery_completed"
	SummaryItemStatusDiscoveryInProgressConst             = "discovery_in_progress"
	SummaryItemStatusDiscoveryResultPostedNoErrorConst    = "discovery_result_posted_no_error"
	SummaryItemStatusDiscoveryResultPostedWithErrorConst  = "discovery_result_posted_with_error"
	SummaryItemStatusDiscoveryStartedConst                = "discovery_started"
	SummaryItemStatusErrorInAbortTaskRequestConst         = "error_in_abort_task_request"
	SummaryItemStatusErrorInDiscoveryConst                = "error_in_discovery"
	SummaryItemStatusErrorInFactCollectionConst           = "error_in_fact_collection"
	SummaryItemStatusErrorInFactValidationConst           = "error_in_fact_validation"
	SummaryItemStatusErrorInInventoryConst                = "error_in_inventory"
	SummaryItemStatusErrorInRemediationConst              = "error_in_remediation"
	SummaryItemStatusErrorInValidationConst               = "error_in_validation"
	SummaryItemStatusFactCollectionCompletedConst         = "fact_collection_completed"
	SummaryItemStatusFactCollectionInProgressConst        = "fact_collection_in_progress"
	SummaryItemStatusFactCollectionStartedConst           = "fact_collection_started"
	SummaryItemStatusFactValidationCompletedConst         = "fact_validation_completed"
	SummaryItemStatusFactValidationInProgressConst        = "fact_validation_in_progress"
	SummaryItemStatusFactValidationStartedConst           = "fact_validation_started"
	SummaryItemStatusGatewayAbortedConst                  = "gateway_aborted"
	SummaryItemStatusInventoryCompletedConst              = "inventory_completed"
	SummaryItemStatusInventoryCompletedWithErrorConst     = "inventory_completed_with_error"
	SummaryItemStatusInventoryInProgressConst             = "inventory_in_progress"
	SummaryItemStatusInventoryStartedConst                = "inventory_started"
	SummaryItemStatusNotAcceptedConst                     = "not_accepted"
	SummaryItemStatusPendingConst                         = "pending"
	SummaryItemStatusRemediationCompletedConst            = "remediation_completed"
	SummaryItemStatusRemediationInProgressConst           = "remediation_in_progress"
	SummaryItemStatusRemediationStartedConst              = "remediation_started"
	SummaryItemStatusSentToCollectorConst                 = "sent_to_collector"
	SummaryItemStatusUserAbortedConst                     = "user_aborted"
	SummaryItemStatusValidationCompletedConst             = "validation_completed"
	SummaryItemStatusValidationInProgressConst            = "validation_in_progress"
	SummaryItemStatusValidationResultPostedNoErrorConst   = "validation_result_posted_no_error"
	SummaryItemStatusValidationResultPostedWithErrorConst = "validation_result_posted_with_error"
	SummaryItemStatusValidationStartedConst               = "validation_started"
	SummaryItemStatusWaitingForRefineConst                = "waiting_for_refine"
)

// UnmarshalSummaryItem unmarshals an instance of SummaryItem from the specified map of raw messages.
func UnmarshalSummaryItem(m map[string]json.RawMessage, result interface{}) (err error) {
	obj := new(SummaryItem)
	err = core.UnmarshalPrimitive(m, "scan_id", &obj.ScanID)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "scan_name", &obj.ScanName)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "scope_id", &obj.ScopeID)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "scope_name", &obj.ScopeName)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "report_run_by", &obj.ReportRunBy)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "started_time", &obj.StartedTime)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "end_time", &obj.EndTime)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "status", &obj.Status)
	if err != nil {
		return
	}
	err = core.UnmarshalModel(m, "profile", &obj.Profile, UnmarshalProfileResult)
	if err != nil {
		return
	}
	err = core.UnmarshalModel(m, "group_profiles", &obj.GroupProfiles, UnmarshalGroupProfileResult)
	if err != nil {
		return
	}
	reflect.ValueOf(result).Elem().Set(reflect.ValueOf(obj))
	return
}

// TaniumComplianceFindings : loren ipsum.
type TaniumComplianceFindings struct {
	// loren ipsum.
	CheckID *string `json:"Check ID,omitempty"`

	// loren ipsum.
	State *string `json:"State,omitempty"`

	// loren ipsum.
	RuleID *string `json:"Rule ID,omitempty"`
}

// UnmarshalTaniumComplianceFindings unmarshals an instance of TaniumComplianceFindings from the specified map of raw messages.
func UnmarshalTaniumComplianceFindings(m map[string]json.RawMessage, result interface{}) (err error) {
	obj := new(TaniumComplianceFindings)
	err = core.UnmarshalPrimitive(m, "Check ID", &obj.CheckID)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "State", &obj.State)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "Rule ID", &obj.RuleID)
	if err != nil {
		return
	}
	reflect.ValueOf(result).Elem().Set(reflect.ValueOf(obj))
	return
}

// ValidateResultsOptions : The ValidateResults options.
type ValidateResultsOptions struct {
	// The uuid of the scope used for Tanium integration.
	ScopeUUID *string `validate:"required,ne="`

	// The type of result used for Tanium integration.
	ResultType *string `validate:"required"`

	// loren ipsum.
	ComputerName *string

	// loren ipsum.
	TaniumClientIPAddress *string

	// loren ipsum.
	IPAddress []string

	// loren ipsum.
	ComplyComplianceFindings []TaniumComplianceFindings

	// loren ipsum.
	Count *string

	// The unique identifier that is used to trace an entire request. If you omit this field, the service generates and
	// sends a transaction ID as a response header of the request.
	TransactionID *string

	// Allows users to set headers on API requests
	Headers map[string]string
}

// NewValidateResultsOptions : Instantiate ValidateResultsOptions
func (*PostureManagementV1) NewValidateResultsOptions(scopeUUID string, resultType string) *ValidateResultsOptions {
	return &ValidateResultsOptions{
		ScopeUUID:  core.StringPtr(scopeUUID),
		ResultType: core.StringPtr(resultType),
	}
}

// SetScopeUUID : Allow user to set ScopeUUID
func (_options *ValidateResultsOptions) SetScopeUUID(scopeUUID string) *ValidateResultsOptions {
	_options.ScopeUUID = core.StringPtr(scopeUUID)
	return _options
}

// SetResultType : Allow user to set ResultType
func (_options *ValidateResultsOptions) SetResultType(resultType string) *ValidateResultsOptions {
	_options.ResultType = core.StringPtr(resultType)
	return _options
}

// SetComputerName : Allow user to set ComputerName
func (_options *ValidateResultsOptions) SetComputerName(computerName string) *ValidateResultsOptions {
	_options.ComputerName = core.StringPtr(computerName)
	return _options
}

// SetTaniumClientIPAddress : Allow user to set TaniumClientIPAddress
func (_options *ValidateResultsOptions) SetTaniumClientIPAddress(taniumClientIPAddress string) *ValidateResultsOptions {
	_options.TaniumClientIPAddress = core.StringPtr(taniumClientIPAddress)
	return _options
}

// SetIPAddress : Allow user to set IPAddress
func (_options *ValidateResultsOptions) SetIPAddress(ipAddress []string) *ValidateResultsOptions {
	_options.IPAddress = ipAddress
	return _options
}

// SetComplyComplianceFindings : Allow user to set ComplyComplianceFindings
func (_options *ValidateResultsOptions) SetComplyComplianceFindings(complyComplianceFindings []TaniumComplianceFindings) *ValidateResultsOptions {
	_options.ComplyComplianceFindings = complyComplianceFindings
	return _options
}

// SetCount : Allow user to set Count
func (_options *ValidateResultsOptions) SetCount(count string) *ValidateResultsOptions {
	_options.Count = core.StringPtr(count)
	return _options
}

// SetTransactionID : Allow user to set TransactionID
func (_options *ValidateResultsOptions) SetTransactionID(transactionID string) *ValidateResultsOptions {
	_options.TransactionID = core.StringPtr(transactionID)
	return _options
}

// SetHeaders : Allow user to set Headers
func (options *ValidateResultsOptions) SetHeaders(param map[string]string) *ValidateResultsOptions {
	options.Headers = param
	return options
}
