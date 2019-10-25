// +skip_license_check

/*
This file contains portions of code directly taken from the 'xenolf/lego' project.
A copy of the license for this code can be found in the file named LICENSE in
this directory.
*/

// Package cis implements a DNS provider for solving the DNS-01
// challenge using IBM Cloud Internet Servcies.
package cis

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/jetstack/cert-manager/pkg/issuer/acme/dns/util"
	"k8s.io/klog"
)

// CISAPIUrl represents the API endpoint to call.
const CISAPIUrl = "https://api.cis.cloud.ibm.com/v1"

// IAMUrl represents the authentication endpoint to call.
const IAMUrl = "https://iam.cloud.ibm.com"


// DNSProvider is an implementation of the DNSProvider interface.
type DNSProvider struct {
	apikey string
	crn    string
}

// NewDNSProvider returns a DNSProvider instance configured for cis.
// Credentials must be passed in the environment variables: API_KEY and CRN
func NewDNSProvider() (*DNSProvider, error) {
	apikey := os.Getenv("IBMCLOUD_API_KEY")
	crn := os.Getenv("IBMCLOUD_CIS_CRN")
	return NewDNSProviderCredentials(apikey, crn)
}

// NewDNSProviderCredentials uses the supplied credentials to return a
// DNSProvider instance configured for IBM Cloud Internet Servcies.
func NewDNSProviderCredentials(apikey, crn string) (*DNSProvider, error) {
	if apikey == "" || crn == "" {
		return nil, fmt.Errorf("IBM Cloud credentials missing")
	}
	return &DNSProvider{
		apikey: apikey,
		crn:    crn,
	}, nil
}

// Timeout returns the timeout and interval to use when checking for DNS
// propagation. Adjusting here to cope with spikes in propagation times.
func (c *DNSProvider) Timeout() (timeout, interval time.Duration) {
	return 120 * time.Second, 2 * time.Second
}

// Present creates a TXT record to fulfil the dns-01 challenge.
func (c *DNSProvider) Present(domain, token, keyAuth string) error {
	accessToken, err := c.getAccessToken()
	if err != nil {
		return err
	}
	fqdn, txtValue, _ := util.DNS01Record(domain, keyAuth)
	zoneId, err := c.getHostedZoneId(fqdn, accessToken)
	if err != nil {
		return err
	}
	txtRecordId, err := c.findTxtRecordId(fqdn, zoneId, accessToken)
	if err != nil {
		return err
	}
	if txtRecordId == "" {
		_, err := c.createTxtRecord(fqdn, zoneId, txtValue, accessToken)
		if err != nil {
			return err
		}
	} else {
		_, err := c.updateTxtRecord(txtRecordId, fqdn, zoneId, txtValue, accessToken)
		if err != nil {
			return err
		}
	}
	return nil
}

// CleanUp removes the TXT record matching the specified parameters.
func (c *DNSProvider) CleanUp(domain, token, keyAuth string) error {
	accessToken, err := c.getAccessToken()
	if err != nil {
		return err
	}
	fqdn, _, _ := util.DNS01Record(domain, keyAuth)
	zoneId, err := c.getHostedZoneId(fqdn, accessToken)
	if err != nil {
		return err
	}
	txtRecordId, err := c.findTxtRecordId(fqdn, zoneId, accessToken)
	if err != nil {
		return err
	}
	if txtRecordId != "" {
		_, err = c.deleteTxtRecord(txtRecordId, fqdn, zoneId, accessToken)
		if err != nil {
			return err
		}
	}
	return nil
}

func (c *DNSProvider) getAccessToken() (string, error) {
	data := url.Values{}
	data.Set("grant_type", "urn:ibm:params:oauth:grant-type:apikey")
	data.Set("apikey", c.apikey)
	req, err := http.NewRequest("POST", fmt.Sprintf("%s%s", IAMUrl, "/identity/token"), strings.NewReader(data.Encode()))
	req.Header.Set("User-Agent", pkgutil.CertManagerUserAgent)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	client := http.Client{
		Timeout: 30 * time.Second,
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("Error querying IAM API -> %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNoContent {
		return "", nil
	}
	iamResponse, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("Failed to read iamResponse -> %v", err)
	}
	var tokenResponse map[string]interface{}
	err = json.Unmarshal(iamResponse, &tokenResponse)
	if err != nil {
		return "", err
	}
	accessToken := "Bearer " + tokenResponse["access_token"].(string)
	return accessToken, nil
}

// getHostedZoneId returns the managed-zone
func (c *DNSProvider) getHostedZoneId(fqdn, accessToken string) (string, error) {
	authZone, err := util.FindZoneByFqdn(fqdn, util.RecursiveNameservers)
	if err != nil {
		return "", err
	}
	uri := fmt.Sprintf("/%s/zones", url.QueryEscape(c.crn))
	result, err := c.makeCISRequest("GET", uri, nil, accessToken)
	if err != nil {
		return "", err
	}
	var cisRequestResult cisRequestResult
	json.Unmarshal(result, &cisRequestResult)
	for _, zone := range cisRequestResult.Result {
		if zone.Name == util.UnFqdn(authZone) {
			return zone.Id, nil
		}
	}
	return "", errors.New("Zone not found for fqdn")
}

func (c *DNSProvider) findTxtRecordId(fqdn, zoneId, accessToken string) (string, error) {
	uri := fmt.Sprintf("/%s/zones/%s/dns_records", url.QueryEscape(c.crn), zoneId)
	result, err := c.makeCISRequest("GET", uri, nil, accessToken)
	if err != nil {
		return "", err
	}
	var cisRequestResult cisRequestResult
	json.Unmarshal(result, &cisRequestResult)
	for _, record := range cisRequestResult.Result {
		// txt record already exists; update the existing record
		if record.Type == "TXT" && record.Name == util.UnFqdn(fqdn) {
			return record.Id, nil
		}
	}
	return "", nil
}

func (c *DNSProvider) createTxtRecord(fqdn, zoneId, txtValue, accessToken string) (*resultObject, error) {
	uri := fmt.Sprintf("/%s/zones/%s/dns_records", url.QueryEscape(c.crn), zoneId)
	body := []byte(fmt.Sprintf(`{"name": "%s", "type": "TXT", "content": "%s"}`, fqdn, txtValue))
	_, err := c.makeCISRequest("POST", uri, bytes.NewBuffer(body), accessToken)
	if err != nil {
		return nil, err
	}
	return nil, nil
}

func (c *DNSProvider) updateTxtRecord(txtRecordId, fqdn, zoneId, txtValue, accessToken string) (*resultObject, error) {
	uri := fmt.Sprintf("/%s/zones/%s/dns_records/%s", url.QueryEscape(c.crn), zoneId, txtRecordId)
	body := []byte(fmt.Sprintf(`{"name": "%s", "type": "TXT", "content": "%s"}`, fqdn, txtValue))
	_, err := c.makeCISRequest("PUT", uri, bytes.NewBuffer(body), accessToken)
	if err != nil {
		return nil, err
	}
	return nil, nil
}

func (c *DNSProvider) deleteTxtRecord(txtRecordId, fqdn, zoneId, accessToken string) (*resultObject, error) {
	uri := fmt.Sprintf("/%s/zones/%s/dns_records/%s", url.QueryEscape(c.crn), zoneId, txtRecordId)
	_, err := c.makeCISRequest("DELETE", uri, nil, accessToken)
	if err != nil {
		return nil, err
	}
	return nil, nil
}

func (c *DNSProvider) makeCISRequest(method, uri string, body io.Reader, accessToken string) ([]byte, error) {
	req, err := http.NewRequest(method, fmt.Sprintf("%s%s", CISAPIUrl, uri), body)
	req.Header.Set("X-Auth-User-Token", accessToken)
	req.Header.Set("User-Agent", pkgutil.CertManagerUserAgent)
	req.Header.Set("Content-Type", "application/json")
	client := http.Client{
		Timeout: 30 * time.Second,
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("Error querying CIS API -> %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNoContent {
		return nil, nil
	}
	if resp.StatusCode != http.StatusOK {
		responsePayload, readErr := ioutil.ReadAll(resp.Body)
		if readErr == nil {
			return responsePayload, fmt.Errorf("CIS API returned %d %s", resp.StatusCode, resp.Status)
		}
		return nil, fmt.Errorf("CIS API returned %d %s", resp.StatusCode, resp.Status)
	}
	responsePayload, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("Failed to read response payload -> %v", err)
	}
	return responsePayload, nil
}

type cisRequestResult struct {
	Result []resultObject `json:"result"`
}

type resultObject struct {
	Id   string `json:"id"`
	Name string `json:"name"`
	Type string `json:"type,omitempty"`
}
