// Copyright 2025, Jamf Software LLC.
package google_idp

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"

	"jsctfprovider/internal/auth"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

type googleConnection struct {
	ID    string `json:"id"`
	Name  string `json:"name"`
	Type  string `json:"type"`
	State string `json:"state"`
}

type googleConsentResponse struct {
	ConsentURL string `json:"consentUrl"`
}

// ResourceGoogleIdp returns the schema.Resource for jsc_google_idp.
// This resource manages Google Workspace identity provider connections
// in Jamf Security Cloud (RADAR).
func ResourceGoogleIdp() *schema.Resource {
	return &schema.Resource{
		Create: resourceGoogleIdpCreate,
		Read:   resourceGoogleIdpRead,
		Update: resourceGoogleIdpUpdate,
		Delete: resourceGoogleIdpDelete,

		Importer: &schema.ResourceImporter{
			StateContext: schema.ImportStatePassthroughContext,
		},

		Schema: map[string]*schema.Schema{
			"name": {
				Type:        schema.TypeString,
				Required:    true,
				ForceNew:    true,
				Description: "Display name for the Google Workspace IdP connection.",
			},
			"state": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "Current state of the IdP connection. INITIAL until Google OAuth consent is completed, then APPROVED.",
			},
			"consent_url": {
				Type:        schema.TypeString,
				Computed:    true,
				Sensitive:   true,
				Description: "Google OAuth consent URL generated after connection creation. An administrator must visit this URL in a browser to authorize RADAR access to Google Workspace directory (groups and users).",
			},
		},
	}
}

func resourceGoogleIdpCreate(d *schema.ResourceData, m interface{}) error {
	// Step 1: Create the Google IdP connection
	payload, err := json.Marshal(map[string]string{
		"type": "GOOGLE",
		"name": d.Get("name").(string),
	})
	if err != nil {
		return fmt.Errorf("failed to marshal jsc_google_idp payload: %v", err)
	}

	req, err := http.NewRequest("POST", "https://radar.wandera.com/gate/identity-service/v1/connections", bytes.NewBuffer(payload))
	if err != nil {
		return fmt.Errorf("failed to build jsc_google_idp create request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := auth.MakeRequest(req)
	if err != nil {
		return fmt.Errorf("jsc_google_idp create request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("failed to create jsc_google_idp connection: %s - %s", resp.Status, string(body))
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read jsc_google_idp create response: %v", err)
	}

	var connection googleConnection
	if err := json.Unmarshal(body, &connection); err != nil {
		return fmt.Errorf("failed to parse jsc_google_idp create response: %v", err)
	}

	if connection.ID == "" {
		return fmt.Errorf("jsc_google_idp was created but API returned an empty ID")
	}

	d.SetId(connection.ID)
	d.Set("state", connection.State)

	// Step 2: Trigger the consent transaction to generate the OAuth URL.
	// The admin must visit this URL to authorize RADAR access to Google Workspace.
	// Required scopes: admin.directory.group.readonly, admin.directory.user.readonly
	consentReq, err := http.NewRequest("POST",
		fmt.Sprintf("https://radar.wandera.com/gate/identity-service/v1/connections/%s/consent-transactions", connection.ID),
		bytes.NewBuffer([]byte("{}")))
	if err != nil {
		return fmt.Errorf("failed to build consent transaction request: %v", err)
	}
	consentReq.Header.Set("Content-Type", "application/json")

	consentResp, err := auth.MakeRequest(consentReq)
	if err != nil {
		return fmt.Errorf("consent transaction request failed: %v", err)
	}
	defer consentResp.Body.Close()

	if consentResp.StatusCode != http.StatusOK && consentResp.StatusCode != http.StatusCreated {
		// Consent transaction might not be required for Google (unlike Entra).
		// If this fails, just log and continue - the connection was created successfully.
		consentBody, _ := io.ReadAll(consentResp.Body)
		log.Printf("Warning: consent transaction returned %s: %s\n", consentResp.Status, string(consentBody))
		return nil
	}

	consentBody, err := io.ReadAll(consentResp.Body)
	if err != nil {
		return fmt.Errorf("failed to read consent transaction response: %v", err)
	}

	var consentResult googleConsentResponse
	if err := json.Unmarshal(consentBody, &consentResult); err != nil {
		// If parsing fails, the consent flow might work differently for Google
		log.Printf("Warning: could not parse consent URL: %v\n", err)
		return nil
	}

	// Store the consent URL so the admin can retrieve it and complete the OAuth flow
	if consentResult.ConsentURL != "" {
		d.Set("consent_url", consentResult.ConsentURL)
	}

	return nil
}

func resourceGoogleIdpRead(d *schema.ResourceData, m interface{}) error {
	// No single-resource GET endpoint - must filter the connections list by ID
	req, err := http.NewRequest("GET", "https://radar.wandera.com/gate/identity-service/v1/connections", nil)
	if err != nil {
		return fmt.Errorf("failed to build jsc_google_idp read request: %v", err)
	}

	resp, err := auth.MakeRequest(req)
	if err != nil {
		return fmt.Errorf("jsc_google_idp read request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("failed to list IdP connections: %s", resp.Status)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read jsc_google_idp list response: %v", err)
	}

	var connections []googleConnection
	if err := json.Unmarshal(body, &connections); err != nil {
		return fmt.Errorf("failed to parse jsc_google_idp list response: %v", err)
	}

	for _, c := range connections {
		// Match by ID and verify type is GOOGLE (defensive check)
		if c.ID == d.Id() && c.Type == "GOOGLE" {
			d.Set("name", c.Name)
			d.Set("state", c.State)
			// Clear the consent URL once consent is complete
			if c.State == "APPROVED" {
				d.Set("consent_url", "")
			}
			return nil
		}
	}

	// Not found in list - resource has been deleted outside Terraform
	d.SetId("")
	return nil
}

func resourceGoogleIdpUpdate(d *schema.ResourceData, m interface{}) error {
	// API doesn't support PATCH - delete and recreate
	if err := resourceGoogleIdpDelete(d, m); err != nil {
		return err
	}
	return resourceGoogleIdpCreate(d, m)
}

func resourceGoogleIdpDelete(d *schema.ResourceData, m interface{}) error {
	req, err := http.NewRequest("DELETE",
		fmt.Sprintf("https://radar.wandera.com/gate/identity-service/v1/connections/%s", d.Id()),
		nil)
	if err != nil {
		return fmt.Errorf("failed to build jsc_google_idp delete request: %v", err)
	}

	resp, err := auth.MakeRequest(req)
	if err != nil {
		return fmt.Errorf("jsc_google_idp delete request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		return fmt.Errorf("failed to delete jsc_google_idp: %s", resp.Status)
	}

	d.SetId("")
	return nil
}
