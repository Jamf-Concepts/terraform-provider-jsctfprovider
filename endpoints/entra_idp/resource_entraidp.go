// Copyright 2025, Jamf Software LLC.
package entra_idp

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"

	"jsctfprovider/internal/auth"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

type entraConnection struct {
	ID    string `json:"id"`
	Name  string `json:"name"`
	Type  string `json:"type"`
	State string `json:"state"`
}

type entraConsentResponse struct {
	ConsentURL string `json:"consentUrl"`
}

// ResourceEntraIdp returns the schema.Resource for jsc_entra_idp.
func ResourceEntraIdp() *schema.Resource {
	return &schema.Resource{
		Create: resourceEntraIdpCreate,
		Read:   resourceEntraIdpRead,
		Update: resourceEntraIdpUpdate,
		Delete: resourceEntraIdpDelete,

		Schema: map[string]*schema.Schema{
			"name": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Display name for the Entra IdP connection.",
			},
			"state": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "Current state of the IdP connection. INITIAL until Microsoft OAuth consent is completed, then APPROVED.",
			},
			"consent_url": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "Microsoft OAuth consent URL generated after connection creation. Visit this URL in a browser to complete IdP setup.",
			},
		},
	}
}

func resourceEntraIdpCreate(d *schema.ResourceData, m interface{}) error {
	// Step 1: Create the Entra connection
	payload, err := json.Marshal(map[string]string{
		"type": "AZURE_END_USER",
		"name": d.Get("name").(string),
	})
	if err != nil {
		return fmt.Errorf("failed to marshal jsc_entra_idp payload: %v", err)
	}

	req, err := http.NewRequest("POST", "https://radar.wandera.com/gate/identity-service/v1/connections", bytes.NewBuffer(payload))
	if err != nil {
		return fmt.Errorf("failed to build jsc_entra_idp create request: %v", err)
	}

	resp, err := auth.MakeRequest(req)
	if err != nil {
		return fmt.Errorf("jsc_entra_idp create request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		return fmt.Errorf("failed to create jsc_entra_idp connection: %s", resp.Status)
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read jsc_entra_idp create response: %v", err)
	}

	var connection entraConnection
	if err := json.Unmarshal(body, &connection); err != nil {
		return fmt.Errorf("failed to parse jsc_entra_idp create response: %v", err)
	}

	if connection.ID == "" {
		return fmt.Errorf("jsc_entra_idp was created but API returned an empty ID")
	}

	d.SetId(connection.ID)

	// Step 2: Trigger the consent transaction to generate the OAuth URL.
	// The URL is printed to the console for the admin to complete manually.
	// It is NOT stored in Terraform state to avoid persisting OAuth tokens.
	consentReq, err := http.NewRequest("POST",
		fmt.Sprintf("https://radar.wandera.com/gate/identity-service/v1/connections/%s/consent-transactions", connection.ID),
		bytes.NewBuffer([]byte("{}")))
	if err != nil {
		return fmt.Errorf("failed to build consent transaction request: %v", err)
	}

	consentResp, err := auth.MakeRequest(consentReq)
	if err != nil {
		return fmt.Errorf("consent transaction request failed: %v", err)
	}
	defer consentResp.Body.Close()

	if consentResp.StatusCode != http.StatusOK && consentResp.StatusCode != http.StatusCreated {
		return fmt.Errorf("failed to create consent transaction: %s", consentResp.Status)
	}

	consentBody, err := ioutil.ReadAll(consentResp.Body)
	if err != nil {
		return fmt.Errorf("failed to read consent transaction response: %v", err)
	}

	var consentResult entraConsentResponse
	if err := json.Unmarshal(consentBody, &consentResult); err != nil {
		return fmt.Errorf("failed to parse consent transaction response: %v", err)
	}

	// Store the consent URL so the admin can retrieve it and complete the OAuth
	// consent flow. Cleared automatically by Read once state reaches APPROVED.
	d.Set("consent_url", consentResult.ConsentURL)

	return nil
}

func resourceEntraIdpRead(d *schema.ResourceData, m interface{}) error {
	// No single-resource GET — must filter the connections list by ID.
	req, err := http.NewRequest("GET", "https://radar.wandera.com/gate/identity-service/v1/connections", nil)
	if err != nil {
		return fmt.Errorf("failed to build jsc_entra_idp read request: %v", err)
	}

	resp, err := auth.MakeRequest(req)
	if err != nil {
		return fmt.Errorf("jsc_entra_idp read request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("failed to list IdP connections: %s", resp.Status)
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read jsc_entra_idp list response: %v", err)
	}

	var connections []entraConnection
	if err := json.Unmarshal(body, &connections); err != nil {
		return fmt.Errorf("failed to parse jsc_entra_idp list response: %v", err)
	}

	for _, c := range connections {
		if c.ID == d.Id() {
			d.Set("name", c.Name)
			d.Set("state", c.State)
			// Clear the consent URL once consent is complete — it is only needed
			// during the INITIAL/PENDING window and should not persist in state.
			if c.State == "APPROVED" {
				d.Set("consent_url", "")
			}
			return nil
		}
	}

	// Not found in list — resource has been deleted outside Terraform
	d.SetId("")
	return nil
}

func resourceEntraIdpUpdate(d *schema.ResourceData, m interface{}) error {
	if err := resourceEntraIdpDelete(d, m); err != nil {
		return err
	}
	return resourceEntraIdpCreate(d, m)
}

func resourceEntraIdpDelete(d *schema.ResourceData, m interface{}) error {
	req, err := http.NewRequest("DELETE",
		fmt.Sprintf("https://radar.wandera.com/gate/identity-service/v1/connections/%s", d.Id()),
		nil)
	if err != nil {
		return fmt.Errorf("failed to build jsc_entra_idp delete request: %v", err)
	}

	resp, err := auth.MakeRequest(req)
	if err != nil {
		return fmt.Errorf("jsc_entra_idp delete request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		return fmt.Errorf("failed to delete jsc_entra_idp: %s", resp.Status)
	}

	d.SetId("")
	return nil
}
