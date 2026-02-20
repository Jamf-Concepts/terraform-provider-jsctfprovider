// Copyright 2025, Jamf Software LLC.
package physical_access

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"jsctfprovider/internal/auth"
)

// ResourceSwiftConnect returns the schema.Resource for the jsc_swiftconnect resource.
func ResourceSwiftConnect() *schema.Resource {
	return &schema.Resource{
		Create: resourceSwiftConnectCreate,
		Read:   resourceSwiftConnectRead,
		Update: resourceSwiftConnectUpdate,
		Delete: resourceSwiftConnectDelete,

		Schema: map[string]*schema.Schema{
			"base_url": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "The SwiftConnect API base URL (e.g. https://api.swiftconnect.io).",
			},
			"application_id": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "The SwiftConnect application ID.",
			},
			"origo_uuid": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "The Origo UUID provided by SwiftConnect.",
			},
			"organization_uuid": {
				Type:        schema.TypeString,
				Optional:    true,
				Default:     "",
				Description: "The SwiftConnect organization UUID. Optional.",
			},
			"risk_level_enabled": {
				Type:        schema.TypeBool,
				Optional:    true,
				Default:     false,
				Description: "Whether risk level enforcement is enabled for credential issuance.",
			},
			"risk_level_threshold": {
				Type:        schema.TypeString,
				Optional:    true,
				Default:     "HIGH",
				Description: "Risk level threshold required for credential issuance. Valid values: HIGH, MEDIUM, LOW.",
			},
		},
	}
}

func resourceSwiftConnectCreate(d *schema.ResourceData, m interface{}) error {
	payload, err := json.Marshal(map[string]interface{}{
		"baseUrl":            d.Get("base_url").(string),
		"applicationId":      d.Get("application_id").(string),
		"origoUuid":          d.Get("origo_uuid").(string),
		"organizationUuid":   d.Get("organization_uuid").(string),
		"riskLevelEnabled":   d.Get("risk_level_enabled").(bool),
		"riskLevelThreshold": d.Get("risk_level_threshold").(string),
	})
	if err != nil {
		return fmt.Errorf("failed to marshal SwiftConnect payload: %v", err)
	}

	req, err := http.NewRequest("POST", "https://radar.wandera.com/gate/physical-access-service/v1/integrations/{customerid}", bytes.NewBuffer(payload))
	if err != nil {
		return fmt.Errorf("failed to build SwiftConnect create request: %v", err)
	}

	resp, err := auth.MakeRequest(req)
	if err != nil {
		return fmt.Errorf("SwiftConnect create request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		return fmt.Errorf("failed to create SwiftConnect integration: %s", resp.Status)
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read SwiftConnect create response: %v", err)
	}

	var response struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(body, &response); err != nil {
		return fmt.Errorf("failed to parse SwiftConnect create response: %v", err)
	}

	d.SetId(response.ID)
	return nil
}

func resourceSwiftConnectRead(d *schema.ResourceData, m interface{}) error {
	req, err := http.NewRequest("GET", "https://radar.wandera.com/gate/physical-access-service/v1/integrations/{customerid}", nil)
	if err != nil {
		return fmt.Errorf("failed to build SwiftConnect read request: %v", err)
	}

	resp, err := auth.MakeRequest(req)
	if err != nil {
		return fmt.Errorf("SwiftConnect read request failed: %v", err)
	}
	defer resp.Body.Close()

	// 404 means no integration exists — tell Terraform to recreate it
	if resp.StatusCode == http.StatusNotFound {
		d.SetId("")
		return nil
	}

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("failed to read SwiftConnect integration: %s", resp.Status)
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read SwiftConnect read response: %v", err)
	}

	var response struct {
		ID                 string `json:"id"`
		BaseURL            string `json:"baseUrl"`
		ApplicationID      string `json:"applicationId"`
		OrigoUUID          string `json:"origoUuid"`
		OrganizationUUID   string `json:"organizationUuid"`
		RiskLevelEnabled   bool   `json:"riskLevelEnabled"`
		RiskLevelThreshold string `json:"riskLevelThreshold"`
	}
	if err := json.Unmarshal(body, &response); err != nil {
		return fmt.Errorf("failed to parse SwiftConnect read response: %v", err)
	}

	d.Set("base_url", response.BaseURL)
	d.Set("application_id", response.ApplicationID)
	d.Set("origo_uuid", response.OrigoUUID)
	d.Set("organization_uuid", response.OrganizationUUID)
	d.Set("risk_level_enabled", response.RiskLevelEnabled)
	d.Set("risk_level_threshold", response.RiskLevelThreshold)

	return nil
}

func resourceSwiftConnectUpdate(d *schema.ResourceData, m interface{}) error {
	if err := resourceSwiftConnectDelete(d, m); err != nil {
		return err
	}
	return resourceSwiftConnectCreate(d, m)
}

func resourceSwiftConnectDelete(d *schema.ResourceData, m interface{}) error {
	// Delete uses v2 endpoint with integration id (not customerId) — intentional API asymmetry
	req, err := http.NewRequest("DELETE", fmt.Sprintf("https://radar.wandera.com/gate/physical-access-service/v2/integrations/%s", d.Id()), nil)
	if err != nil {
		return fmt.Errorf("failed to build SwiftConnect delete request: %v", err)
	}

	resp, err := auth.MakeRequest(req)
	if err != nil {
		return fmt.Errorf("SwiftConnect delete request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		return fmt.Errorf("failed to delete SwiftConnect integration: %s", resp.Status)
	}

	d.SetId("")
	return nil
}
