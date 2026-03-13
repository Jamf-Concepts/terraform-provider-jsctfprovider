// Copyright 2025, Jamf Software LLC.
package ztna

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"

	"jsctfprovider/internal/auth"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

// Define the schema for the ZTNA resource
func Resourceztna() *schema.Resource {
	return &schema.Resource{
		Create: resourceztnaCreate,
		Read:   resourceztnaRead,
		Update: resourceztnaUpdate,
		Delete: resourceztnaDelete,

		Schema: map[string]*schema.Schema{
			"name": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Friendly name of ZTNA Access Policy.",
			},
			"type": {
				Type:        schema.TypeString,
				Optional:    true,
				Default:     "ENTERPRISE",
				Description: "Type of ZTNA Access Policy. ENTERPRISE or SAAS.",
			},
			"routeid": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "The routeid required for egress. Can be obtained from jsc_routes datasource.",
			},
			"hostnames": {
				Type:        schema.TypeList,
				Elem:        &schema.Schema{Type: schema.TypeString},
				Required:    true,
				Description: "Hostnames that this ZTNA Access Policy will capture.",
			},
		},
	}
}

// Define the create function for the ZTNA resource
func resourceztnaCreate(d *schema.ResourceData, m interface{}) error {
	hostnames := d.Get("hostnames").([]interface{})
	var hostnamesStrings []string
	for _, h := range hostnames {
		hostnamesStrings = append(hostnamesStrings, h.(string))
	}

	app := map[string]interface{}{
		"name":         d.Get("name").(string),
		"type":         d.Get("type").(string),
		"categoryName": "Uncategorized",
		"hostnames":    hostnamesStrings,
		"bareIps":      []string{},
		"routing": map[string]interface{}{
			"type":                "CUSTOM",
			"routeId":             d.Get("routeid").(string),
			"dnsIpResolutionType": "IPv6",
		},
		"groupOverrides": map[string]interface{}{
			"routingOverrides": []interface{}{},
		},
		"assignments": map[string]interface{}{
			"inclusions": map[string]interface{}{
				"allUsers": true,
				"groups":   []interface{}{},
			},
		},
		"security": map[string]interface{}{
			"riskControls": map[string]interface{}{
				"enabled":              false,
				"levelThreshold":       "HIGH",
				"notificationsEnabled": true,
			},
			"dohIntegration": map[string]interface{}{
				"blocking":             false,
				"notificationsEnabled": true,
			},
			"deviceManagementBasedAccess": map[string]interface{}{
				"enabled":              false,
				"notificationsEnabled": true,
			},
		},
	}

	payload, err := json.Marshal(app)
	if err != nil {
		return fmt.Errorf("failed to marshal ZTNA app payload: %v", err)
	}

	req, err := http.NewRequest("POST", "https://radar.wandera.com/gate/traffic-routing-service/v1/apps", bytes.NewBuffer(payload))
	if err != nil {
		return fmt.Errorf("failed to create HTTP request: %v", err)
	}

	resp, err := auth.MakeRequest(req)
	if err != nil {
		return fmt.Errorf("failed to execute request: %v", err)
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read response body: %v", err)
	}

	if resp.StatusCode != http.StatusCreated {
		return fmt.Errorf("failed to create ZTNA app: %s - %s", resp.Status, string(body))
	}

	var response struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(body, &response); err != nil {
		return fmt.Errorf("failed to parse response: %v", err)
	}

	d.SetId(response.ID)

	return nil
}

// Define the read function for the ZTNA resource
func resourceztnaRead(d *schema.ResourceData, m interface{}) error {
	req, err := http.NewRequest("GET", fmt.Sprintf("https://radar.wandera.com/gate/traffic-routing-service/v1/apps/%s", d.Id()), nil)
	if err != nil {
		return fmt.Errorf("failed to create HTTP request: %v", err)
	}

	resp, err := auth.MakeRequest(req)
	if err != nil {
		return fmt.Errorf("failed to execute request: %v", err)
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read response body: %v", err)
	}

	if resp.StatusCode == http.StatusNotFound {
		d.SetId("")
		return nil
	}

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("failed to read ZTNA app: %s - %s", resp.Status, string(body))
	}

	var app struct {
		ID        string   `json:"id"`
		Name      string   `json:"name"`
		Type      string   `json:"type"`
		Hostnames []string `json:"hostnames"`
		Routing   struct {
			RouteID string `json:"routeId"`
		} `json:"routing"`
	}
	if err := json.Unmarshal(body, &app); err != nil {
		return fmt.Errorf("failed to parse response: %v", err)
	}

	d.Set("name", app.Name)
	d.Set("type", app.Type)
	d.Set("hostnames", app.Hostnames)
	d.Set("routeid", app.Routing.RouteID)

	return nil
}

// Define the update function for the ZTNA resource
func resourceztnaUpdate(d *schema.ResourceData, m interface{}) error {
	hostnames := d.Get("hostnames").([]interface{})
	var hostnamesStrings []string
	for _, h := range hostnames {
		hostnamesStrings = append(hostnamesStrings, h.(string))
	}

	app := map[string]interface{}{
		"id":           d.Id(),
		"name":         d.Get("name").(string),
		"type":         d.Get("type").(string),
		"categoryName": "Uncategorized",
		"hostnames":    hostnamesStrings,
		"bareIps":      []string{},
		"routing": map[string]interface{}{
			"type":                "CUSTOM",
			"routeId":             d.Get("routeid").(string),
			"dnsIpResolutionType": "IPv6",
		},
		"groupOverrides": map[string]interface{}{
			"routingOverrides": []interface{}{},
		},
		"assignments": map[string]interface{}{
			"inclusions": map[string]interface{}{
				"allUsers": true,
				"groups":   []interface{}{},
			},
		},
		"security": map[string]interface{}{
			"riskControls": map[string]interface{}{
				"enabled":              false,
				"levelThreshold":       "HIGH",
				"notificationsEnabled": true,
			},
			"dohIntegration": map[string]interface{}{
				"blocking":             false,
				"notificationsEnabled": true,
			},
			"deviceManagementBasedAccess": map[string]interface{}{
				"enabled":              false,
				"notificationsEnabled": true,
			},
		},
	}

	payload, err := json.Marshal(app)
	if err != nil {
		return fmt.Errorf("failed to marshal ZTNA app payload: %v", err)
	}

	req, err := http.NewRequest("PUT", fmt.Sprintf("https://radar.wandera.com/gate/traffic-routing-service/v1/apps/%s", d.Id()), bytes.NewBuffer(payload))
	if err != nil {
		return fmt.Errorf("failed to create HTTP request: %v", err)
	}

	resp, err := auth.MakeRequest(req)
	if err != nil {
		return fmt.Errorf("failed to execute request: %v", err)
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read response body: %v", err)
	}

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("failed to update ZTNA app: %s - %s", resp.Status, string(body))
	}

	return resourceztnaRead(d, m)
}

// Define the delete function for the ZTNA resource
func resourceztnaDelete(d *schema.ResourceData, m interface{}) error {
	req, err := http.NewRequest("DELETE", fmt.Sprintf("https://radar.wandera.com/gate/traffic-routing-service/v1/apps/%s", d.Id()), nil)
	if err != nil {
		return fmt.Errorf("failed to create HTTP request: %v", err)
	}

	resp, err := auth.MakeRequest(req)
	if err != nil {
		return fmt.Errorf("failed to execute request: %v", err)
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read response body: %v", err)
	}

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		return fmt.Errorf("failed to delete ZTNA app: %s - %s", resp.Status, string(body))
	}

	d.SetId("")

	return nil
}
