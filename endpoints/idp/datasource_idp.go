// Copyright 2025, Jamf Software LLC.
package idp

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"

	"jsctfprovider/internal/auth"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

// IdpConnection represents a single IdP connection returned by the JSC identity-service API.
type IdpConnection struct {
	ID    string `json:"id"`
	Name  string `json:"name"`
	Type  string `json:"type"`
	State string `json:"state"`
}

// IdpConnectionListResponse handles the case where the API wraps results in a "data" key.
type IdpConnectionListResponse struct {
	Data []IdpConnection `json:"data"`
}

func DataSourceIdpConnection() *schema.Resource {
	return &schema.Resource{
		ReadContext: dataSourceIdpConnectionRead,

		Schema: map[string]*schema.Schema{
			"connection_id": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "The IdP connection ID. Pass this to jsc_ap as oktaconnectionid.",
			},
			"name": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "The display name of the IdP connection.",
			},
			"type": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "The connection type, e.g. okta or entra.",
			},
			"state": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "The current state of the IdP connection.",
			},
		},
	}
}

// dataSourceIdpConnectionRead calls GET /gate/identity-service/v1/connections,
// takes the first result, and populates all computed attributes.
func dataSourceIdpConnectionRead(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	req, err := http.NewRequest("GET", "https://radar.wandera.com/gate/identity-service/v1/connections", nil)
	if err != nil {
		return diag.FromErr(fmt.Errorf("error building IdP connection request: %w", err))
	}

	resp, err := auth.MakeRequest(req)
	if err != nil {
		return diag.FromErr(fmt.Errorf("error executing IdP connection request: %w", err))
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return diag.FromErr(fmt.Errorf("failed to read IdP connections: %s", resp.Status))
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return diag.FromErr(fmt.Errorf("error reading IdP connection response body: %w", err))
	}

	// The API may return either a bare array or an object with a "data" key.
	// Attempt bare array first; fall back to the wrapped form.
	var connections []IdpConnection
	if err := json.Unmarshal(body, &connections); err != nil {
		// Try the wrapped form.
		var wrapped IdpConnectionListResponse
		if err2 := json.Unmarshal(body, &wrapped); err2 != nil {
			return diag.FromErr(fmt.Errorf("error parsing IdP connection response: %w (wrapped parse: %v)", err, err2))
		}
		connections = wrapped.Data
	}

	if len(connections) == 0 {
		return diag.FromErr(fmt.Errorf("no IdP connections found on this JSC tenant"))
	}

	first := connections[0]

	d.SetId(first.ID)

	if err := d.Set("connection_id", first.ID); err != nil {
		return diag.FromErr(fmt.Errorf("error setting connection_id: %w", err))
	}
	if err := d.Set("name", first.Name); err != nil {
		return diag.FromErr(fmt.Errorf("error setting name: %w", err))
	}
	if err := d.Set("type", first.Type); err != nil {
		return diag.FromErr(fmt.Errorf("error setting type: %w", err))
	}
	if err := d.Set("state", first.State); err != nil {
		return diag.FromErr(fmt.Errorf("error setting state: %w", err))
	}

	return nil
}
