// Copyright 2025, Jamf Software LLC.
package entra_idp

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"jsctfprovider/internal/auth"
)

// DataSourceEntraIdps returns all Entra IdP connections for discovery/import.
func DataSourceEntraIdps() *schema.Resource {
	return &schema.Resource{
		ReadContext: dataSourceEntraIdpsRead,

		Schema: map[string]*schema.Schema{
			"connections": {
				Type:        schema.TypeList,
				Computed:    true,
				Description: "List of all Entra IdP connections.",
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"id": {
							Type:        schema.TypeString,
							Computed:    true,
							Description: "The unique identifier (use for import).",
						},
						"name": {
							Type:        schema.TypeString,
							Computed:    true,
							Description: "Display name of the connection.",
						},
						"type": {
							Type:        schema.TypeString,
							Computed:    true,
							Description: "Connection type (e.g., AZURE_END_USER).",
						},
						"state": {
							Type:        schema.TypeString,
							Computed:    true,
							Description: "Current state (INITIAL, APPROVED, etc.).",
						},
					},
				},
			},
		},
	}
}

func dataSourceEntraIdpsRead(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	req, err := http.NewRequest("GET", "https://radar.wandera.com/gate/identity-service/v1/connections", nil)
	if err != nil {
		return diag.FromErr(fmt.Errorf("failed to build Entra IdP list request: %v", err))
	}

	resp, err := auth.MakeRequest(req)
	if err != nil {
		return diag.FromErr(fmt.Errorf("Entra IdP list request failed: %v", err))
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return diag.FromErr(fmt.Errorf("failed to list Entra IdP connections: %s", resp.Status))
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return diag.FromErr(fmt.Errorf("failed to read Entra IdP response: %v", err))
	}

	var connections []entraConnection
	if err := json.Unmarshal(body, &connections); err != nil {
		return diag.FromErr(fmt.Errorf("failed to parse Entra IdP response: %v", err))
	}

	// Filter to only AZURE_END_USER (Entra) connections
	var entraConnections []map[string]interface{}
	for _, c := range connections {
		if c.Type == "AZURE_END_USER" {
			entraConnections = append(entraConnections, map[string]interface{}{
				"id":    c.ID,
				"name":  c.Name,
				"type":  c.Type,
				"state": c.State,
			})
		}
	}

	if err := d.Set("connections", entraConnections); err != nil {
		return diag.FromErr(fmt.Errorf("failed to set connections: %v", err))
	}

	d.SetId("entra_idp_connections")
	return nil
}
