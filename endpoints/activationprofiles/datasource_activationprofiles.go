// Copyright 2025, Jamf Software LLC.
package activationprofiles

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

// apListItem represents an activation profile in the list response
type apListItem struct {
	Code string `json:"code"`
	Name string `json:"name"`
}

// apListResponse wraps the API response
type apListResponse struct {
	Links []apListItem `json:"links"`
}

// DataSourceActivationProfiles returns all activation profiles for discovery/import.
func DataSourceActivationProfiles() *schema.Resource {
	return &schema.Resource{
		ReadContext: dataSourceActivationProfilesRead,

		Schema: map[string]*schema.Schema{
			"profiles": {
				Type:        schema.TypeList,
				Computed:    true,
				Description: "List of all activation profiles.",
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"id": {
							Type:        schema.TypeString,
							Computed:    true,
							Description: "The unique identifier (code) - use for import.",
						},
						"name": {
							Type:        schema.TypeString,
							Computed:    true,
							Description: "The name of the activation profile.",
						},
					},
				},
			},
		},
	}
}

func dataSourceActivationProfilesRead(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	req, err := http.NewRequest("GET", "https://radar.wandera.com/gate/activation-profile-service/v1/enrollment-links", nil)
	if err != nil {
		return diag.FromErr(fmt.Errorf("failed to build activation profiles list request: %v", err))
	}

	resp, err := auth.MakeRequest(req)
	if err != nil {
		return diag.FromErr(fmt.Errorf("activation profiles list request failed: %v", err))
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return diag.FromErr(fmt.Errorf("failed to list activation profiles: %s", resp.Status))
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return diag.FromErr(fmt.Errorf("failed to read activation profiles response: %v", err))
	}

	var response apListResponse
	if err := json.Unmarshal(body, &response); err != nil {
		return diag.FromErr(fmt.Errorf("failed to parse activation profiles response: %v", err))
	}

	profileList := make([]map[string]interface{}, len(response.Links))
	for i, p := range response.Links {
		profileList[i] = map[string]interface{}{
			"id":   p.Code,
			"name": p.Name,
		}
	}

	if err := d.Set("profiles", profileList); err != nil {
		return diag.FromErr(fmt.Errorf("failed to set profiles: %v", err))
	}

	d.SetId("activation_profiles")
	return nil
}
