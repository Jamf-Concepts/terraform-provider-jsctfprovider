// Copyright 2025, Jamf Software LLC.
package ztna_app

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

// DataSourceAccessPolicies returns the schema.Resource for listing all jsc_access_policy resources.
func DataSourceAccessPolicies() *schema.Resource {
	return &schema.Resource{
		ReadContext: dataSourceAccessPoliciesRead,

		Schema: map[string]*schema.Schema{
			"policies": {
				Type:        schema.TypeList,
				Computed:    true,
				Description: "List of all access policies.",
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"id": {
							Type:        schema.TypeString,
							Computed:    true,
							Description: "The unique identifier of the access policy.",
						},
						"name": {
							Type:        schema.TypeString,
							Computed:    true,
							Description: "The name of the access policy.",
						},
						"type": {
							Type:        schema.TypeString,
							Computed:    true,
							Description: "The type of the access policy (e.g., ENTERPRISE, SAAS).",
						},
						"categoryname": {
							Type:        schema.TypeString,
							Computed:    true,
							Description: "The category name of the access policy.",
						},
					},
				},
			},
		},
	}
}

func dataSourceAccessPoliciesRead(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	req, err := http.NewRequest("GET", "https://radar.wandera.com/gate/traffic-routing-service/v1/apps", nil)
	if err != nil {
		return diag.FromErr(fmt.Errorf("failed to build access policies list request: %v", err))
	}

	resp, err := auth.MakeRequest(req)
	if err != nil {
		return diag.FromErr(fmt.Errorf("access policies list request failed: %v", err))
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return diag.FromErr(fmt.Errorf("failed to list access policies: %s", resp.Status))
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return diag.FromErr(fmt.Errorf("failed to read access policies response: %v", err))
	}

	var policies []ztnaAppResponse
	if err := json.Unmarshal(body, &policies); err != nil {
		return diag.FromErr(fmt.Errorf("failed to parse access policies response: %v", err))
	}

	policyList := make([]map[string]interface{}, len(policies))
	for i, policy := range policies {
		policyList[i] = map[string]interface{}{
			"id":           policy.ID,
			"name":         policy.Name,
			"type":         policy.Type,
			"categoryname": policy.CategoryName,
		}
	}

	if err := d.Set("policies", policyList); err != nil {
		return diag.FromErr(fmt.Errorf("failed to set policies: %v", err))
	}

	d.SetId("access_policies")
	return nil
}
