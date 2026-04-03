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

type appTemplateResponse struct {
	ID        string   `json:"id"`
	Name      string   `json:"name"`
	Hostnames []string `json:"hostnames"`
}

// DataSourceAppTemplate returns the schema.Resource for looking up a jsc_app_template by name.
func DataSourceAppTemplate() *schema.Resource {
	return &schema.Resource{
		ReadContext: dataSourceAppTemplateRead,

		Schema: map[string]*schema.Schema{
			"name": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "The name of the SaaS app template to look up (e.g., \"Okta\", \"Atlassian Cloud\", \"ServiceNow\").",
			},
			"id": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "The unique identifier of the app template. Use as app_template_id in jsc_access_policy.",
			},
			"hostnames": {
				Type:        schema.TypeList,
				Computed:    true,
				Elem:        &schema.Schema{Type: schema.TypeString},
				Description: "List of hostnames covered by this app template.",
			},
		},
	}
}

func dataSourceAppTemplateRead(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	req, err := http.NewRequest("GET", "https://radar.wandera.com/gate/traffic-routing-service/v1/app-templates", nil)
	if err != nil {
		return diag.FromErr(fmt.Errorf("failed to build app templates request: %v", err))
	}

	resp, err := auth.MakeRequest(req)
	if err != nil {
		return diag.FromErr(fmt.Errorf("app templates request failed: %v", err))
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return diag.FromErr(fmt.Errorf("failed to list app templates: %s", resp.Status))
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return diag.FromErr(fmt.Errorf("failed to read app templates response: %v", err))
	}

	var templates []appTemplateResponse
	if err := json.Unmarshal(body, &templates); err != nil {
		return diag.FromErr(fmt.Errorf("failed to parse app templates response: %v", err))
	}

	name := d.Get("name").(string)
	for _, t := range templates {
		if t.Name == name {
			d.SetId(t.ID)
			d.Set("name", t.Name)
			d.Set("hostnames", t.Hostnames)
			return nil
		}
	}

	return diag.FromErr(fmt.Errorf("app template with name %q not found", name))
}
