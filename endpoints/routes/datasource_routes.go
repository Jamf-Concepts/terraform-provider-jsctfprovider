// Copyright 2025, Jamf Software LLC.
package routes

import (
	//"bytes"
	//"encoding/json"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"

	"context"
	"jsctfprovider/internal/auth"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

// Route represents a VPN route from the API
type Route struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Shared      bool   `json:"shared"`
	Deployments []struct {
		Datacenter string `json:"datacenter"`
	} `json:"deployments"`
}

func DataSourceRoutes() *schema.Resource {
	return &schema.Resource{
		ReadContext: dataSourceRoutesRead,

		Schema: map[string]*schema.Schema{
			"name": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "The name of the route",
			},
			"id": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "The unique identifier of the route datasource set from JSC",
			},
			"datacenter": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "The datacenter of the route",
			},
			"shared": {
				Type:        schema.TypeBool,
				Computed:    true,
				Description: "If the route is shared or not",
			},
		},
	}
}

// Define the read function for routes
func dataSourceRoutesRead(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	req, err := http.NewRequest("GET", "https://radar.wandera.com/gate/traffic-routing-service/v2/vpn-routes?view=deployments", nil)
	if err != nil {
		return diag.FromErr(fmt.Errorf("failed to create HTTP request: %v", err))
	}

	resp, err := auth.MakeRequest(req)
	if err != nil {
		return diag.FromErr(fmt.Errorf("failed to execute request: %v", err))
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return diag.FromErr(fmt.Errorf("failed to read response body: %v", err))
	}

	if resp.StatusCode != http.StatusOK {
		return diag.FromErr(fmt.Errorf("failed to read routes info: %s - %s", resp.Status, string(body)))
	}

	var routes []Route
	if err := json.Unmarshal(body, &routes); err != nil {
		return diag.FromErr(fmt.Errorf("failed to parse response: %v", err))
	}

	routeName := d.Get("name").(string)
	found := false

	for _, route := range routes {
		if strings.Contains(route.Name, routeName) {
			d.SetId(route.ID)
			d.Set("shared", route.Shared)
			d.Set("name", route.Name)
			if len(route.Deployments) > 0 {
				d.Set("datacenter", route.Deployments[0].Datacenter)
			}
			found = true
			break
		}
	}

	if !found {
		return diag.FromErr(fmt.Errorf("no route found matching name: %s", routeName))
	}

	return nil
}
