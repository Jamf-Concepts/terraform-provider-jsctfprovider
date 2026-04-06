// Copyright 2025, Jamf Software LLC.
package groupedgws

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"

	"jsctfprovider/internal/auth"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

// GroupedGateway represents a virtual VPN route (grouped gateway) from the API
type GroupedGateway struct {
	ID                 string   `json:"id"`
	Name               string   `json:"name"`
	Shared             bool     `json:"shared"`
	CustomerIds        []string `json:"customerIds"`
	RouteIds           []string `json:"routeIds"`
	RecoveryDelayInSec int      `json:"recoveryDelayInSec"`
	RoutingStrategy    string   `json:"routingStrategy"`
}

func DataSourceGroupedGWs() *schema.Resource {
	return &schema.Resource{
		ReadContext: dataSourceGroupedGWsRead,

		Schema: map[string]*schema.Schema{
			"name": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "The name of the grouped gateway",
			},
			"id": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "The unique identifier of the grouped gateway",
			},
			"shared": {
				Type:        schema.TypeBool,
				Computed:    true,
				Description: "Whether the grouped gateway is shared",
			},
			"route_ids": {
				Type:        schema.TypeList,
				Computed:    true,
				Elem:        &schema.Schema{Type: schema.TypeString},
				Description: "List of route IDs that make up this grouped gateway",
			},
			"recovery_delay_seconds": {
				Type:        schema.TypeInt,
				Computed:    true,
				Description: "Recovery delay in seconds before failing back to primary route",
			},
			"routing_strategy": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "The routing strategy (e.g., NEAREST)",
			},
		},
	}
}

func dataSourceGroupedGWsRead(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	req, err := http.NewRequest("GET", "https://radar.wandera.com/gate/traffic-routing-service/v1/virtual-vpn-routes", nil)
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
		return diag.FromErr(fmt.Errorf("failed to read grouped gateways: %s - %s", resp.Status, string(body)))
	}

	var gateways []GroupedGateway
	if err := json.Unmarshal(body, &gateways); err != nil {
		return diag.FromErr(fmt.Errorf("failed to parse response: %v", err))
	}

	searchName := d.Get("name").(string)
	for _, gw := range gateways {
		if strings.EqualFold(gw.Name, searchName) {
			d.SetId(gw.ID)
			d.Set("name", gw.Name)
			d.Set("shared", gw.Shared)
			d.Set("route_ids", gw.RouteIds)
			d.Set("recovery_delay_seconds", gw.RecoveryDelayInSec)
			d.Set("routing_strategy", gw.RoutingStrategy)
			return nil
		}
	}

	return diag.FromErr(fmt.Errorf("grouped gateway not found: %s", searchName))
}
