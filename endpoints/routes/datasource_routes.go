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

// define type of route - don't use much but nice to keep for future use
type Deployment struct {
	ID            string `json:"id"`
	RouteID       string `json:"routeId"`
	Datacenter    string `json:"datacenter"`
	Enabled       bool   `json:"enabled"`
	InfraSpecHash string `json:"infraSpecHash"`
	Components    struct {
		VpnRouter struct {
			Deployment struct {
				PublicNodes struct {
					Enabled bool `json:"enabled"`
				} `json:"deployment"`
			} `json:"vpnRouter"`
		} `json:"vpnRouter"`
		VpnLoadBalancer struct {
			Deployment []interface{} `json:"deployment"`
		} `json:"vpnLoadBalancer"`
	} `json:"components"`
	Status struct {
		ID            string `json:"id"`
		RouteID       string `json:"routeId"`
		Datacenter    string `json:"datacenter"`
		Status        string `json:"status"`
		InfraStatus   string `json:"infraStatus"`
		InfraSpecHash string `json:"infraSpecHash"`
		TimestampInMs int64  `json:"timestampInMs"`
	} `json:"status"`
	CreatedAtInMs int64 `json:"createdAtInMs"`
	UpdatedAtInMs int64 `json:"updatedAtInMs"`
}
type IP struct {
	ID          string       `json:"id"`
	Name        string       `json:"name"`
	Shared      bool         `json:"shared"`
	Deployments []Deployment `json:"deployments"`
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
	//routeName := d.Get("name").(string)

	d.Set("routeid", "aaZZ")

	req, err := http.NewRequest("GET", ("https://radar.wandera.com/api/gateways/vpn-routes?view=deployments_with_status&"), nil)
	if err != nil {
		return diag.FromErr(fmt.Errorf("error converting making http request body"))
	}
	resp, err := auth.MakeRequest((req))

	if err != nil {
		return diag.FromErr(err)
	}
	defer resp.Body.Close()

	// Check the response status code
	if resp.StatusCode != http.StatusOK {
		return diag.FromErr(fmt.Errorf("failed to read routes info: %s", resp.Status))
	}

	// Read the response body
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return diag.FromErr(fmt.Errorf("error making parsing body response"))
	}

	// Parse the response JSON if needed
	// (this depends on the structure of the API response)
	fmt.Println(string(body))
	// Parse the response JSON

	var response []IP
	err = json.Unmarshal(body, &response)
	if err != nil {
		return diag.FromErr(err)
	}

	// Find id from the first instance where name contains "the provided name"

	for _, ip := range response {
		if strings.Contains(ip.Name, d.Get("name").(string)) {
			d.SetId(ip.ID)
			d.Set("shared", ip.Shared)
			d.Set("name", ip.Name)
			d.Set("datacenter", ip.Deployments[0].Datacenter)
			break
		}
	}

	return nil
}
