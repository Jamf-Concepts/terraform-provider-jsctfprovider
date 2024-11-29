package pagztnaapp

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

// Define structs to represent the JSON structure

type Inclusions struct {
	AllUsers bool     `json:"allUsers"`
	Groups   []string `json:"groups"`
}

type Assignments struct {
	Inclusions Inclusions `json:"inclusions"`
}

type Routing struct {
	Type                string `json:"type"`
	RouteId             string `json:"routeId,omitempty"`
	DnsIpResolutionType string `json:"dnsIpResolutionType,omitempty"`
}

type RiskControls struct {
	Enabled              bool   `json:"enabled"`
	LevelThreshold       string `json:"levelThreshold"`
	NotificationsEnabled bool   `json:"notificationsEnabled"`
}

type DohIntegration struct {
	Blocking             bool `json:"blocking"`
	NotificationsEnabled bool `json:"notificationsEnabled"`
}

type DeviceManagementBasedAccess struct {
	Enabled              bool `json:"enabled"`
	NotificationsEnabled bool `json:"notificationsEnabled"`
}

type Security struct {
	RiskControls                RiskControls                `json:"riskControls"`
	DohIntegration              DohIntegration              `json:"dohIntegration"`
	DeviceManagementBasedAccess DeviceManagementBasedAccess `json:"deviceManagementBasedAccess"`
}

type GroupOverrides struct {
	RoutingOverrides []interface{} `json:"routingOverrides"`
}

type ResponseItemZTNAApps struct {
	Name           string         `json:"name"`
	CategoryName   string         `json:"categoryName"`
	Hostnames      []string       `json:"hostnames"`
	BareIps        []string       `json:"bareIps"`
	Assignments    Assignments    `json:"assignments"`
	GroupOverrides GroupOverrides `json:"groupOverrides"`
	Routing        Routing        `json:"routing"`
	Security       Security       `json:"security"`
	ID             string         `json:"id"`
	AppTemplateId  string         `json:"appTemplateId"`
}

func DataSourcePAGZTNAApp() *schema.Resource {
	return &schema.Resource{
		ReadContext: dataSourcePAGZTNAAppRead,

		Schema: map[string]*schema.Schema{
			"name": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "The name of the ZTNA App",
			},
			"id": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "The unique identifier of the ZTNA App datasource set from JSC",
			},
			"hostnames": {
				Type:        schema.TypeList,
				Elem:        &schema.Schema{Type: schema.TypeString},
				Computed:    true,
				Description: "List of hostnames",
			},
			"bareips": {
				Type:        schema.TypeList,
				Elem:        &schema.Schema{Type: schema.TypeString},
				Computed:    true,
				Description: "List of bare ips",
			},
			"categoryname": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "Category Name",
			},
			"apptemplateid": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "App Template ID (if applicable)",
			},
			"routingtype": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "Routing Type",
			},
			"routingid": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "Routing ID",
			},
			"routingdnstype": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "Routing IP DNS Resolution Type",
			},
			"securityriskcontrolenabled": {
				Type:        schema.TypeBool,
				Computed:    true,
				Description: "Enable device risk security controls for ZTNA App policy",
			},
			"securityriskcontrolthreshold": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "Risk level threshold (when enabled), options of HIGH, MEDIUM, LOW",
			},
			"securityriskcontrolnotifications": {
				Type:        schema.TypeBool,
				Computed:    true,
				Description: "Enable notificatons for device risk security controls",
			},
			"securitydohintegrationblocking": {
				Type:        schema.TypeBool,
				Computed:    true,
				Description: "Enable DoH blocking for ZTNA App Policy",
			},
			"securitydohintegrationnotifications": {
				Type:        schema.TypeBool,
				Computed:    true,
				Description: "Enable DoH notifications for ZTNA App Policy",
			},
			"securitydevicemanagementbasedaccessenabled": {
				Type:        schema.TypeBool,
				Computed:    true,
				Description: "Enable deviceManagementBasedAccess for ZTNA App Policy",
			},
			"securitydevicemanagementbasedaccessnotifications": {
				Type:        schema.TypeBool,
				Computed:    true,
				Description: "Enable deviceManagementBasedAccess notifications for ZTNA App Policy",
			},
			"assignmentallusers": {
				Type:        schema.TypeBool,
				Computed:    true,
				Description: "Assign ZTNA App to all users",
			},
			"assignmentgroups": {
				Type:        schema.TypeList,
				Elem:        &schema.Schema{Type: schema.TypeString},
				Computed:    true,
				Description: "Groups to assign ZTNA App Policy to",
			},
		},
	}
}

// Define the read function for ZTNA App
func dataSourcePAGZTNAAppRead(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {

	req, err := http.NewRequest("GET", ("https://api.wandera.com/ztna/v1/apps"), nil)
	if err != nil {
		return diag.FromErr(fmt.Errorf("error converting making http request body"))
	}
	resp, err := auth.MakePAGRequest((req))

	if err != nil {
		return diag.FromErr(err)
	}
	defer resp.Body.Close()

	// Check the response status code
	if resp.StatusCode != http.StatusOK {
		return diag.FromErr(fmt.Errorf("failed to read app template info: %s", resp.Status))
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

	var response []ResponseItemZTNAApps
	err = json.Unmarshal(body, &response)
	if err != nil {
		return diag.FromErr(err)
	}

	// Find id from the first instance where name contains "the provided name"

	for _, ip := range response {
		if strings.Contains(ip.Name, d.Get("name").(string)) {
			d.SetId(ip.ID)
			d.Set("hostnames", ip.Hostnames)
			d.Set("bareips", ip.BareIps)
			d.Set("name", ip.Name)
			d.Set("categoryname", ip.CategoryName)
			d.Set("apptemplateid", ip.AppTemplateId)
			d.Set("routingtype", ip.Routing.Type)
			d.Set("routingid", ip.Routing.RouteId)
			d.Set("routingdnstype", ip.Routing.DnsIpResolutionType)
			d.Set("securityriskcontrolenabled", ip.Security.RiskControls.Enabled)
			d.Set("securityriskcontrolthreshold", ip.Security.RiskControls.LevelThreshold)
			d.Set("securityriskcontrolnotifications", ip.Security.RiskControls.NotificationsEnabled)
			d.Set("securitydohintegrationblocking", ip.Security.DohIntegration.Blocking)
			d.Set("securitydohintegrationnotifications", ip.Security.DohIntegration.NotificationsEnabled)
			d.Set("securitydevicemanagementbasedaccessenabled", ip.Security.DeviceManagementBasedAccess.Enabled)
			d.Set("securitydevicemanagementbasedaccessnotifications", ip.Security.DeviceManagementBasedAccess.NotificationsEnabled)
			d.Set("assignmentallusers", ip.Assignments.Inclusions.AllUsers)
			d.Set("assignmentgroups", ip.Assignments.Inclusions.Groups)
			break
		}
	}

	return nil
}
