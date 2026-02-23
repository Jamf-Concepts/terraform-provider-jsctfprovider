// Copyright 2025, Jamf Software LLC.
package ztna_app

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"jsctfprovider/internal/auth"
)

type ztnaAppInclusions struct {
	AllUsers bool     `json:"allUsers"`
	Groups   []string `json:"groups"`
}

type ztnaAppAssignments struct {
	Inclusions ztnaAppInclusions `json:"inclusions"`
}

type ztnaAppRouting struct {
	Type                string `json:"type"`
	RouteId             string `json:"routeId,omitempty"`
	DnsIpResolutionType string `json:"dnsIpResolutionType,omitempty"`
}

type ztnaAppRiskControls struct {
	Enabled              bool   `json:"enabled"`
	LevelThreshold       string `json:"levelThreshold"`
	NotificationsEnabled bool   `json:"notificationsEnabled"`
}

type ztnaAppDohIntegration struct {
	Blocking             bool `json:"blocking"`
	NotificationsEnabled bool `json:"notificationsEnabled"`
}

type ztnaAppDeviceMgmtAccess struct {
	Enabled              bool `json:"enabled"`
	NotificationsEnabled bool `json:"notificationsEnabled"`
}

type ztnaAppSecurity struct {
	RiskControls                ztnaAppRiskControls     `json:"riskControls"`
	DohIntegration              ztnaAppDohIntegration   `json:"dohIntegration"`
	DeviceManagementBasedAccess ztnaAppDeviceMgmtAccess `json:"deviceManagementBasedAccess"`
}

type ztnaAppRequest struct {
	Name         string             `json:"name"`
	Type         string             `json:"type"`
	CategoryName string             `json:"categoryName"`
	Hostnames    []string           `json:"hostnames"`
	BareIps      []string           `json:"bareIps"`
	Assignments  ztnaAppAssignments `json:"assignments"`
	Routing      ztnaAppRouting     `json:"routing"`
	Security     ztnaAppSecurity    `json:"security"`
}

type ztnaAppResponse struct {
	ID           string             `json:"id"`
	Name         string             `json:"name"`
	Type         string             `json:"type"`
	CategoryName string             `json:"categoryName"`
	Hostnames    []string           `json:"hostnames"`
	BareIps      []string           `json:"bareIps"`
	Assignments  ztnaAppAssignments `json:"assignments"`
	Routing      ztnaAppRouting     `json:"routing"`
	Security     ztnaAppSecurity    `json:"security"`
}

func toStringSlice(in []interface{}) []string {
	out := make([]string, len(in))
	for i, v := range in {
		out[i] = v.(string)
	}
	return out
}

func buildZTNAAppRequest(d *schema.ResourceData) ztnaAppRequest {
	routingdnstype := d.Get("routingdnstype").(string)
	if d.Get("routingtype").(string) == "DIRECT" {
		routingdnstype = ""
	}

	return ztnaAppRequest{
		Name:         d.Get("name").(string),
		Type:         d.Get("type").(string),
		CategoryName: d.Get("categoryname").(string),
		Hostnames:    toStringSlice(d.Get("hostnames").([]interface{})),
		BareIps:      toStringSlice(d.Get("bareips").([]interface{})),
		Assignments: ztnaAppAssignments{
			Inclusions: ztnaAppInclusions{
				AllUsers: d.Get("assignmentallusers").(bool),
				Groups:   toStringSlice(d.Get("assignmentgroups").([]interface{})),
			},
		},
		Routing: ztnaAppRouting{
			Type:                d.Get("routingtype").(string),
			RouteId:             d.Get("routingid").(string),
			DnsIpResolutionType: routingdnstype,
		},
		Security: ztnaAppSecurity{
			RiskControls: ztnaAppRiskControls{
				Enabled:              d.Get("securityriskcontrolenabled").(bool),
				LevelThreshold:       d.Get("securityriskcontrolthreshold").(string),
				NotificationsEnabled: d.Get("securityriskcontrolnotifications").(bool),
			},
			DohIntegration: ztnaAppDohIntegration{
				Blocking:             d.Get("securitydohintegrationblocking").(bool),
				NotificationsEnabled: d.Get("securitydohintegrationnotifications").(bool),
			},
			DeviceManagementBasedAccess: ztnaAppDeviceMgmtAccess{
				Enabled:              d.Get("securitydevicemanagementbasedaccessenabled").(bool),
				NotificationsEnabled: d.Get("securitydevicemanagementbasedaccessnotifications").(bool),
			},
		},
	}
}

// ResourceZTNAApp returns the schema.Resource for jsc_app.
func ResourceZTNAApp() *schema.Resource {
	return &schema.Resource{
		Create: resourceZTNAAppCreate,
		Read:   resourceZTNAAppRead,
		Update: resourceZTNAAppUpdate,
		Delete: resourceZTNAAppDelete,

		Schema: map[string]*schema.Schema{
			"name": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "The name of the ZTNA App. Must be unique across the tenant.",
			},
			"type": {
				Type:        schema.TypeString,
				Optional:    true,
				Default:     "ENTERPRISE",
				Description: "The app type. Use ENTERPRISE for SwiftConnect routing.",
			},
			"categoryname": {
				Type:        schema.TypeString,
				Optional:    true,
				Default:     "Uncategorized",
				Description: "Category name for the app.",
			},
			"hostnames": {
				Type:        schema.TypeList,
				Elem:        &schema.Schema{Type: schema.TypeString},
				Optional:    true,
				Description: "List of hostnames to route through this ZTNA policy.",
			},
			"bareips": {
				Type:        schema.TypeList,
				Elem:        &schema.Schema{Type: schema.TypeString},
				Optional:    true,
				Description: "List of bare IPs in IPv4 CIDR notation.",
			},
			"routingtype": {
				Type:        schema.TypeString,
				Optional:    true,
				Default:     "CUSTOM",
				Description: "Routing type. CUSTOM routes via a specific VPN route; DIRECT routes without a relay.",
			},
			"routingid": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "The VPN route ID. Required when routingtype is CUSTOM. Obtain from jsc_pag_vpnroutes datasource.",
			},
			"routingdnstype": {
				Type:        schema.TypeString,
				Optional:    true,
				Default:     "IPv6",
				Description: "DNS IP resolution type. IPv4 or IPv6. Ignored when routingtype is DIRECT.",
			},
			"assignmentallusers": {
				Type:        schema.TypeBool,
				Optional:    true,
				Default:     false,
				Description: "Assign this ZTNA app policy to all users.",
			},
			"assignmentgroups": {
				Type:        schema.TypeList,
				Elem:        &schema.Schema{Type: schema.TypeString},
				Optional:    true,
				Description: "List of group IDs to assign this ZTNA app policy to.",
			},
			"securityriskcontrolenabled": {
				Type:        schema.TypeBool,
				Optional:    true,
				Default:     false,
				Description: "Enable device risk controls for this app policy.",
			},
			"securityriskcontrolthreshold": {
				Type:        schema.TypeString,
				Optional:    true,
				Default:     "HIGH",
				Description: "Risk level threshold for access. Valid values: HIGH, MEDIUM, LOW.",
			},
			"securityriskcontrolnotifications": {
				Type:        schema.TypeBool,
				Optional:    true,
				Default:     true,
				Description: "Enable notifications for risk control events.",
			},
			"securitydohintegrationblocking": {
				Type:        schema.TypeBool,
				Optional:    true,
				Default:     false,
				Description: "Enable DNS-over-HTTPS blocking for this app policy.",
			},
			"securitydohintegrationnotifications": {
				Type:        schema.TypeBool,
				Optional:    true,
				Default:     true,
				Description: "Enable notifications for DoH integration events.",
			},
			"securitydevicemanagementbasedaccessenabled": {
				Type:        schema.TypeBool,
				Optional:    true,
				Default:     false,
				Description: "Enable device management based access control.",
			},
			"securitydevicemanagementbasedaccessnotifications": {
				Type:        schema.TypeBool,
				Optional:    true,
				Default:     false,
				Description: "Enable notifications for device management based access events.",
			},
		},
	}
}

func resourceZTNAAppCreate(d *schema.ResourceData, m interface{}) error {
	payload, err := json.Marshal(buildZTNAAppRequest(d))
	if err != nil {
		return fmt.Errorf("failed to marshal jsc_app payload: %v", err)
	}

	req, err := http.NewRequest("POST", "https://radar.wandera.com/gate/traffic-routing-service/v1/apps", bytes.NewBuffer(payload))
	if err != nil {
		return fmt.Errorf("failed to build jsc_app create request: %v", err)
	}

	resp, err := auth.MakeRequest(req)
	if err != nil {
		return fmt.Errorf("jsc_app create request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		return fmt.Errorf("failed to create jsc_app: %s", resp.Status)
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read jsc_app create response: %v", err)
	}

	var response struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(body, &response); err != nil {
		return fmt.Errorf("failed to parse jsc_app create response: %v", err)
	}

	if response.ID == "" {
		return fmt.Errorf("jsc_app was created but API returned an empty ID")
	}

	d.SetId(response.ID)
	return nil
}

func resourceZTNAAppRead(d *schema.ResourceData, m interface{}) error {
	req, err := http.NewRequest("GET", fmt.Sprintf("https://radar.wandera.com/gate/traffic-routing-service/v1/apps/%s", d.Id()), nil)
	if err != nil {
		return fmt.Errorf("failed to build jsc_app read request: %v", err)
	}

	resp, err := auth.MakeRequest(req)
	if err != nil {
		return fmt.Errorf("jsc_app read request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		d.SetId("")
		return nil
	}

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("failed to read jsc_app: %s", resp.Status)
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read jsc_app read response: %v", err)
	}

	var response ztnaAppResponse
	if err := json.Unmarshal(body, &response); err != nil {
		return fmt.Errorf("failed to parse jsc_app read response: %v", err)
	}

	d.Set("name", response.Name)
	d.Set("type", response.Type)
	d.Set("categoryname", response.CategoryName)
	d.Set("hostnames", response.Hostnames)
	d.Set("bareips", response.BareIps)
	d.Set("assignmentallusers", response.Assignments.Inclusions.AllUsers)
	d.Set("assignmentgroups", response.Assignments.Inclusions.Groups)
	d.Set("routingtype", response.Routing.Type)
	d.Set("routingid", response.Routing.RouteId)
	d.Set("routingdnstype", response.Routing.DnsIpResolutionType)
	d.Set("securityriskcontrolenabled", response.Security.RiskControls.Enabled)
	d.Set("securityriskcontrolthreshold", response.Security.RiskControls.LevelThreshold)
	d.Set("securityriskcontrolnotifications", response.Security.RiskControls.NotificationsEnabled)
	d.Set("securitydohintegrationblocking", response.Security.DohIntegration.Blocking)
	d.Set("securitydohintegrationnotifications", response.Security.DohIntegration.NotificationsEnabled)
	d.Set("securitydevicemanagementbasedaccessenabled", response.Security.DeviceManagementBasedAccess.Enabled)
	d.Set("securitydevicemanagementbasedaccessnotifications", response.Security.DeviceManagementBasedAccess.NotificationsEnabled)

	return nil
}

func resourceZTNAAppUpdate(d *schema.ResourceData, m interface{}) error {
	if err := resourceZTNAAppDelete(d, m); err != nil {
		return err
	}
	return resourceZTNAAppCreate(d, m)
}

func resourceZTNAAppDelete(d *schema.ResourceData, m interface{}) error {
	req, err := http.NewRequest("DELETE", fmt.Sprintf("https://radar.wandera.com/gate/traffic-routing-service/v1/apps/%s", d.Id()), nil)
	if err != nil {
		return fmt.Errorf("failed to build jsc_app delete request: %v", err)
	}

	resp, err := auth.MakeRequest(req)
	if err != nil {
		return fmt.Errorf("jsc_app delete request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		return fmt.Errorf("failed to delete jsc_app: %s", resp.Status)
	}

	d.SetId("")
	return nil
}
