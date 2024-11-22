package pagztnaapp

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"jsctfprovider/internal/auth"
	"net/http"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

type RequestItemZTNAApp struct {
	Name          string      `json:"name"`
	CategoryName  string      `json:"categoryName"`
	Hostnames     []string    `json:"hostnames"`
	BareIps       []string    `json:"bareIps"`
	Assignments   Assignments `json:"assignments"`
	Routing       Routing     `json:"routing"`
	Security      Security    `json:"security"`
	AppTemplateId string      `json:"appTemplateId,omitempty"`
}

type ResponseItemZTNAApp struct {
	Name          string      `json:"name"`
	CategoryName  string      `json:"categoryName"`
	Hostnames     []string    `json:"hostnames"`
	BareIps       []string    `json:"bareIps"`
	Assignments   Assignments `json:"assignments"`
	Routing       Routing     `json:"routing"`
	Security      Security    `json:"security"`
	AppTemplateId string      `json:"appTemplateId"`
	ID            string      `json:"id"`
}

// Define the schema for the ZTNA resource
func ResourcePAGZTNAApp() *schema.Resource {
	return &schema.Resource{
		Create:        resourcePAGZTNAAppCreate,
		Read:          resourcePAGZTNAAppRead,
		Update:        resourcePAGZTNAAppUpdate,
		Delete:        resourcePAGZTNAAppDelete,
		CustomizeDiff: validatePAGZTNADataFields,

		Schema: map[string]*schema.Schema{
			"name": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "The name of the ZTNA App. Must be unique",
			},
			"id": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "The unique identifier of the ZTNA App datasource set from JSC",
			},
			"hostnames": {
				Type:        schema.TypeList,
				Elem:        &schema.Schema{Type: schema.TypeString},
				Optional:    true,
				Description: "List of hostnames. Must be unique across all Access Policies and App Templates",
			},
			"bareips": {
				Type:        schema.TypeList,
				Elem:        &schema.Schema{Type: schema.TypeString},
				Optional:    true,
				Description: "List of bare ips - IPv4 only CIDR notation",
			},
			"categoryname": {
				Type:        schema.TypeString,
				Optional:    true,
				Default:     "Uncategorized",
				Description: "Category Name - supported types are Adult, Advertising, App Counters, App Stores, Audio & Music, Browsers, Business & Industry, Cloud & File Storage, Communication, Content Servers, Custom, Entertainment, Extreme, Finance, Gambling, Games, Generative AI, Illegal, Lifestyle, Medical, Navigation, News & Sport, OS Updates, Productivity, Reference, Shopping, Social, Technology, Travel, Uncategorized, Video & Photo",
			},
			"apptemplateid": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "App Template ID (if applicable)",
			},
			"routingtype": {
				Type:        schema.TypeString,
				Optional:    true,
				Default:     "DIRECT",
				Description: "Routing Type - DIRECT or CUSTOM",
			},
			"routingid": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Routing ID - required when routingtype is CUSTOM. Otherwise must be omitted",
			},
			"routingdnstype": {
				Type:        schema.TypeString,
				Optional:    true,
				Default:     "IPv6",
				Description: "Routing IP DNS Resolution Type - IPv4 or IPv6 (default is IPv6)",
			},
			"securityriskcontrolenabled": {
				Type:        schema.TypeBool,
				Optional:    true,
				Default:     false,
				Description: "Enable device risk security controls for ZTNA App policy",
			},
			"securityriskcontrolthreshold": {
				Type:        schema.TypeString,
				Optional:    true,
				Default:     "HIGH",
				Description: "Risk level threshold (when enabled), options of HIGH, MEDIUM, LOW",
			},
			"securityriskcontrolnotifications": {
				Type:        schema.TypeBool,
				Optional:    true,
				Default:     false,
				Description: "Enable notificatons for device risk security controls",
			},
			"securitydohintegrationblocking": {
				Type:        schema.TypeBool,
				Optional:    true,
				Default:     true,
				Description: "Enable DoH blocking for ZTNA App Policy",
			},
			"securitydohintegrationnotifications": {
				Type:        schema.TypeBool,
				Optional:    true,
				Default:     false,
				Description: "Enable DoH notifications for ZTNA App Policy",
			},
			"securitydevicemanagementbasedaccessenabled": {
				Type:        schema.TypeBool,
				Optional:    true,
				Default:     false,
				Description: "Enable deviceManagementBasedAccess for ZTNA App Policy",
			},
			"securitydevicemanagementbasedaccessnotifications": {
				Type:        schema.TypeBool,
				Optional:    true,
				Default:     false,
				Description: "Enable deviceManagementBasedAccess notifications for ZTNA App Policy",
			},
			"assignmentallusers": {
				Type:        schema.TypeBool,
				Optional:    true,
				Default:     false,
				Description: "Assign ZTNA App to all users",
			},
			"assignmentgroups": {
				Type:        schema.TypeList,
				Elem:        &schema.Schema{Type: schema.TypeString},
				Optional:    true,
				Description: "Group IDs to assign ZTNA App Policy",
			},
		},
	}
}

// Define the create function for the ztna resource
func resourcePAGZTNAAppCreate(d *schema.ResourceData, m interface{}) error {

	hostnamesInterface := d.Get("hostnames").([]interface{}) // Get the raw slice of interfaces

	// Now convert each element of the slice to a string
	hostnames := make([]string, len(hostnamesInterface)) // Create a string slice with the same length

	for i, v := range hostnamesInterface {
		hostnames[i] = v.(string) // Assert each element as a string
	}

	bareipssInterface := d.Get("bareips").([]interface{}) // Get the raw slice of interfaces

	// Now convert each element of the slice to a string
	bareips := make([]string, len(bareipssInterface)) // Create a string slice with the same length

	for i, v := range bareipssInterface {
		bareips[i] = v.(string) // Assert each element as a string
	}

	groupsInterface := d.Get("assignmentgroups").([]interface{}) // Get the raw slice of interfaces

	// Now convert each element of the slice to a string
	groups := make([]string, len(groupsInterface)) // Create a string slice with the same length

	for i, v := range groupsInterface {
		groups[i] = v.(string) // Assert each element as a string
	}
	routingdnstype := d.Get("routingdnstype").(string)
	if d.Get("routingtype").(string) == "DIRECT" {
		//if routing is DIRECT, we need to remove the routingdns type
		routingdnstype = ""
	}

	config := RequestItemZTNAApp{
		Name:         d.Get("name").(string),
		CategoryName: d.Get("categoryname").(string),
		Assignments: Assignments{
			Inclusions: Inclusions{
				AllUsers: d.Get("assignmentallusers").(bool),
				Groups:   groups,
			},
		},
		Routing: Routing{
			Type:                d.Get("routingtype").(string),
			RouteId:             d.Get("routingid").(string),
			DnsIpResolutionType: routingdnstype,
		},
		Security: Security{
			RiskControls: RiskControls{
				Enabled:              d.Get("securityriskcontrolenabled").(bool),
				LevelThreshold:       d.Get("securityriskcontrolthreshold").(string),
				NotificationsEnabled: d.Get("securityriskcontrolnotifications").(bool),
			},
			DohIntegration: DohIntegration{
				Blocking:             false,
				NotificationsEnabled: true,
			},
			DeviceManagementBasedAccess: DeviceManagementBasedAccess{
				Enabled:              false,
				NotificationsEnabled: true,
			},
		},
		AppTemplateId: d.Get("apptemplateid").(string),
		Hostnames:     hostnames,
		BareIps:       bareips,
	}

	payload, err := json.Marshal(config)
	if err != nil {
		return err
	}
	// Make a POST request to create a new okta
	req, err := http.NewRequest("POST", ("https://api.wandera.com/ztna/v1/apps"), bytes.NewBuffer(payload))
	if err != nil {
		return err
	}
	resp, err := auth.MakePAGRequest((req))
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	// Check the response status code
	if resp.StatusCode != http.StatusOK && resp.StatusCode != 201 {
		println(payload)
		return fmt.Errorf("failed to create PAG ZTNA App: %s", resp.Status+" "+string(payload))

	}

	// Read the response body
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	// Parse the response JSON if needed
	// (this depends on the structure of the API response)
	fmt.Println(string(body))

	// Parse the response JSON
	var response struct {
		ID string `json:"id"`
	}
	err = json.Unmarshal(body, &response)
	if err != nil {
		return err
	}

	// Set the resource ID
	d.SetId(response.ID)

	return nil
}

// Define the read function for the ztna resource
func resourcePAGZTNAAppRead(d *schema.ResourceData, m interface{}) error {

	req, err := http.NewRequest("GET", fmt.Sprintf("https://api.wandera.com/ztna/v1/apps/%s", d.Id()), nil)

	if err != nil {
		return (fmt.Errorf("error converting making http request body"))
	}
	resp, err := auth.MakePAGRequest((req))

	if err != nil {
		return (err)
	}
	defer resp.Body.Close()

	// Check the response status code
	if resp.StatusCode != http.StatusOK {
		return (fmt.Errorf("failed to read app policy info: %s", resp.Status))
	}

	// Read the response body
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return (fmt.Errorf("error making parsing body response"))
	}

	// Parse the response JSON if needed
	// (this depends on the structure of the API response)
	fmt.Println(string(body))
	// Parse the response JSON

	var response ResponseItemZTNAApp
	err = json.Unmarshal(body, &response)
	if err != nil {
		return err
	}

	d.SetId(response.ID)
	d.Set("hostnames", response.Hostnames)
	d.Set("bareips", response.BareIps)
	d.Set("name", response.Name)
	d.Set("categoryname", response.CategoryName)
	d.Set("apptemplateid", response.AppTemplateId)
	d.Set("routingtype", response.Routing.Type)
	d.Set("routingid", response.Routing.RouteId)
	d.Set("routingdnstype", response.Routing.DnsIpResolutionType)

	return nil
}

// Define the update function for the ztna  resource NOT IMPLIMENTED

func resourcePAGZTNAAppUpdate(d *schema.ResourceData, m interface{}) error {

	d.Set("requires_replace", true)
	resourcePAGZTNAAppDelete(d, m)
	resourcePAGZTNAAppCreate(d, m)
	return nil
}

// Define the delete function for the ztna resource
func resourcePAGZTNAAppDelete(d *schema.ResourceData, m interface{}) error {

	req, err := http.NewRequest("DELETE", fmt.Sprintf("https://api.wandera.com/ztna/v1/apps/%s", d.Id()), nil)
	if err != nil {
		return err
	}

	// Send the request
	resp, err := auth.MakePAGRequest((req))
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	// Check the response status code
	if resp.StatusCode != http.StatusOK && resp.StatusCode != 204 {
		return fmt.Errorf("failed to delete ZTNA App: %v %v %v", resp.Status, resp, req)
	}

	// Clear the resource ID
	d.SetId("")

	return nil
}
