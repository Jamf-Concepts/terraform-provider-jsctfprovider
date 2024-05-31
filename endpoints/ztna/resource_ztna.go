package ztna

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"jsctfprovider/internal/auth"
)

// Define the schema for the blockpage resource - only datablock rn
func Resourceztna() *schema.Resource {
	return &schema.Resource{
		Create: resourceztnaCreate,
		Read:   resourceztnaRead,
		Update: resourceztnaUpdate,
		Delete: resourceztnaDelete,

		// Define the attributes of the okta resource
		Schema: map[string]*schema.Schema{
			"name": {
				Type:     schema.TypeString,
				Required: true,
				Description: "Friendly name of ZTNA Access Policy.",
			},
			"type": {
				Type:     schema.TypeString,
				Optional: true,
				Default: "ENTERPRISE",
				Description: "Type of ZTNA Access Policy. ENTERPRISE or SAAS.",
			},
			"routeid": {
				Type:     schema.TypeString,
				Required: true,
				Description: "The routeid required for egress. Can be obtained from jsc_routes datasource.",
			},
			"hostnames": {
				Type:     schema.TypeList,
				Elem:     &schema.Schema{Type: schema.TypeString},
				Required: true,
				Description: "Hostnames that this ZTNA Access Policy will capture.",
			},
			// Add more attributes as needed
		},
	}
}

// Define the create function for the UEMC resource
func resourceztnaCreate(d *schema.ResourceData, m interface{}) error {


	hostnames := d.Get("hostnames").([]interface{})
	// Convert hostnames from []interface{} to []string
	var hostnamesStrings []string
	for _, h := range hostnames {
		hostnamesStrings = append(hostnamesStrings, h.(string))
	}

	app := map[string]interface{}{
			"type":         d.Get("type").(string),
			"name":         d.Get("name").(string),
			"categoryName": "Uncategorized",
			"hostnames":    hostnamesStrings,
			"bareIps":      []string{},
			"routing": map[string]interface{}{
				"type":                "CUSTOM",
				"routeId":             d.Get("routeid").(string),
				"dnsIpResolutionType": "IPv6",
			},
			"assignments": map[string]interface{}{
				"inclusions": map[string]interface{}{
					"allUsers": true,
					"groups":   []interface{}{},
				},
			},
			"security": map[string]interface{}{
				"riskControls": map[string]interface{}{
					"enabled":               false,
					"levelThreshold":        "HIGH",
					"notificationsEnabled": true,
				},
				"dohIntegration": map[string]interface{}{
					"blocking":             false,
					"notificationsEnabled": true,
				},
				"deviceManagementBasedAccess": map[string]interface{}{
					"enabled":               false,
					"notificationsEnabled": true,
				},
			},
		}
	

	payload, err := json.Marshal(app)
	if err != nil {
		return fmt.Errorf("an error occurred: %s", "marshalling")
	}
	req, err := http.NewRequest("POST", fmt.Sprintf("https://radar.wandera.com/api/app-definitions?appName=%s&", d.Get("name").(string)), bytes.NewBuffer(payload))
	if err != nil {
		return fmt.Errorf("an error occurred: %s", "additional information2")
	}
	resp, err := auth.MakeRequest((req))

	if err != nil {
		return fmt.Errorf("an error occurred: %s", "additional information3")
	}
	defer resp.Body.Close()
	// Check the response status code
	if resp.StatusCode != http.StatusOK && resp.StatusCode != 204 {
		return fmt.Errorf("failed to create ztnaapp page : %s", resp.Status+" "+string(payload))
	}

	// Read the response body
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("an error occurred: %s", "additional information4")
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
	d.Set("appname", d.Get("name").(string))



	return nil
}

// Define the read function for the ZTNA resource
func resourceztnaRead(d *schema.ResourceData, m interface{}) error {
	// Make a GET request to read the details of an existing ZTNA app
	
	req, err := http.NewRequest("GET", fmt.Sprintf("https://radar.wandera.com/api/app-definitions/%s?appName=&", d.Id() ), nil)
	if err != nil {
		return err
	}
	resp, err := auth.MakeRequest((req))

	if err != nil {
		return err
	}
	defer resp.Body.Close()

	// Check the response status code
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("failed to read ztna info: %s", resp.Status)
	}

	// Read the response body
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	// Parse the response JSON if needed
	// (this depends on the structure of the API response)
	fmt.Println(string(body))

	return nil
}

// Define the update function for the ZTNA - needs to be replace completely
func resourceztnaUpdate(d *schema.ResourceData, m interface{}) error {
	d.Set("requires_replace", true)
	resourceztnaDelete(d, m)
	resourceztnaCreate(d, m)

	return nil
}

// Define the delete function for the ZTNA page 
func resourceztnaDelete(d *schema.ResourceData, m interface{}) error {
	// Retrieve the value of the "name" attribute from the resource configuration

	name := d.Get("name").(string)

	req, err := http.NewRequest("DELETE", fmt.Sprintf("https://radar.wandera.com/api/app-definitions/%s?appName=%s&", d.Id(), name), nil)
	if err != nil {
		return err
	}
	resp, err := auth.MakeRequest((req))

	if err != nil {
		return err
	}
	defer resp.Body.Close()

	// Check the response status code
	if resp.StatusCode != http.StatusOK && resp.StatusCode != 204 {
		return fmt.Errorf("failed to delete ztna app : %s", resp.Status+" ")
	}

	// Read the response body
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	// Parse the response JSON if needed
	// (this depends on the structure of the API response)
	fmt.Println(string(body))

	// Clear the resource ID
	d.SetId("")

	return nil
}
