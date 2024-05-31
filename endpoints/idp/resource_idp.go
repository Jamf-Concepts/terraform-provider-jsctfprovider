package idp

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"jsctfprovider/internal/auth"
)

// Define the schema for the Okta resource
func ResourceOktaIdp() *schema.Resource {
	return &schema.Resource{
		Create: resourceOktaIdpCreate,
		Read:   resourceOktaIdpRead,
		Update: resourceOktaIdpUpdate,
		Delete: resourceOktaIdpDelete,

		// Define the attributes of the okta resource
		Schema: map[string]*schema.Schema{
			"name": {
				Type:     schema.TypeString,
				Required: true,
				Description: "Friendly name.",
			},
			"orgdomain": {
				Type:     schema.TypeString,
				Required: true,
				Description: "OrgDomain of Okta tenant",
			},
			"clientid": {
				Type:     schema.TypeString,
				Required: true,
				Description: "Client ID of Okta App.",
			},
			// Add more attributes as needed
		},
	}
}

// Define the create function for the okta resource
func resourceOktaIdpCreate(d *schema.ResourceData, m interface{}) error {


	// Construct the request body
	vm := map[string]interface{}{
		"name":      d.Get("name").(string),
		"orgDomain": d.Get("orgdomain").(string),
		"clientId":  d.Get("clientid").(string),
		"type":      "OKTA",
	}
	payload, err := json.Marshal(vm)
	if err != nil {
		return err
	}

	// Make a POST request to create a new okta
	req, err := http.NewRequest("POST", ("https://radar.wandera.com/gate/identity-service/v1/connections"), bytes.NewBuffer(payload))
	if err != nil {
		return err
	}
	resp, err := auth.MakeRequest((req))
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	// Check the response status code
	if resp.StatusCode != http.StatusOK && resp.StatusCode != 201 {
		return fmt.Errorf("failed to create Okta IDP Connection: %s", resp.Status+" ")
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

	// Set the resource ID
	//d.SetId("example-vm-id")

	return nil
}

// Define the read function for the Okta resource
func resourceOktaIdpRead(d *schema.ResourceData, m interface{}) error {
	// Make a GET request to read the details of an existing Okta IDP



	req, err := http.NewRequest("GET", ("https://radar.wandera.com/gate/identity-service/v1/connections"), nil)
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
		return fmt.Errorf("failed to read OKTA IDP info: %s", resp.Status)
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

// Define the update function for the Okta  resource NOT IMPLIMENTED

func resourceOktaIdpUpdate(d *schema.ResourceData, m interface{}) error {

	d.Set("requires_replace", true)
	resourceOktaIdpDelete(d, m)
	resourceOktaIdpCreate(d, m)
	return nil
}

// Define the delete function for the Okta resource
func resourceOktaIdpDelete(d *schema.ResourceData, m interface{}) error {
	// Make a DELETE request to delete an existing Okta



	req, err := http.NewRequest("DELETE", fmt.Sprintf("https://radar.wandera.com/gate/identity-service/v1/connections/%s", d.Id()), nil)
	if err != nil {
		return err
	}

	// Send the request
	resp, err := auth.MakeRequest((req))
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	// Check the response status code
	if resp.StatusCode != http.StatusOK && resp.StatusCode != 204 {
		return fmt.Errorf("failed to delete OktaIDP: %v %v %v", resp.Status, resp, req)
	}

	// Clear the resource ID
	d.SetId("")

	return nil
}
