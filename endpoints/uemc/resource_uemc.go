package uemc

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

// Define the schema for the UEMC resource
func resourceUEMC() *schema.Resource {
	return &schema.Resource{
		Create: resourceUEMCCreate,
		Read:   resourceUEMCRead,
		Update: resourceUEMCUpdate,
		Delete: resourceUEMCDelete,

		// Define the attributes of the okta resource
		Schema: map[string]*schema.Schema{
			"domain": {
				Type:     schema.TypeString,
				Required: true,
			},
			"clientsecret": {
				Type:     schema.TypeString,
				Required: true,
			},
			"clientid": {
				Type:     schema.TypeString,
				Required: true,
			},
			// Add more attributes as needed
		},
	}
}

// Define the create function for the UEMC resource
func resourceUEMCCreate(d *schema.ResourceData, m interface{}) error {

	// Perform authentication if the authentication token is empty
	if authToken == "" {
		err := authenticate()
		if err != nil {
			return err
		}
	}

	// Construct the request body
	vm := map[string]interface{}{
		"url":          d.Get("domain").(string),
		"authStrategy": "JAMF_PRO_OAUTH",
		"deviceSyncAuth": map[string]string{
			"clientId":     d.Get("clientid").(string),
			"clientSecret": d.Get("clientsecret").(string),
		},
		"isoCountry": "us",
		"vendor":     "JAMF_PRO",
	}

	/*vm := map[string]interface{}{
		"domain":       d.Get("domain").(string),
		"clientsecret": d.Get("clientsecret").(string),
		"clientId":     d.Get("clientid").(string),
	}*/

	payload, err := json.Marshal(vm)
	if err != nil {
		return err
	}

	// Make a POST request to create a new okta
	client := &http.Client{}
	req, err := http.NewRequest("PUT", fmt.Sprintf("https://radar.wandera.com/gate/connector-service/v1/config/%s/emm-server?customerId=%s", Customerid, Customerid), bytes.NewBuffer(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("X-Xsrf-Token", xsrfToken)
	req.AddCookie(&http.Cookie{Name: "SESSION", Value: sessionCookie, Path: "/", SameSite: http.SameSiteLaxMode, Secure: true, HttpOnly: true})
	req.AddCookie(&http.Cookie{Name: "XSRF-TOKEN", Value: xsrfToken})
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	// Check the response status code
	if resp.StatusCode != http.StatusOK && resp.StatusCode != 200 {
		return fmt.Errorf("failed to create UEMC Connection: %s", resp.Status+" "+string(payload))
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

	// Set the resource ID... hint there's only 1 ID of UEMC!
	d.SetId("1")

	// Set the resource ID
	//d.SetId("example-vm-id")

	return nil
}

// Define the read function for the Okta resource
func resourceUEMCRead(d *schema.ResourceData, m interface{}) error {
	// Make a GET request to read the details of an existing Okta IDP

	// Perform authentication if the authentication token is empty
	if authToken == "" {
		err := authenticate()
		if err != nil {
			return err
		}
	}

	client := &http.Client{}
	req, err := http.NewRequest("GET", fmt.Sprintf("https://radar.wandera.com/gate/connector-service/v1/sync-state/%s?customerId=%s", Customerid, Customerid), nil)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("X-Xsrf-Token", xsrfToken)
	req.AddCookie(&http.Cookie{Name: "SESSION", Value: sessionCookie, Path: "/", SameSite: http.SameSiteLaxMode, Secure: true, HttpOnly: true})
	req.AddCookie(&http.Cookie{Name: "XSRF-TOKEN", Value: xsrfToken})
	resp, err := client.Do(req)

	//resp, err := http.Get(fmt.Sprintf("https://radar.wandera.com/gate/identity-service/v1/connections?customerId=993ae0ee-4bd8-4325-bc5d-1db0ea45b4f6&type=OKTA"))
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	// Check the response status code
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("failed to read UEMC info: %s", resp.Status)
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

// Define the update function for the UEMC - needs to be replace completely
func resourceUEMCUpdate(d *schema.ResourceData, m interface{}) error {
	d.Set("requires_replace", true)

	return nil
}

// Define the delete function for the Okta resource
func resourceUEMCDelete(d *schema.ResourceData, m interface{}) error {
	// Make a DELETE request to delete an existing Okta

	// Perform authentication if the authentication token is empty
	if authToken == "" {
		err := authenticate()
		if err != nil {
			return err
		}
	}

	req, err := http.NewRequest("DELETE", fmt.Sprintf("https://radar.wandera.com/gate/connector-service/v1/config/%s?customerId=%s", Customerid, Customerid), nil)
	if err != nil {
		return err
	}

	// Send the request
	client := &http.Client{}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("X-Xsrf-Token", xsrfToken)
	req.AddCookie(&http.Cookie{Name: "SESSION", Value: sessionCookie, Path: "/", SameSite: http.SameSiteLaxMode, Secure: true, HttpOnly: true})
	req.AddCookie(&http.Cookie{Name: "XSRF-TOKEN", Value: xsrfToken})
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	// Check the response status code
	if resp.StatusCode != http.StatusOK && resp.StatusCode != 204 {
		return fmt.Errorf("failed to delete UEMC: %v %v %v", resp.Status, resp, req)
	}

	// Clear the resource ID
	d.SetId("")

	return nil
}
