package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

// Define the schema for the Okta resource
func resourceOktaIdp() *schema.Resource {
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
			},
			"orgdomain": {
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

// Define the create function for the okta resource
func resourceOktaIdpCreate(d *schema.ResourceData, m interface{}) error {

	// Perform authentication if the authentication token is empty
	if authToken == "" {
		err := authenticate()
		if err != nil {
			return err
		}
	}
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
	client := &http.Client{}
	req, err := http.NewRequest("POST", fmt.Sprintf("https://radar.wandera.com/gate/identity-service/v1/connections?customerId=%s", Customerid), bytes.NewBuffer(payload))
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
	if resp.StatusCode != http.StatusOK && resp.StatusCode != 201 {
		return fmt.Errorf("failed to create Okta IDP Connection: %s", resp.Status+" "+sessionCookie)
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

	// Perform authentication if the authentication token is empty
	if authToken == "" {
		err := authenticate()
		if err != nil {
			return err
		}
	}

	client := &http.Client{}
	req, err := http.NewRequest("GET", fmt.Sprintf("https://radar.wandera.com/gate/identity-service/v1/connections?customerId=%s&type=OKTA", Customerid), nil)
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
	return nil
}

// Define the delete function for the Okta resource
func resourceOktaIdpDelete(d *schema.ResourceData, m interface{}) error {
	// Make a DELETE request to delete an existing Okta

	// Perform authentication if the authentication token is empty
	if authToken == "" {
		err := authenticate()
		if err != nil {
			return err
		}
	}

	req, err := http.NewRequest("DELETE", fmt.Sprintf("https://radar.wandera.com/gate/identity-service/v1/connections/%s?customerId=%s", d.Id(), Customerid), nil)
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
		return fmt.Errorf("failed to delete OktaIDP: %v %v %v", resp.Status, resp, req)
	}

	// Clear the resource ID
	d.SetId("")

	return nil
}
