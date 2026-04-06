// Copyright 2025, Jamf Software LLC.
package hostnamemapping

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
	"sync"

	"jsctfprovider/internal/auth"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

// Mutex to serialize read-modify-write operations on hostname mappings.
// The API stores all mappings as a single collection, so concurrent
// modifications cause a race condition where parallel creates overwrite
// each other.
var hostnameMappingMu sync.Mutex

// Define the schema for the Okta resource
func ResourceHostnameMapping() *schema.Resource {
	return &schema.Resource{
		Create: resourceHostnameMappingCreate,
		Read:   resourceHostnameMappingRead,
		Update: resourceHostnameMappingUpdate,
		Delete: resourceHostnameMappingDelete,
		Importer: &schema.ResourceImporter{
			StateContext: schema.ImportStatePassthroughContext,
		},

		// Define the attributes of the okta resource
		Schema: map[string]*schema.Schema{
			"hostname": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Hostname of mapping",
			},
			"a": {
				Type:        schema.TypeSet,
				Optional:    true,
				Description: "Set (unordered list) of IPv4 A records",
				Elem: &schema.Schema{
					Type: schema.TypeString, // Assuming the A records are represented as strings
				},
			},
			"aaaa": {
				Type:        schema.TypeSet,
				Optional:    true,
				Description: "Set (unordered list) of IPv6 A records",
				Elem: &schema.Schema{
					Type: schema.TypeString, // Assuming the AAAA records are represented as strings
				},
			},
			"securedns": {
				Type:        schema.TypeBool,
				Optional:    true,
				Default:     true,
				Description: "If used with Secure DNS",
			},
			"ztna": {
				Type:        schema.TypeBool,
				Optional:    true,
				Default:     true,
				Description: "If used with ZTNA",
			},
			// Add more attributes as needed
		},
	}
}

//a few helper functions

func getAllHostnameMappings() (*Mappings, error) {
	req, err := http.NewRequest("GET", fmt.Sprintf("https://radar.wandera.com/gate/dns-zone-management-service/v1/custom-hostname-mappings"), nil)
	if err != nil {
		return nil, (fmt.Errorf("error converting making http request body"))
	}
	resp, err := auth.MakeRequest((req))

	if err != nil {
		return nil, (fmt.Errorf("error making http request"))
	}
	defer resp.Body.Close()

	// Check the response status code
	if resp.StatusCode != http.StatusOK {
		return nil, (fmt.Errorf("failed to read routes info: %s", resp.Status))
	}

	// Read the response body
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, (fmt.Errorf("error making parsing body response"))
	}

	// Parse the response JSON
	var response Mappings
	err = json.Unmarshal(body, &response)
	if err != nil {
		return nil, (err)
	}

	return &response, nil
}

// Define the create function for the mapping resource
func resourceHostnameMappingCreate(d *schema.ResourceData, m interface{}) error {
	// Lock to prevent concurrent read-modify-write race conditions
	hostnameMappingMu.Lock()
	defer hostnameMappingMu.Unlock()

	response, err := getAllHostnameMappings()
	if err != nil {
		return err
	}

	for _, mapping := range response.Mapping {
		if strings.EqualFold(mapping.Hostname, d.Get("hostname").(string)) {
			return (fmt.Errorf("hostname mapping already exists"))
		}
	}

	// Convert schema.TypeSet to []string
	aSet := d.Get("a").(*schema.Set)

	var aList []string
	for _, item := range aSet.List() {
		aList = append(aList, item.(string))
	}

	// Convert schema.TypeSet to []string
	aaaaSet := d.Get("aaaa").(*schema.Set)

	var aaaaList []string
	for _, item := range aaaaSet.List() {
		aaaaList = append(aaaaList, item.(string))
	}

	// Create a new Mapping to append
	newMapping := Mapping{
		Hostname:  d.Get("hostname").(string),
		SecureDNS: d.Get("securedns").(bool),
		ZTNA:      d.Get("ztna").(bool),
		A:         aList,
		AAAA:      aaaaList,
	}
	response.Mapping = append(response.Mapping, newMapping)

	payload, err := json.Marshal(response)
	if err != nil {
		return err
	}

	// Make a PUT request to update all mappings
	req, err := http.NewRequest("PUT", ("https://radar.wandera.com/gate/dns-zone-management-service/v1/custom-hostname-mappings"), bytes.NewBuffer(payload))
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
		return fmt.Errorf("failed to create hostname mapping: %s", resp.Status+" ")
	}

	d.SetId(d.Get("hostname").(string))
	return nil
}

// Define the read function for the hostname mapping
func resourceHostnameMappingRead(d *schema.ResourceData, m interface{}) error {
	// Make a GET request to read the details of mappings

	response, err := getAllHostnameMappings()
	if err != nil {
		return err
	}

	for _, mapping := range response.Mapping {
		if strings.EqualFold(mapping.Hostname, d.Get("hostname").(string)) {
			d.Set("securedns", mapping.SecureDNS)
			d.Set("ztna", mapping.ZTNA)
			// Convert your `A` slice to a set
			aSet := schema.NewSet(schema.HashString, convertStringSliceToInterfaceSet(mapping.A))
			d.Set("a", aSet)
			// Convert your `AAAA` slice to a set
			aaaaSet := schema.NewSet(schema.HashString, convertStringSliceToInterfaceSet(mapping.AAAA))
			d.Set("aaaa", aaaaSet)
			d.SetId(mapping.Hostname) //need to set something for resource to exist
			break
		}
	}

	return nil
}

// Define the update function for the hostname resource
func resourceHostnameMappingUpdate(d *schema.ResourceData, m interface{}) error {
	// Lock to prevent concurrent read-modify-write race conditions
	hostnameMappingMu.Lock()
	defer hostnameMappingMu.Unlock()

	response, err := getAllHostnameMappings()
	if err != nil {
		return err
	}

	// Convert schema.TypeSet to []string for A records
	aSet := d.Get("a").(*schema.Set)
	var aList []string
	for _, item := range aSet.List() {
		aList = append(aList, item.(string))
	}

	// Convert schema.TypeSet to []string for AAAA records
	aaaaSet := d.Get("aaaa").(*schema.Set)
	var aaaaList []string
	for _, item := range aaaaSet.List() {
		aaaaList = append(aaaaList, item.(string))
	}

	// Find and update the existing mapping
	found := false
	for i, mapping := range response.Mapping {
		if strings.EqualFold(mapping.Hostname, d.Id()) {
			response.Mapping[i] = Mapping{
				Hostname:  d.Get("hostname").(string),
				SecureDNS: d.Get("securedns").(bool),
				ZTNA:      d.Get("ztna").(bool),
				A:         aList,
				AAAA:      aaaaList,
			}
			found = true
			break
		}
	}

	if !found {
		return fmt.Errorf("hostname mapping not found for update: %s", d.Id())
	}

	payload, err := json.Marshal(response)
	if err != nil {
		return err
	}

	req, err := http.NewRequest("PUT", "https://radar.wandera.com/gate/dns-zone-management-service/v1/custom-hostname-mappings", bytes.NewBuffer(payload))
	if err != nil {
		return err
	}

	resp, err := auth.MakeRequest(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != 201 {
		return fmt.Errorf("failed to update hostname mapping: %s", resp.Status)
	}

	// Update the ID if hostname changed
	d.SetId(d.Get("hostname").(string))
	return nil
}

// Define the delete function for the hostname resource
func resourceHostnameMappingDelete(d *schema.ResourceData, m interface{}) error {
	// Lock to prevent concurrent read-modify-write race conditions
	hostnameMappingMu.Lock()
	defer hostnameMappingMu.Unlock()

	response, err := getAllHostnameMappings()
	if err != nil {
		return err
	}
	var filteredMappings []Mapping
	for _, mapping := range response.Mapping {
		if !strings.EqualFold(mapping.Hostname, d.Get("hostname").(string)) {
			filteredMappings = append(filteredMappings, mapping) //add back all mappings but the one we're deleting
		}
	}
	response.Mapping = filteredMappings

	payload, err := json.Marshal(response)
	if err != nil {
		return err
	}

	// Make a PUT request to update all mappings
	req, err := http.NewRequest("PUT", ("https://radar.wandera.com/gate/dns-zone-management-service/v1/custom-hostname-mappings"), bytes.NewBuffer(payload))
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
		return fmt.Errorf("failed to delete hostname mapping: %s", resp.Status+" ")
	}

	// Clear the resource ID
	d.SetId("")

	return nil
}
