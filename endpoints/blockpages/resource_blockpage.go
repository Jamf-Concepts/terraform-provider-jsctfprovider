package blockpages

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"sync"

	"jsctfprovider/internal/auth"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

// Create a global mutex need to lock patch requests
var mu sync.Mutex

// Define the schema for the blockpage resource - only datablock rn
func ResourceBlockPage() *schema.Resource {
	return &schema.Resource{
		Create: resourceBlockPageCreate,
		Read:   resourceBlockPageRead,
		Update: resourceBlockPageUpdate,
		Delete: resourceBlockPageCDelete,

		// Define the attributes of the okta resource
		Schema: map[string]*schema.Schema{
			"description": {
				Type:        schema.TypeString,
				Optional:    true,
				Default:     "The site you are attempting to view has been blocked. If you would like more information please contact your administrator.",
				Description: "Text presented to end-user.",
			},
			"title": {
				Type:        schema.TypeString,
				Optional:    true,
				Default:     "Site Blocked",
				Description: "Title of text.",
			},
			"type": {
				Type:     schema.TypeString,
				Optional: true,
				Default:  "block",
				ValidateFunc: func(val any, key string) (warns []string, errs []error) {

					if val != "block" && val != "secureBlock" && val != "cap" && val != "deviceRisk" && val != "deviceManagement" {
						errs = append(errs, fmt.Errorf("%q must be either block, secureBlock, cap, deviceRisk, or deviceManagement: got: %d", key, val))
					}
					return
				},
			},
			"show_classification": {
				Type:     schema.TypeBool,
				Optional: true,
				Default:  true,
			},
			"show_requesturl": {
				Type:     schema.TypeBool,
				Optional: true,
				Default:  true,
			},
			// Add more attributes as needed
		},
	}
}

// Define the create function for the UEMC resource
func resourceBlockPageCreate(d *schema.ResourceData, m interface{}) error {

	vm := map[string]interface{}{
		d.Get("type").(string): map[string]interface{}{
			"description":        d.Get("description").(string),
			"enabled":            true,
			"logo":               "iVBORw0KGgoAAAANSUhEUgAAAC0AAAAtCAMAAAANxBKoAAAACXBIWXMAAA3XAAAN1wFCKJt4AAAAS1BMVEVHcEz/OzD/LS3/Oy//NzL/OjD/OjD/OzD/Oy//OzD/OzD/OzD/OzD/OjD/OzH/OzD/PC//OzD/OzD/OzD/OTD/OjD/Oy//OzD/OzAH3jTpAAAAGHRSTlMARwIqCaCH6FNovbD6FTLxPMfWeg8fk9059WpCAAACU0lEQVRIx4VV2aKrIAwUFAFFQVDL/3/pDavB0nvSlxrHLJMJDMPbpl24eZ4luYa/7HKL8sU4E/Q/WLP6l3F3/oobseq4Jdl3I9zKI15240sN76zcHg81LJR1fDcwMfB/vurcbsBz8gYvUMM8dVLuFt6IL7Am/XZC1hYODj72kEaAQfcKhZIQuQcmvFKpKpOXbr59SlaIeVa8kGnuVQz1MRnNAbsmTxCo67FBueeFUeH9UkOLXugRpR+OHPyCCfaH672sDyJ/6rATF3J7f+Gy9JRygIqiba0i7Y2eZoDBALBArfmpZhKJM42e1U/4pAIrgZs521p5ysXuQtaNs/4TmySYp6f2keXB2zk4hZWx+r3Gcg/1J0Nz144O4degQxOZh9HGNZZCyDUs1ZJyuqqA1IpNYF02ktLhnCFNZDtMDM19SYWftkaLQY4iQuDRDbhwktS3TM1m+RQUZLI22gDnqDzfGjCXWU1VlychwsaeGZZOBI9BqTmrKWT7mAgLu4ALXUWLVwQvsH87EnYBU6ojXRP3aktfrXKn6Z98gWNqnRm/qyRbUhE4FB5oOiH4Hp+2FxqDYRQqTiuwMwE3n2er5BcYNMjTTIANtj28j+lvC37mAsePX9FMP16fLzBeXxLVSdAOuhf4zMylUgO8vtu010d7kLKq5dyZ5/Wwd/EOQWBwcHxriKD5I+ND30jIJ3vvNw0uiDCTKdUCjRuabkXYT/V1QpmkY36VewiqX1cbfb2TwzBduKHCPqfMvXXPGDqR2eVeKbltuNEW+fcdHvHQYHP8/gPvrjcrgOzcSAAAAABJRU5ErkJggg==",
			"logoType":           "image/png",
			"showClassification": d.Get("show_classification"),
			"showRequestUrl":     d.Get("show_requesturl"),
			"showTransactionId":  true,
			"templateId":         "default",
			"title":              d.Get("title").(string),
		},
		"jamfCustomizableBlockSupport": true,
		"privateRelayDomainsBlock":     true,
	}

	payload, err := json.Marshal(vm)
	if err != nil {
		return fmt.Errorf("an error occurred: %s", "additional information1")
	}
	req, err := http.NewRequest("PATCH", fmt.Sprintf("https://radar.wandera.com/gate/block-service/blocks/v1/customers/{customerid}"), bytes.NewBuffer(payload))
	if err != nil {
		return fmt.Errorf("an error occurred: %s", "additional information2")
	}
	// Lock the mutex to ensure only one patch can run this function at a time
	mu.Lock()
	defer mu.Unlock()
	resp, err := auth.MakeRequest((req))

	if err != nil {
		return fmt.Errorf("an error occurred: %s", "additional information3")
	}
	defer resp.Body.Close()
	// Check the response status code
	if resp.StatusCode != http.StatusOK && resp.StatusCode != 204 {
		return fmt.Errorf("failed to create block page : %s", resp.Status+" "+string(payload))
	}

	// Read the response body
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("an error occurred: %s", "additional information4")
	}

	// Parse the response JSON if needed
	// (this depends on the structure of the API response)
	fmt.Println(string(body))

	// Set the resource ID... hint there's only 1 ID of UEMC!
	d.SetId("1")

	// Set the resource ID
	//d.SetId("example-vm-id")

	return nil
}

// Define the read function for the Blockpage resource
func resourceBlockPageRead(d *schema.ResourceData, m interface{}) error {
	// Make a GET request to read the details of an existing Okta IDP

	req, err := http.NewRequest("GET", fmt.Sprintf("https://radar.wandera.com/gate/block-service/blocks/v1/customers/{customerid}"), nil)
	if err != nil {
		return err
	}
	resp, err := auth.MakeRequest((req))

	//resp, err := http.Get(fmt.Sprintf("https://radar.wandera.com/gate/identity-service/v1/connections?customerId=993ae0ee-4bd8-4325-bc5d-1db0ea45b4f6&type=OKTA"))
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	// Check the response status code
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("failed to read BlockPage info: %s", resp.Status)
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
func resourceBlockPageUpdate(d *schema.ResourceData, m interface{}) error {
	d.Set("requires_replace", true)
	resourceBlockPageCreate(d, m)
	return nil
}

// Define the delete function for the block page - which doesn't really exist do we just reset back to default
func resourceBlockPageCDelete(d *schema.ResourceData, m interface{}) error {

	vm := map[string]interface{}{
		d.Get("type").(string): map[string]interface{}{
			"description":        "The site you are attempting to view has been blocked. If you would like more information please contact your administrator.",
			"enabled":            false,
			"logo":               "iVBORw0KGgoAAAANSUhEUgAAAC0AAAAtCAMAAAANxBKoAAAACXBIWXMAAA3XAAAN1wFCKJt4AAAAS1BMVEVHcEz/OzD/LS3/Oy//NzL/OjD/OjD/OzD/Oy//OzD/OzD/OzD/OzD/OjD/OzH/OzD/PC//OzD/OzD/OzD/OTD/OjD/Oy//OzD/OzAH3jTpAAAAGHRSTlMARwIqCaCH6FNovbD6FTLxPMfWeg8fk9059WpCAAACU0lEQVRIx4VV2aKrIAwUFAFFQVDL/3/pDavB0nvSlxrHLJMJDMPbpl24eZ4luYa/7HKL8sU4E/Q/WLP6l3F3/oobseq4Jdl3I9zKI15240sN76zcHg81LJR1fDcwMfB/vurcbsBz8gYvUMM8dVLuFt6IL7Am/XZC1hYODj72kEaAQfcKhZIQuQcmvFKpKpOXbr59SlaIeVa8kGnuVQz1MRnNAbsmTxCo67FBueeFUeH9UkOLXugRpR+OHPyCCfaH672sDyJ/6rATF3J7f+Gy9JRygIqiba0i7Y2eZoDBALBArfmpZhKJM42e1U/4pAIrgZs521p5ysXuQtaNs/4TmySYp6f2keXB2zk4hZWx+r3Gcg/1J0Nz144O4degQxOZh9HGNZZCyDUs1ZJyuqqA1IpNYF02ktLhnCFNZDtMDM19SYWftkaLQY4iQuDRDbhwktS3TM1m+RQUZLI22gDnqDzfGjCXWU1VlychwsaeGZZOBI9BqTmrKWT7mAgLu4ALXUWLVwQvsH87EnYBU6ojXRP3aktfrXKn6Z98gWNqnRm/qyRbUhE4FB5oOiH4Hp+2FxqDYRQqTiuwMwE3n2er5BcYNMjTTIANtj28j+lvC37mAsePX9FMP16fLzBeXxLVSdAOuhf4zMylUgO8vtu010d7kLKq5dyZ5/Wwd/EOQWBwcHxriKD5I+ND30jIJ3vvNw0uiDCTKdUCjRuabkXYT/V1QpmkY36VewiqX1cbfb2TwzBduKHCPqfMvXXPGDqR2eVeKbltuNEW+fcdHvHQYHP8/gPvrjcrgOzcSAAAAABJRU5ErkJggg==",
			"logoType":           "image/png",
			"showClassification": true,
			"showRequestUrl":     true,
			"showTransactionId":  true,
			"templateId":         "default",
			"title":              "Site Blocked",
		},
		"jamfCustomizableBlockSupport": false,
		"privateRelayDomainsBlock":     false,
	}

	payload, err := json.Marshal(vm)
	if err != nil {
		return err
	}
	req, err := http.NewRequest("PATCH", fmt.Sprintf("https://radar.wandera.com/gate/block-service/blocks/v1/customers/{customerid}"), bytes.NewBuffer(payload))
	if err != nil {
		return err
	}
	//lock to ensure only one patch can occur at one time
	mu.Lock()
	defer mu.Unlock()
	resp, err := auth.MakeRequest((req))

	if err != nil {
		return err
	}
	defer resp.Body.Close()

	// Check the response status code
	if resp.StatusCode != http.StatusOK && resp.StatusCode != 204 {
		return fmt.Errorf("failed to reset block page : %s", resp.Status+" "+string(payload))
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
