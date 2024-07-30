package hostnamemapping

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

// define type of mapping - don't use much but nice to keep for future use
type Mapping struct {
	Hostname  string   `json:"hostname"`
	SecureDNS bool     `json:"secureDns"`
	ZTNA      bool     `json:"ztna"`
	A         []string `json:"A"`
	AAAA      []string `json:"AAAA"`
}

type Mappings struct {
	Mapping []Mapping `json:"mappings"`
}

// Helper function to convert string slice to interface slice
func convertStringSliceToInterfaceSet(slice []string) []interface{} {
	var result []interface{}
	for _, item := range slice {
		result = append(result, item)
	}
	return result
}

func DataSourceHostnameMapping() *schema.Resource {
	return &schema.Resource{
		ReadContext: dataSourceMappingsRead,

		Schema: map[string]*schema.Schema{
			"hostname": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "The hostname of the mapping",
			},
			"securedns": {
				Type:        schema.TypeBool,
				Computed:    true,
				Description: "If used with Secure DNS",
			},
			"ztna": {
				Type:        schema.TypeBool,
				Computed:    true,
				Description: "If used with ZTNA",
			},
			"a": {
				Type:        schema.TypeSet,
				Computed:    true,
				Description: "Set (unordered list) of IPv4 A records",
				Elem: &schema.Schema{
					Type: schema.TypeString, // Assuming the A records are represented as strings
				},
			},
			"aaaa": {
				Type:        schema.TypeSet,
				Computed:    true,
				Description: "Set (unordered list) of IPv6 AAAA records",
				Elem: &schema.Schema{
					Type: schema.TypeString, // Assuming the AAAA records are represented as strings
				},
			},
		},
	}
}

// Define the read function for routes
func dataSourceMappingsRead(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {

	req, err := http.NewRequest("GET", fmt.Sprintf("https://radar.wandera.com/gate/dns-zone-management-service/v1/custom-hostname-mappings"), nil)
	if err != nil {
		return diag.FromErr(fmt.Errorf("error converting making http request body"))
	}
	resp, err := auth.MakeRequest((req))

	if err != nil {
		return diag.FromErr(fmt.Errorf("error making http request"))
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

	var response Mappings
	err = json.Unmarshal(body, &response)
	if err != nil {
		return diag.FromErr(err)
	}

	// Print the parsed struct
	fmt.Printf("Parsed struct: %+v\n", response)

	// Find id from the first instance where name contains "the provided name"

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
