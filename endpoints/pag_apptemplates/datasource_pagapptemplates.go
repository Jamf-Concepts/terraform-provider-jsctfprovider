package pagapptemplates

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

type ResponseItemAppTemplates struct {
	ID        string   `json:"id"`
	Name      string   `json:"name"`
	Hostnames []string `json:"hostnames"`
}

func DataSourcePAGAppTemplates() *schema.Resource {
	return &schema.Resource{
		ReadContext: dataSourcePAGAppTemplatesRead,

		Schema: map[string]*schema.Schema{
			"name": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "The name of the App Template",
			},
			"id": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "The unique identifier of the App Template datasource set from JSC",
			},
			"hostnames": {
				Type:        schema.TypeList,
				Elem:        &schema.Schema{Type: schema.TypeString},
				Computed:    true,
				Description: "List of hostnames",
			},
		},
	}
}

// Define the read function for routes
func dataSourcePAGAppTemplatesRead(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {

	req, err := http.NewRequest("GET", ("https://api.wandera.com/ztna/v1/app-templates"), nil)
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

	var response []ResponseItemAppTemplates
	err = json.Unmarshal(body, &response)
	if err != nil {
		return diag.FromErr(err)
	}

	// Find id from the first instance where name contains "the provided name"

	for _, ip := range response {
		if strings.Contains(ip.Name, d.Get("name").(string)) {
			d.SetId(ip.ID)
			d.Set("hostnames", ip.Hostnames)
			d.Set("name", ip.Name)
			break
		}
	}

	return nil
}
