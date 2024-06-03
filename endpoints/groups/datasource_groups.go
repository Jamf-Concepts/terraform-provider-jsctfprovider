package groups

import (
	//"bytes"
	//"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"encoding/json"
	"strings"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
    "context"
    "github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"jsctfprovider/internal/auth"
)
//define type of route - don't use much but nice to keep for future use
type Groups struct {
    ID              string `json:"id"`
    Name         	string `json:"name"`
	Devices	 	    int64 `json:"devices"`
    } 


func DataSourceGroups() *schema.Resource {
    return &schema.Resource{
		ReadContext: dataSourceGroupsRead,

		Schema: map[string]*schema.Schema{
			"devices": {
				Type:        schema.TypeInt,
				Computed:    true,
				Description: "The number of devices in group",
			},
			"id": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "The unique identifier of the group (from JSC)",
			},
            "name": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "The display name of the group in JSC",
			},
		},
	}
}

// Define the read function for routes
func dataSourceGroupsRead(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
    //routeName := d.Get("name").(string)

    
	req, err := http.NewRequest("GET", fmt.Sprintf("https://radar.wandera.com/api/groups"), nil)
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


	
	var response []Groups
	err = json.Unmarshal(body, &response)
	if err != nil {
		return diag.FromErr(err)
	}

		// Find id from the first instance where name contains "the provided name"

		for _, groups := range response {
			if strings.EqualFold(groups.Name, d.Get("name").(string)) {
				d.Set("name", groups.Name)
				d.SetId(groups.ID) 
				d.Set("devices", groups.Devices)
				break
			}
		}

	


    return nil
}