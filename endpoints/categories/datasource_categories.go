package categories

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
type Categories struct {
    ID              string `json:"id"`
    Name         	string `json:"name"`
	DisplayName	    string `json:"displayName"`
    } 


func DataSourceCategories() *schema.Resource {
    return &schema.Resource{
		ReadContext: dataSourceCategoriesRead,

		Schema: map[string]*schema.Schema{
			"name": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "The ID of the category",
			},
			"id": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "The unique identifier of the category",
			},
            "displayname": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "The route display name of the category",
			},
		},
	}
}

// Define the read function for routes
func dataSourceCategoriesRead(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
    //routeName := d.Get("name").(string)

    
	req, err := http.NewRequest("GET", fmt.Sprintf("https://radar.wandera.com/gate/content-block-service/v1/customers/{customerid}/categories"), nil)
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


	
	var response []Categories
	err = json.Unmarshal(body, &response)
	if err != nil {
		return diag.FromErr(err)
	}

		// Find id from the first instance where name contains "the provided name"

		for _, category := range response {
			if strings.EqualFold(category.DisplayName, d.Get("displayname").(string)) {
				d.Set("name", category.Name)
				d.SetId(category.ID) //need to set something for resource to exist
				break
			}
		}

	


    return nil
}