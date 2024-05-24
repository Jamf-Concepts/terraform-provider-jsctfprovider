package routes

import (
	//"bytes"
	//"encoding/json"
	//"fmt"
	//"io/ioutil"
	//"net/http"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
    "context"
    "github.com/hashicorp/terraform-plugin-sdk/v2/diag"
    "log"
	//"jsctfprovider/internal/auth"
)

func DataSourceRoutes() *schema.Resource {
    return &schema.Resource{
		ReadContext: dataSourceRoutessRead,

		Schema: map[string]*schema.Schema{
			"name": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "The name of the route.",
			},
			"id": {
				Type:        schema.TypeInt,
				Computed:    true,
				Description: "The unique identifier of the route",
			},
            "routeid": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "The route identifier of the route",
			},
            "datacenter": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "The datacenter of the route",
			},
            "shared": {
				Type:        schema.TypeBool,
				Computed:    true,
				Description: "If the route is shared or not",
			},
		},
	}
}

// Define the read function for routes
func dataSourceRoutessRead(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
    //routeName := d.Get("name").(string)

    // dummy ID for testing
    d.Set("id", 99999999) //doesn't work
    d.SetId("9999999998")
    d.Set("routeid", "aaZZ")
    log.Println("[INFO] I AM THE dataresourcedebug")


    return nil
}