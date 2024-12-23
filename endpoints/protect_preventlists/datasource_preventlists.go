package protectpreventlists

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"

	"jsctfprovider/internal/auth"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

type Response struct {
	Data struct {
		GetPreventList PreventList `json:"getPreventList"`
	} `json:"data"`
}

type PreventList struct {
	ID          string   `json:"id"`
	Created     string   `json:"created"`
	Name        string   `json:"name"`
	Type        string   `json:"type"`
	List        []string `json:"list"`
	Description string   `json:"description"`
}

func DataSourcePreventlists() *schema.Resource {
	return &schema.Resource{
		ReadContext: dataSourcePreventlistsRead,

		Schema: map[string]*schema.Schema{
			"name": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "The name of the prevent list",
			},
			"id": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "The unique identifier of the prevent list",
			},
			"type": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "The type of the prevent list",
			},
			"description": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "The description of the prevent list",
			},
			"list": {
				Type:        schema.TypeList,
				Elem:        &schema.Schema{Type: schema.TypeString},
				Computed:    true,
				Description: "The list of the prevent list",
			},
		},
	}
}

func dataSourcePreventlistsRead(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	graphpayload := "{\"query\":\"query getPreventList {getPreventList(id: \\\"" + d.Get("id").(string) + "\\\") {id,created,name,type,list,description}}\"}"

	req, err := http.NewRequest("POST", "https://protecturl/graphql", strings.NewReader(graphpayload))
	if err != nil {
		return diag.FromErr(fmt.Errorf("error converting making http request body"))
	}
	resp, err := auth.MakeProtectRequest((req))

	if err != nil {
		return diag.FromErr(err)
	}
	defer resp.Body.Close()

	bodyread, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		fmt.Println("Error:", err)
		return nil
	}
	fmt.Println("Response body:", string(bodyread))
	// Check the response status code
	if resp.StatusCode != http.StatusOK {
		return diag.FromErr(fmt.Errorf("failed to read preventlists info: %s", resp.Status))
	}

	// Parse the response JSON if needed
	// (this depends on the structure of the API response)
	fmt.Print("nxt is string of body.. come onnnn.")
	//fmt.Println(string(body))

	// Create a variable to hold the unmarshalled response
	var response Response

	// Unmarshal the JSON data into the struct
	errjsonmarshal := json.Unmarshal(bodyread, &response)
	if errjsonmarshal != nil {

		return diag.FromErr(errjsonmarshal)
	}
	d.Set("name", response.Data.GetPreventList.Name)
	fmt.Println("is there a name?")
	fmt.Println(response.Data.GetPreventList.Name)
	fmt.Println("is there a description?")
	d.Set("description", response.Data.GetPreventList.Description)
	fmt.Println(response.Data.GetPreventList.Description)
	fmt.Println("is there a type?")
	d.Set("type", response.Data.GetPreventList.Type)
	fmt.Println(response.Data.GetPreventList.Type)
	d.SetId(response.Data.GetPreventList.ID)

	return nil
}
