package protectpreventlists

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"jsctfprovider/internal/auth"
	"net/http"
	"strings"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

type ResponseCreate struct {
	Data struct {
		PreventListCreate PreventList `json:"createPreventList"`
	} `json:"data"`
}

type PreventListCreate struct {
	ID          string   `json:"id"`
	Created     string   `json:"created"`
	Name        string   `json:"name"`
	Type        string   `json:"type"`
	List        []string `json:"list"`
	Description string   `json:"description"`
}

// Resource definition (this is where you'll manage state, create/update resources)
func ResourcePreventlists() *schema.Resource {
	return &schema.Resource{
		Create: resourceExampleCreate,
		Read:   resourceExampleRead,
		Update: resourceExampleUpdate,
		Delete: resourceExampleDelete,

		Schema: map[string]*schema.Schema{
			"name": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "The name identifier of the prevent list",
			},
			"id": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "The unique identifier of the prevent list",
			},
			"type": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "The type of the prevent list. SIGNINGID, CDHASH, FILEHASH, or TEAMID are the only acceptable values",
				ValidateFunc: func(val interface{}, key string) (warns []string, errs []error) {
					validValues := []string{"CDHASH", "TEAMID", "FILEHASH", "SIGNINGID"}
					value := val.(string)

					// Check if the value is valid
					isValid := false
					for _, validValue := range validValues {
						if value == validValue {
							isValid = true
							break
						}
					}

					if !isValid {
						errs = append(errs, fmt.Errorf("%s must be one of %v", key, validValues))
					}

					return warns, errs
				},
			},
			"description": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "The description of the prevent list",
			},
			"list": {
				Type:        schema.TypeList,
				Elem:        &schema.Schema{Type: schema.TypeString},
				Optional:    true,
				Description: "The list of the prevent list",
			},
		},
	}
}

func resourceExampleCreate(d *schema.ResourceData, m interface{}) error {
	// Create the resource (for example, make an API call to create the resource)
	name := d.Get("name").(string)
	typevar := d.Get("type").(string)
	description := d.Get("description").(string)

	fmt.Printf("Creating resource with name: %s\n", name)
	fmt.Printf("Creating resource with type: %s\n", typevar)
	fmt.Printf("Creating resource with description: %s\n", description)
	listsInterface := d.Get("list").([]interface{}) // Get the raw slice of interfaces

	// Now convert each element of the slice to a string
	list := make([]string, len(listsInterface)) // Create a string slice with the same length

	for i, v := range listsInterface {
		list[i] = "\\\"" + v.(string) + "\\\"" // Assert each element as a string
	}
	fmt.Printf("Creating resource with list: %s\n", list)

	//graphpayload := "{\"query\":\"mutation createpeeventlist { createPreventList(    input:  {     name: \\\"" + name + "\\\"    description: \\\"" + description + "\\\"     tags: []      type: " + typevar + "      list: [\\\"test\\\",\\\"test2\\\"]     }){name    description    id    type  }}\",\"variables\":{}}"
	//fmt.Printf(graphpayload)
	graphpayloadnew := "{\"query\":\"mutation createpeeventlist { createPreventList(    input:  {     name: \\\"" + name + "\\\"    description: \\\"" + description + "\\\"     tags: []      type: " + typevar + "      list: [" + strings.Join(list, ", ") + "]     }){name    description    id    type  }}\",\"variables\":{}}"
	//fmt.Printf(graphpayloadnew)
	req, err := http.NewRequest("POST", "https://protecturl/graphql", strings.NewReader(graphpayloadnew))
	if err != nil {
		return (fmt.Errorf("error converting making http request body"))
	}
	resp, err := auth.MakeProtectRequest((req))

	if err != nil {
		return err
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
		return (fmt.Errorf("failed to read preventlists info: %s", resp.Status))
	}

	// Create a variable to hold the unmarshalled response
	var response ResponseCreate

	// Unmarshal the JSON data into the struct
	errjsonmarshal := json.Unmarshal(bodyread, &response)
	if errjsonmarshal != nil {

		return (errjsonmarshal)
	}
	d.Set("name", response.Data.PreventListCreate.Name)
	fmt.Println("is there a name?")
	fmt.Println(response.Data.PreventListCreate.Name)
	fmt.Println("is there a description?")
	d.Set("description", response.Data.PreventListCreate.Description)
	fmt.Println(response.Data.PreventListCreate.Description)
	fmt.Println("is there a type?")
	d.Set("type", response.Data.PreventListCreate.Type)
	fmt.Println(response.Data.PreventListCreate.Type)
	d.SetId(response.Data.PreventListCreate.ID)
	return nil
	//return resourceExampleRead(d, m)
}

func resourceExampleRead(d *schema.ResourceData, m interface{}) error {
	// Read the resource data (e.g., make an API call to fetch resource details)
	resourceid := d.Id()
	fmt.Printf("Reading resource with ID: %s\n", resourceid)

	graphpayload := "{\"query\":\"query getPreventList {getPreventList(id: \\\"" + d.Get("id").(string) + "\\\") {id,created,name,type,list,description}}\"}"

	req, err := http.NewRequest("POST", "https://protecturl/graphql", strings.NewReader(graphpayload))
	if err != nil {
		return (fmt.Errorf("error converting making http request body"))
	}
	resp, err := auth.MakeProtectRequest((req))

	if err != nil {
		return (err)
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
		return (fmt.Errorf("failed to read preventlists info: %s", resp.Status))
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

		return (errjsonmarshal)
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

func resourceExampleUpdate(d *schema.ResourceData, m interface{}) error {
	// Update the resource (e.g., make an API call to update the resource)
	name := d.Get("name").(string)
	typevar := d.Get("type").(string)
	description := d.Get("description").(string)

	fmt.Printf("Updating resource with name: %s\n", name)
	fmt.Printf("Updating resource with type: %s\n", typevar)
	fmt.Printf("Updating resource with description: %s\n", description)
	listsInterface := d.Get("list").([]interface{}) // Get the raw slice of interfaces

	// Now convert each element of the slice to a string
	list := make([]string, len(listsInterface)) // Create a string slice with the same length

	for i, v := range listsInterface {
		list[i] = "\\\"" + v.(string) + "\\\"" // Assert each element as a string
	}
	fmt.Printf("Updating resource with list: %s\n", list)
	graphpayload := "{\"query\":\"mutation updatePreventList {  updatePreventList(  input:  {    name: \\\"" + name + "\\\"      description: \\\"" + description + "\\\"      tags: []     type: " + typevar + "      list: [" + strings.Join(list, ", ") + "]      }  id: \\\"" + d.Id() + "\\\"){id  }}\",\"variables\":{}}"
	//fmt.Printf(graphpayload)
	req, err := http.NewRequest("POST", "https://protecturl/graphql", strings.NewReader(graphpayload))
	if err != nil {
		return (fmt.Errorf("error converting making http request body"))
	}
	resp, err := auth.MakeProtectRequest((req))

	if err != nil {
		return err
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
		return (fmt.Errorf("failed to update preventlists info: %s", resp.Status))
	}

	return resourceExampleRead(d, m)
}

func resourceExampleDelete(d *schema.ResourceData, m interface{}) error {
	// Delete the resource (e.g., make an API call to delete the resource)
	name := d.Get("name").(string)
	fmt.Printf("Deleting resource with name: %s\n", name)
	fmt.Printf("Deleting resource with ID: %s\n", d.Id())

	// Delete logic here (if needed)

	graphpayload := "{\"query\":\"mutation deletePreventList {  deletePreventList(id: \\\"" + d.Id() + "\\\")  {name    description    id    type  }}\",\"variables\":{}}"

	req, err := http.NewRequest("POST", "https://protecturl/graphql", strings.NewReader(graphpayload))
	if err != nil {
		return (fmt.Errorf("error converting making http request body"))
	}
	resp, err := auth.MakeProtectRequest((req))

	if err != nil {
		return err
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
		return (fmt.Errorf("failed to delete preventlists info: %s", resp.Status))
	}
	// Remove resource from state
	d.SetId("")
	return nil
}
