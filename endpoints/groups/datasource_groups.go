// Copyright 2025, Jamf Software LLC.
package groups

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

// Group represents a device group from the user-service API
type Group struct {
	Group          *string `json:"group"`   // nullable for ungrouped devices
	GroupId        *string `json:"groupId"` // nullable for ungrouped devices
	Devices        int64   `json:"devices"`
	DeletedDevices int64   `json:"deletedDevices"`
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

// Define the read function for groups
func dataSourceGroupsRead(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	req, err := http.NewRequest("GET", "https://radar.wandera.com/gate/user-service/user/v3/{customerid}/groups?showDeleted=false", nil)
	if err != nil {
		return diag.FromErr(fmt.Errorf("error creating http request: %v", err))
	}
	resp, err := auth.MakeRequest(req)

	if err != nil {
		return diag.FromErr(err)
	}
	defer resp.Body.Close()

	// Check the response status code
	if resp.StatusCode != http.StatusOK {
		return diag.FromErr(fmt.Errorf("failed to read groups info: %s", resp.Status))
	}

	// Read the response body
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return diag.FromErr(fmt.Errorf("error parsing body response: %v", err))
	}

	// Parse the response JSON
	var response []Group
	err = json.Unmarshal(body, &response)
	if err != nil {
		return diag.FromErr(err)
	}

	// Find group by name (case-insensitive match)
	searchName := d.Get("name").(string)
	for _, group := range response {
		// Skip entries with null group name (ungrouped devices)
		if group.Group == nil || group.GroupId == nil {
			continue
		}
		if strings.EqualFold(*group.Group, searchName) {
			d.Set("name", *group.Group)
			d.SetId(*group.GroupId)
			d.Set("devices", group.Devices)
			return nil
		}
	}

	return diag.FromErr(fmt.Errorf("group not found: %s", searchName))
}
