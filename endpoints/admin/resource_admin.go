// Copyright 2025, Jamf Software LLC.
package admin

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"jsctfprovider/internal/auth"
)

type adminProfile struct {
	Name string `json:"name"`
}

type adminSSO struct {
	Enabled bool `json:"enabled"`
}

type adminAuthentication struct {
	Username string   `json:"username"`
	SSO      adminSSO `json:"sso"`
}

type adminAuthorization struct {
	Permissions []string `json:"permissions"`
	Roles       []string `json:"roles"`
}

type adminNotificationSettings struct {
	SubscribedNotificationCategories []string `json:"subscribedNotificationCategories"`
}

type adminRequest struct {
	Profile              adminProfile              `json:"profile"`
	Authentication       adminAuthentication       `json:"authentication"`
	Authorization        adminAuthorization        `json:"authorization"`
	NotificationSettings adminNotificationSettings `json:"notificationSettings"`
}

type adminResponse struct {
	ID                   string                    `json:"id"`
	Profile              adminProfile              `json:"profile"`
	Authentication       adminAuthentication       `json:"authentication"`
	Authorization        adminAuthorization        `json:"authorization"`
	NotificationSettings adminNotificationSettings `json:"notificationSettings"`
}

func toStringSlice(in []interface{}) []string {
	out := make([]string, len(in))
	for i, v := range in {
		out[i] = v.(string)
	}
	return out
}

func buildAdminRequest(d *schema.ResourceData) adminRequest {
	return adminRequest{
		Profile: adminProfile{
			Name: d.Get("name").(string),
		},
		Authentication: adminAuthentication{
			Username: d.Get("username").(string),
			SSO:      adminSSO{Enabled: d.Get("sso_enabled").(bool)},
		},
		Authorization: adminAuthorization{
			Roles:       toStringSlice(d.Get("roles").([]interface{})),
			Permissions: toStringSlice(d.Get("permissions").([]interface{})),
		},
		NotificationSettings: adminNotificationSettings{
			SubscribedNotificationCategories: toStringSlice(d.Get("notification_categories").([]interface{})),
		},
	}
}

// ResourceAdmin returns the schema.Resource for jsc_admin.
func ResourceAdmin() *schema.Resource {
	return &schema.Resource{
		Create: resourceAdminCreate,
		Read:   resourceAdminRead,
		Update: resourceAdminUpdate,
		Delete: resourceAdminDelete,

		Schema: map[string]*schema.Schema{
			"name": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Display name for the admin account.",
			},
			"username": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Username (email address) for the admin account.",
			},
			"roles": {
				Type:        schema.TypeList,
				Elem:        &schema.Schema{Type: schema.TypeString},
				Required:    true,
				Description: "Roles assigned to the admin. Known values: WRITE_ADMIN, SUPER_ADMIN, GLOBAL_ADMIN, MAGIC.",
			},
			"permissions": {
				Type:        schema.TypeList,
				Elem:        &schema.Schema{Type: schema.TypeString},
				Required:    true,
				Description: "Permissions granted to the admin. E.g. DEVICES, ACCESS, SETTINGS, SECURITY.",
			},
			"sso_enabled": {
				Type:        schema.TypeBool,
				Optional:    true,
				Default:     false,
				Description: "Whether SSO is enabled for this admin account. Defaults to false (local auth).",
			},
			"notification_categories": {
				Type:        schema.TypeList,
				Elem:        &schema.Schema{Type: schema.TypeString},
				Optional:    true,
				Description: "Notification categories to subscribe to. Known values: SECURITY, MOBILE_DATA, SERVICE_MANAGEMENT.",
			},
		},
	}
}

func resourceAdminCreate(d *schema.ResourceData, m interface{}) error {
	payload, err := json.Marshal(buildAdminRequest(d))
	if err != nil {
		return fmt.Errorf("failed to marshal jsc_admin payload: %v", err)
	}

	req, err := http.NewRequest("POST", "https://radar.wandera.com/gate/admin-service/v4/customers/{customerid}/admins", bytes.NewBuffer(payload))
	if err != nil {
		return fmt.Errorf("failed to build jsc_admin create request: %v", err)
	}

	resp, err := auth.MakeRequest(req)
	if err != nil {
		return fmt.Errorf("jsc_admin create request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		return fmt.Errorf("failed to create jsc_admin: %s", resp.Status)
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read jsc_admin create response: %v", err)
	}

	var response struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(body, &response); err != nil {
		return fmt.Errorf("failed to parse jsc_admin create response: %v", err)
	}

	if response.ID == "" {
		return fmt.Errorf("jsc_admin was created but API returned an empty ID")
	}

	d.SetId(response.ID)
	return nil
}

func resourceAdminRead(d *schema.ResourceData, m interface{}) error {
	req, err := http.NewRequest("GET", fmt.Sprintf("https://radar.wandera.com/gate/admin-service/v4/customers/{customerid}/admins/%s", d.Id()), nil)
	if err != nil {
		return fmt.Errorf("failed to build jsc_admin read request: %v", err)
	}

	resp, err := auth.MakeRequest(req)
	if err != nil {
		return fmt.Errorf("jsc_admin read request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		d.SetId("")
		return nil
	}

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("failed to read jsc_admin: %s", resp.Status)
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read jsc_admin read response: %v", err)
	}

	var response adminResponse
	if err := json.Unmarshal(body, &response); err != nil {
		return fmt.Errorf("failed to parse jsc_admin read response: %v", err)
	}

	d.Set("name", response.Profile.Name)
	d.Set("username", response.Authentication.Username)
	d.Set("sso_enabled", response.Authentication.SSO.Enabled)
	d.Set("roles", response.Authorization.Roles)
	d.Set("permissions", response.Authorization.Permissions)
	d.Set("notification_categories", response.NotificationSettings.SubscribedNotificationCategories)

	return nil
}

func resourceAdminUpdate(d *schema.ResourceData, m interface{}) error {
	if err := resourceAdminDelete(d, m); err != nil {
		return err
	}
	return resourceAdminCreate(d, m)
}

func resourceAdminDelete(d *schema.ResourceData, m interface{}) error {
	req, err := http.NewRequest("DELETE", fmt.Sprintf("https://radar.wandera.com/gate/admin-service/v4/customers/{customerid}/admins/%s", d.Id()), nil)
	if err != nil {
		return fmt.Errorf("failed to build jsc_admin delete request: %v", err)
	}

	resp, err := auth.MakeRequest(req)
	if err != nil {
		return fmt.Errorf("jsc_admin delete request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		return fmt.Errorf("failed to delete jsc_admin: %s", resp.Status)
	}

	d.SetId("")
	return nil
}
