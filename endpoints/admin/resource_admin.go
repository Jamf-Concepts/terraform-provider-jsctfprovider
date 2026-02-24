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
	EntityType           string                    `json:"entityType"`
	EntityId             string                    `json:"entityId"`
	Profile              adminProfile              `json:"profile"`
	Authentication       adminAuthentication       `json:"authentication"`
	Authorization        adminAuthorization        `json:"authorization"`
	NotificationSettings adminNotificationSettings `json:"notificationSettings"`
}

type adminListResponse struct {
	Page       int             `json:"page"`
	PageSize   int             `json:"pageSize"`
	TotalCount int             `json:"totalCount"`
	Data       []adminResponse `json:"data"`
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
			Roles:       toStringSlice(d.Get("roles").(*schema.Set).List()),
			Permissions: toStringSlice(d.Get("permissions").(*schema.Set).List()),
		},
		NotificationSettings: adminNotificationSettings{
			SubscribedNotificationCategories: toStringSlice(d.Get("notification_categories").(*schema.Set).List()),
		},
	}
}

// suppressPermissionDiffForSuperAdmin prevents drift detection on permissions
// when SUPER_ADMIN role is present, since the API auto-grants all permissions
// regardless of what is sent in the request.
func suppressPermissionDiffForSuperAdmin(k, oldValue, newValue string, d *schema.ResourceData) bool {
	rolesSet := d.Get("roles").(*schema.Set)
	roles := rolesSet.List()

	// Check if SUPER_ADMIN is in the roles set
	for _, role := range roles {
		if role.(string) == "SUPER_ADMIN" {
			// If SUPER_ADMIN role is present, suppress all permission diffs
			// The API manages permissions automatically for this role
			return true
		}
	}

	// No SUPER_ADMIN role - allow normal diff detection
	return false
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
				Type:        schema.TypeSet,
				Elem:        &schema.Schema{Type: schema.TypeString},
				Optional:    true,
				Description: "Roles assigned to the admin. Empty set = read-only. Known elevated roles: SUPER_ADMIN, GLOBAL_ADMIN, MAGIC.",
			},
			"permissions": {
				Type:             schema.TypeSet,
				Elem:             &schema.Schema{Type: schema.TypeString},
				Optional:         true,
				DiffSuppressFunc: suppressPermissionDiffForSuperAdmin,
				Description:      "Permissions granted to the admin. Not required if role is SUPER_ADMIN. Known values: DEVICES, ACCESS, SETTINGS, SECURITY, AUDIT_LOGS, USER_SUMMARY, CHANGE_PASSWORD_IN_RADAR.",
			},
			"sso_enabled": {
				Type:        schema.TypeBool,
				Optional:    true,
				Default:     false,
				Description: "Whether SSO is enabled for this admin account. Defaults to false (local auth).",
			},
			"notification_categories": {
				Type:        schema.TypeSet,
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

	// The API returns an empty body on successful creation.
	// We need to list admins with pagination to find the newly created admin and get its ID.
	if len(body) == 0 || string(body) == "" {
		username := d.Get("username").(string)

		// List admins with pagination to find the newly created admin
		// Note: Don't add query params here - auth.MakeRequest adds customerId and will break the URL
		listReq, err := http.NewRequest("GET", "https://radar.wandera.com/gate/admin-service/v4/customers/{customerid}/admins", nil)
		if err != nil {
			return fmt.Errorf("failed to build admin list request: %v", err)
		}

		// Manually construct query string with pagination params
		q := listReq.URL.Query()
		q.Add("page", "0")
		q.Add("pageSize", "100")
		listReq.URL.RawQuery = q.Encode()

		listResp, err := auth.MakeRequest(listReq)
		if err != nil {
			return fmt.Errorf("admin list request failed: %v", err)
		}
		defer listResp.Body.Close()

		if listResp.StatusCode != http.StatusOK {
			return fmt.Errorf("failed to list admins: %s", listResp.Status)
		}

		listBody, err := ioutil.ReadAll(listResp.Body)
		if err != nil {
			return fmt.Errorf("failed to read admin list response: %v", err)
		}

		var listResponse adminListResponse
		if err := json.Unmarshal(listBody, &listResponse); err != nil {
			return fmt.Errorf("failed to parse admin list response: %v", err)
		}

		// Find our admin by username
		var adminID string
		for _, admin := range listResponse.Data {
			if admin.Authentication.Username == username {
				adminID = admin.ID
				break
			}
		}

		if adminID == "" {
			return fmt.Errorf("admin was created but could not be found in the list (username: %s)", username)
		}

		// Set the real admin ID
		d.SetId(adminID)
		return nil
	}

	// If we got a body with JSON, parse it
	var response struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(body, &response); err != nil {
		return fmt.Errorf("failed to parse jsc_admin create response: %v (body was: %s)", err, string(body))
	}

	if response.ID == "" {
		return fmt.Errorf("jsc_admin was created but API returned an empty ID")
	}

	d.SetId(response.ID)
	return nil
}

func resourceAdminRead(d *schema.ResourceData, m interface{}) error {
	// List admins with pagination to find ours by ID
	req, err := http.NewRequest("GET", "https://radar.wandera.com/gate/admin-service/v4/customers/{customerid}/admins", nil)
	if err != nil {
		return fmt.Errorf("failed to build admin list request: %v", err)
	}

	// Add pagination query params properly
	q := req.URL.Query()
	q.Add("page", "0")
	q.Add("pageSize", "100")
	req.URL.RawQuery = q.Encode()

	resp, err := auth.MakeRequest(req)
	if err != nil {
		return fmt.Errorf("admin list request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("failed to list admins: %s", resp.Status)
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read admin list response: %v", err)
	}

	var listResponse adminListResponse
	if err := json.Unmarshal(body, &listResponse); err != nil {
		return fmt.Errorf("failed to parse admin list response: %v", err)
	}

	// Find our admin by ID
	adminID := d.Id()

	for _, admin := range listResponse.Data {
		if admin.ID == adminID {
			// Found it! Update all fields
			d.Set("name", admin.Profile.Name)
			d.Set("username", admin.Authentication.Username)
			d.Set("sso_enabled", admin.Authentication.SSO.Enabled)
			d.Set("roles", admin.Authorization.Roles)
			d.Set("permissions", admin.Authorization.Permissions)
			d.Set("notification_categories", admin.NotificationSettings.SubscribedNotificationCategories)
			return nil
		}
	}

	// Not found - resource has been deleted outside Terraform
	d.SetId("")
	return nil
}

func resourceAdminUpdate(d *schema.ResourceData, m interface{}) error {
	adminID := d.Id()

	payload, err := json.Marshal(buildAdminRequest(d))
	if err != nil {
		return fmt.Errorf("failed to marshal jsc_admin update payload: %v", err)
	}

	req, err := http.NewRequest("PUT", fmt.Sprintf("https://radar.wandera.com/gate/admin-service/v4/customers/{customerid}/admins/%s", adminID), bytes.NewBuffer(payload))
	if err != nil {
		return fmt.Errorf("failed to build jsc_admin update request: %v", err)
	}

	resp, err := auth.MakeRequest(req)
	if err != nil {
		return fmt.Errorf("jsc_admin update request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		body, _ := ioutil.ReadAll(resp.Body)
		return fmt.Errorf("failed to update jsc_admin: %s (response: %s)", resp.Status, string(body))
	}

	// Read back the updated state
	return resourceAdminRead(d, m)
}

func resourceAdminDelete(d *schema.ResourceData, m interface{}) error {
	// Use the admin ID directly (retrieved during create/read)
	adminID := d.Id()

	req, err := http.NewRequest("DELETE", fmt.Sprintf("https://radar.wandera.com/gate/admin-service/v4/customers/{customerid}/admins/%s", adminID), nil)
	if err != nil {
		return fmt.Errorf("failed to build jsc_admin delete request: %v", err)
	}

	resp, err := auth.MakeRequest(req)
	if err != nil {
		return fmt.Errorf("jsc_admin delete request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusNotFound {
		return fmt.Errorf("failed to delete jsc_admin: %s", resp.Status)
	}

	d.SetId("")
	return nil
}
