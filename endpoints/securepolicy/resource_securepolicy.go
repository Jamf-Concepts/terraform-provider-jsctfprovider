// Copyright 2025, Jamf Software LLC.
package securepolicy

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/validation"
	"jsctfprovider/internal/auth"
)

// securePolicyThreat represents a single threat category entry in the secure policy payload.
// Only the fields required for read/write are declared here; the rest are captured in raw JSON
// and passed through unchanged so the full payload round-trips cleanly.
type securePolicyThreat struct {
	ThreatCategoryID string          `json:"threatCategoryId"`
	Action           threatAction    `json:"action"`
	RawRest          json.RawMessage `json:"-"` // not serialised — see marshalThreats
}

type threatAction struct {
	Response            string                 `json:"response"`
	NotificationPolicy  map[string]interface{} `json:"notificationPolicy"`
	ReportingPolicy     threatReportingPolicy  `json:"reportingPolicy"`
	AnalysisPolicy      map[string]interface{} `json:"analysisPolicy"`
}

type threatReportingPolicy struct {
	Types             []interface{} `json:"types"`
	DeviceDelay       string        `json:"deviceDelay"`
	AffectsDeviceRisk bool          `json:"affectsDeviceRisk"`
	Severity          string        `json:"severity"`
}

// securePolicyPayload mirrors the top-level structure returned by GET and accepted by PUT.
// threatCategories is kept as raw JSON so that all 49 threat entries are round-tripped
// without losing unknown fields.
type securePolicyPayload struct {
	SummaryNotificationPolicy map[string]interface{} `json:"summaryNotificationPolicy"`
	CustomerConfiguration     map[string]interface{} `json:"customerConfiguration"`
	ThreatCategories          json.RawMessage        `json:"threatCategories"`
	GroupPolicyOverrides      interface{}            `json:"groupPolicyOverrides"`
}

const securePolicyBaseURL = "https://radar.wandera.com/gate/secure-policy-service/v1/secure-policies/customers/{customerid}"

// validSeverities is the set of accepted severity strings.
var validSeverities = []string{"HIGHEST", "HIGH", "MEDIUM", "LOW", "INFO"}

// ResourceSecurePolicy returns the schema.Resource for jsc_secure_policy.
func ResourceSecurePolicy() *schema.Resource {
	return &schema.Resource{
		Create: resourceSecurePolicyCreate,
		Read:   resourceSecurePolicyRead,
		Update: resourceSecurePolicyUpdate,
		Delete: resourceSecurePolicyDelete,

		Schema: map[string]*schema.Schema{
			// Each exposed override follows the pattern:
			//   <threat_category_id_lowercase>_severity
			// Add additional overrides here as needed in the future.
			"os_outdated_os_low_severity": {
				Type:         schema.TypeString,
				Optional:     true,
				Default:      "MEDIUM",
				Description:  "Severity override for the OS_OUTDATED_OS_LOW threat category (Vulnerable OS - Minor). Valid values: HIGHEST, HIGH, MEDIUM, LOW, INFO. Defaults to MEDIUM (tenant default).",
				ValidateFunc: validation.StringInSlice(validSeverities, false),
			},
		},
	}
}

// getPolicy fetches the current secure policy from the API and returns the raw body bytes.
func getPolicy() ([]byte, error) {
	req, err := http.NewRequest("GET", securePolicyBaseURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to build jsc_secure_policy GET request: %v", err)
	}

	resp, err := auth.MakeRequest(req)
	if err != nil {
		return nil, fmt.Errorf("jsc_secure_policy GET request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("jsc_secure_policy GET returned unexpected status: %s", resp.Status)
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read jsc_secure_policy GET response body: %v", err)
	}

	return body, nil
}

// applyOverrides mutates the ThreatCategories raw JSON in place, applying any severity
// overrides specified in the Terraform config.  All other fields in every threat entry
// are preserved exactly as received from the API.
func applyOverrides(raw json.RawMessage, overrides map[string]string) (json.RawMessage, error) {
	// Unmarshal into a slice of generic maps so every field is preserved.
	var threats []map[string]interface{}
	if err := json.Unmarshal(raw, &threats); err != nil {
		return nil, fmt.Errorf("failed to parse threatCategories: %v", err)
	}

	for i, threat := range threats {
		id, _ := threat["threatCategoryId"].(string)
		newSeverity, ok := overrides[id]
		if !ok {
			continue
		}

		// Navigate action → reportingPolicy → severity, creating intermediate maps
		// if they are unexpectedly missing so we never panic.
		action, ok := threat["action"].(map[string]interface{})
		if !ok {
			return nil, fmt.Errorf("jsc_secure_policy: threat %q has unexpected 'action' structure", id)
		}

		reportingPolicy, ok := action["reportingPolicy"].(map[string]interface{})
		if !ok {
			return nil, fmt.Errorf("jsc_secure_policy: threat %q has unexpected 'action.reportingPolicy' structure", id)
		}

		reportingPolicy["severity"] = newSeverity
		action["reportingPolicy"] = reportingPolicy
		threat["action"] = action
		threats[i] = threat
	}

	updated, err := json.Marshal(threats)
	if err != nil {
		return nil, fmt.Errorf("failed to re-marshal threatCategories after applying overrides: %v", err)
	}

	return updated, nil
}

// putPolicy applies the provided severity overrides to the current policy and PUTs it back.
func putPolicy(overrides map[string]string) error {
	body, err := getPolicy()
	if err != nil {
		return err
	}

	var payload securePolicyPayload
	if err := json.Unmarshal(body, &payload); err != nil {
		return fmt.Errorf("failed to parse jsc_secure_policy response: %v", err)
	}

	updatedThreats, err := applyOverrides(payload.ThreatCategories, overrides)
	if err != nil {
		return err
	}
	payload.ThreatCategories = updatedThreats

	putBody, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal jsc_secure_policy PUT payload: %v", err)
	}

	req, err := http.NewRequest("PUT", securePolicyBaseURL, bytes.NewBuffer(putBody))
	if err != nil {
		return fmt.Errorf("failed to build jsc_secure_policy PUT request: %v", err)
	}

	resp, err := auth.MakeRequest(req)
	if err != nil {
		return fmt.Errorf("jsc_secure_policy PUT request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		respBody, _ := ioutil.ReadAll(resp.Body)
		return fmt.Errorf("jsc_secure_policy PUT returned unexpected status: %s — %s", resp.Status, string(respBody))
	}

	return nil
}

// buildOverrides converts Terraform resource data into the overrides map expected by putPolicy.
func buildOverrides(d *schema.ResourceData) map[string]string {
	return map[string]string{
		"OS_OUTDATED_OS_LOW": d.Get("os_outdated_os_low_severity").(string),
	}
}

func resourceSecurePolicyCreate(d *schema.ResourceData, m interface{}) error {
	if err := putPolicy(buildOverrides(d)); err != nil {
		return err
	}

	// Singleton: use a fixed string as the resource ID since there is exactly
	// one secure policy per JSC customer and no per-resource ID is returned.
	d.SetId("secure_policy")
	return nil
}

func resourceSecurePolicyRead(d *schema.ResourceData, m interface{}) error {
	body, err := getPolicy()
	if err != nil {
		return err
	}

	var payload securePolicyPayload
	if err := json.Unmarshal(body, &payload); err != nil {
		return fmt.Errorf("failed to parse jsc_secure_policy read response: %v", err)
	}

	var threats []map[string]interface{}
	if err := json.Unmarshal(payload.ThreatCategories, &threats); err != nil {
		return fmt.Errorf("failed to parse threatCategories on read: %v", err)
	}

	for _, threat := range threats {
		id, _ := threat["threatCategoryId"].(string)

		switch id {
		case "OS_OUTDATED_OS_LOW":
			severity, err := extractSeverity(threat, id)
			if err != nil {
				return err
			}
			if err := d.Set("os_outdated_os_low_severity", severity); err != nil {
				return fmt.Errorf("failed to set os_outdated_os_low_severity in state: %v", err)
			}
		}
		// Add additional case blocks here as more overrides are introduced.
	}

	return nil
}

func resourceSecurePolicyUpdate(d *schema.ResourceData, m interface{}) error {
	if err := putPolicy(buildOverrides(d)); err != nil {
		return err
	}
	return resourceSecurePolicyRead(d, m)
}

func resourceSecurePolicyDelete(d *schema.ResourceData, m interface{}) error {
	// "Delete" restores the managed overrides to their tenant defaults.
	// OS_OUTDATED_OS_LOW default severity is MEDIUM.
	defaults := map[string]string{
		"OS_OUTDATED_OS_LOW": "MEDIUM",
	}

	if err := putPolicy(defaults); err != nil {
		return err
	}

	d.SetId("")
	return nil
}

// extractSeverity is a helper that safely navigates action → reportingPolicy → severity
// for the given threat entry, returning a clear error if the structure is unexpected.
func extractSeverity(threat map[string]interface{}, id string) (string, error) {
	action, ok := threat["action"].(map[string]interface{})
	if !ok {
		return "", fmt.Errorf("jsc_secure_policy: threat %q has unexpected 'action' structure on read", id)
	}

	reportingPolicy, ok := action["reportingPolicy"].(map[string]interface{})
	if !ok {
		return "", fmt.Errorf("jsc_secure_policy: threat %q has unexpected 'action.reportingPolicy' structure on read", id)
	}

	severity, ok := reportingPolicy["severity"].(string)
	if !ok {
		return "", fmt.Errorf("jsc_secure_policy: threat %q has unexpected 'action.reportingPolicy.severity' type on read", id)
	}

	return severity, nil
}
