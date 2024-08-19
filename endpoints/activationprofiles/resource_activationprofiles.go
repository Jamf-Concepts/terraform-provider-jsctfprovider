package activationprofiles

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"

	"jsctfprovider/internal/auth"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

// Define the struct for the JSON data
type RootCertificates struct {
	Enabled bool `json:"enabled"`
}

type LicencedAmalgam struct {
	ServiceCapabilityCombination []string `json:"serviceCapabilityCombination"`
	CloudProxy                   []string `json:"cloudProxy,omitempty"`
	Platforms                    []string `json:"platforms"`
	InAppDnsControl              []string `json:"inAppDnsControl"`
	RootCertificates             string   `json:"rootCertificates"`
	DefaultLocationServices      string   `json:"defaultLocationServices"`
}

type Management struct {
	EffectiveState *string `json:"effectiveState,omitempty"`
	LastUsed       *string `json:"lastUsed,omitempty"`
	TimeZone       string  `json:"timeZone"`
}

type Data struct {
	Code                      interface{}            `json:"code"`
	Name                      string                 `json:"name"`
	GroupId                   string                 `json:"groupId"`
	Used                      interface{}            `json:"used"`
	Management                Management             `json:"management"`
	DeviceMode                interface{}            `json:"deviceMode"`
	Passcode                  interface{}            `json:"passcode"`
	Errors                    map[string]interface{} `json:"errors"`
	ExtraDeviceAttributes     interface{}            `json:"extraDeviceAttributes"`
	ActiveTab                 string                 `json:"activeTab"`
	AvailableProxyInterfaces  []string               `json:"availableProxyInterfaces"`
	SecureDnsDefaultMandatory bool                   `json:"secureDnsDefaultMandatory"`
	LocationServices          string                 `json:"locationServices"`
	CloudProxy                string                 `json:"cloudProxy"`
	InAppDnsControl           string                 `json:"inAppDnsControl"`
	RootCertificates          RootCertificates       `json:"rootCertificates"`
	HasFailed                 bool                   `json:"hasFailed"`
	IsLoading                 bool                   `json:"isLoading"`
	IsSaving                  bool                   `json:"isSaving"`
	IsUpdating                bool                   `json:"isUpdating"`
	IsOptionsLoaded           bool                   `json:"isOptionsLoaded"`
	IsLoadingOptions          bool                   `json:"isLoadingOptions"`
	CanLeave                  bool                   `json:"canLeave"`
	LicencedAmalgams          []LicencedAmalgam      `json:"licencedAmalgams"`
	LicenceSpecifics          struct {
		EligibleForCloudProxy bool `json:"eligibleForCloudProxy"`
	} `json:"licenceSpecifics"`
	Idp struct {
		Type               string      `json:"type"`
		ConnectionId       string      `json:"connectionId"`
		ExternalIdAdoption interface{} `json:"externalIdAdoption"`
	} `json:"idp"`
	Capabilities struct {
		PrivateAccess struct {
			Enabled bool `json:"enabled"`
		} `json:"privateAccess"`
		ThreatDefence struct {
			Enabled bool `json:"enabled"`
		} `json:"threatDefence"`
		DataPolicy struct {
			Enabled bool `json:"enabled"`
		} `json:"dataPolicy"`
		DeviceIdentity struct {
			Enabled        bool     `json:"enabled"`
			TrustConsumers []string `json:"trustConsumers"`
		} `json:"deviceIdentity"`
		PhysicalAccess struct {
			Enabled bool `json:"enabled"`
		} `json:"physicalAccess"`
		Wireguard struct {
			Enabled bool `json:"enabled"`
		} `json:"wireguard"`
		Proxy struct {
			Enabled                     bool   `json:"enabled"`
			ControlledNetworkInterfaces string `json:"controlledNetworkInterfaces"`
		} `json:"proxy"`
		SecureDns struct {
			Enabled   bool `json:"enabled"`
			Mandatory bool `json:"mandatory"`
		} `json:"secureDns"`
		OnDevice struct {
			Enabled bool `json:"enabled"`
		} `json:"onDevice"`
	} `json:"capabilities"`
}

func makepayloadstruct(activationprofilename string, idpconnectionid string, privateaccess bool, threatdefence bool, datapolicy bool) Data {
	// Create an instance of the Data struct

	data := Data{
		Name:             activationprofilename,
		GroupId:          "DEFAULT",
		ActiveTab:        "INTUNE",
		LocationServices: "BEST_EFFORT",
		CloudProxy:       "NONE",
		InAppDnsControl:  "REQUIRED",
		RootCertificates: RootCertificates{
			Enabled: true,
		},
		HasFailed: false,
		IsLoading: false,
		// Populate other fields as needed...
		LicenceSpecifics: struct {
			EligibleForCloudProxy bool `json:"eligibleForCloudProxy"`
		}{EligibleForCloudProxy: false},
	}

	// Additional capabilities
	data.Capabilities.DeviceIdentity.Enabled = false
	data.Capabilities.PhysicalAccess.Enabled = false
	data.Capabilities.PrivateAccess.Enabled = privateaccess
	data.Capabilities.DataPolicy.Enabled = datapolicy
	data.Capabilities.ThreatDefence.Enabled = threatdefence
	data.Capabilities.Wireguard.Enabled = false
	data.Capabilities.Proxy.Enabled = false
	data.Capabilities.Proxy.ControlledNetworkInterfaces = "CELLULAR_ONLY"
	data.Capabilities.SecureDns.Enabled = false
	data.Capabilities.SecureDns.Mandatory = true
	data.Capabilities.OnDevice.Enabled = false

	// Additional IDP data
	data.Idp.Type = "OKTA"
	data.Idp.ConnectionId = idpconnectionid
	data.Idp.ExternalIdAdoption = nil

	//management
	data.Management.TimeZone = "America/Los_Angeles"
	data.Management.EffectiveState = nil
	data.Management.LastUsed = nil

	// Populate Licenced Amalgams
	data.LicencedAmalgams = []LicencedAmalgam{
		{
			ServiceCapabilityCombination: []string{"deviceIdentity", "dataPolicy", "privateAccess"},
			CloudProxy:                   nil,
			Platforms:                    []string{"Mac"},
			InAppDnsControl:              []string{"REQUIRED"},
			RootCertificates:             "OPTIONAL",
			DefaultLocationServices:      "BEST_EFFORT",
		},
		{
			ServiceCapabilityCombination: []string{"threatDefence"},
			CloudProxy:                   nil,
			Platforms:                    []string{"ChromeOS", "iOS", "Windows", "Galaxy", "Android", "Mac"},
			InAppDnsControl:              []string{"REQUIRED", "OPTIONAL"},
			RootCertificates:             "OPTIONAL",
			DefaultLocationServices:      "DISABLED",
		},
		// Add more Licenced Amalgams as needed...
	}

	// Marshal the struct into JSON
	jsonData, err := json.MarshalIndent(data, "", "    ")
	if err != nil {
		fmt.Println("Error marshaling JSON:", err)
		//return
	}

	// Print the JSON data
	fmt.Println(string(jsonData))
	return data
}

// Define the schema for the activation resource - only resource
func ResourceActivationProfile() *schema.Resource {
	return &schema.Resource{
		Create: resourceAPCreate,
		Read:   resourceAPRead,
		Update: resourceAPUpdate,
		Delete: resourceAPDelete,

		// Define the attributes of the okta resource
		Schema: map[string]*schema.Schema{
			"name": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Friendly name.",
			},
			"oktaconnectionid": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Okta Connection ID.",
			},
			"privateaccess": {
				Type:     schema.TypeBool,
				Optional: true,
				Default:  true,
			},
			"threatdefence": {
				Type:     schema.TypeBool,
				Optional: true,
				Default:  true,
			},
			"datapolicy": {
				Type:     schema.TypeBool,
				Optional: true,
				Default:  true,
			},
			"supervisedappconfig": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "Supervised Devices Managed App Config",
			},
			"supervisedplist": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "Supervised Devices Managed App Config",
			},
			"unsupervisedappconfig": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "UnSupervised Devices Managed App Config",
			},

			// Add more attributes as needed
		},
	}
}

// Define the create function for the UEMC resource
func resourceAPCreate(d *schema.ResourceData, m interface{}) error {
	data := makepayloadstruct(d.Get("name").(string), d.Get("oktaconnectionid").(string), d.Get("privateaccess").(bool), d.Get("threatdefence").(bool), d.Get("datapolicy").(bool))

	payload, err := json.Marshal(data)
	if err != nil {
		return fmt.Errorf("an error occurred: %s", "marshaling json")
	}
	req, err := http.NewRequest("POST", fmt.Sprintf("https://radar.wandera.com/gate/activation-profile-service/v2/enrollment-links"), bytes.NewBuffer(payload))
	if err != nil {
		return fmt.Errorf("an error occurred: %s", "additional information2")
	}
	resp, err := auth.MakeRequest((req))

	if err != nil {
		return fmt.Errorf("an error occurred: %s", "additional information3")
	}
	defer resp.Body.Close()
	// Check the response status code
	if resp.StatusCode != http.StatusOK && resp.StatusCode != 201 {
		return fmt.Errorf("failed to create activation profile  : %s", resp.Status+" "+string(payload))
	}

	// Read the response body
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("an error occurred: %s", "additional information4")
	}

	// Parse the response JSON if needed
	// (this depends on the structure of the API response)
	fmt.Println(string(body))

	// Parse the response JSON
	var response struct {
		Code string `json:"code"`
	}
	err = json.Unmarshal(body, &response)
	if err != nil {
		return err
	}

	// Set the resource ID
	d.SetId(response.Code)
	d.Set("supervisedappconfig", getAPSupervisedManagedAppConfig(response.Code))
	d.Set("supervisedplist", getAPSupervisedPlist(response.Code))
	d.Set("unsupervisedappconfig", getAPUnSupervisedManagedAppConfig(response.Code))

	return nil

}

// Define the read function for the AP resource
func resourceAPRead(d *schema.ResourceData, m interface{}) error {
	// Make a GET request to read the details of an existing AP

	req, err := http.NewRequest("GET", fmt.Sprintf("https://radar.wandera.com/gate/activation-profile-service/v1/enrollment-links/%s", d.Id()), nil)
	if err != nil {
		return err
	}
	resp, err := auth.MakeRequest((req))

	if err != nil {
		return err
	}
	defer resp.Body.Close()

	// Check the response status code
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("failed to read AP info info: %s", resp.Status)
	}

	// Read the response body
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	// Parse the response JSON if needed
	// (this depends on the structure of the API response)
	fmt.Println(string(body))

	return nil
}

// Define the update function for the Okta  resource NOT IMPLIMENTED
func resourceAPUpdate(d *schema.ResourceData, m interface{}) error {

	d.Set("requires_replace", true)
	resourceAPDelete(d, m)
	resourceAPCreate(d, m)
	return nil
}

// need to apply this function
func resourceAPDelete(d *schema.ResourceData, m interface{}) error {
	// Make a DELETE request to delete an existing AP

	req, err := http.NewRequest("DELETE", fmt.Sprintf("https://radar.wandera.com/gate/activation-profile-service/v1/enrollment-links/%s", d.Id()), nil)
	if err != nil {
		return err
	}

	// Send the request
	resp, err := auth.MakeRequest((req))
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	// Check the response status code
	if resp.StatusCode != http.StatusOK && resp.StatusCode != 204 {
		return fmt.Errorf("failed to delete AP: %v %v %v", resp.Status, resp, req)
	}

	// Clear the resource ID
	d.SetId("")

	return nil
}
