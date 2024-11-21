package pagztnaapp

import (
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

// Define the schema for the ZTNA resource
func ResourcePAGZTNAApp() *schema.Resource {
	return &schema.Resource{
		Create:        resourcePAGZTNAAppCreate,
		Read:          resourcePAGZTNAAppRead,
		Update:        resourcePAGZTNAAppUpdate,
		Delete:        resourcePAGZTNAAppDelete,
		CustomizeDiff: validatePAGZTNADataFields,

		Schema: map[string]*schema.Schema{
			"name": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "The name of the ZTNA App",
			},
			"id": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "The unique identifier of the ZTNA App datasource set from JSC",
			},
			"hostnames": {
				Type:        schema.TypeList,
				Elem:        &schema.Schema{Type: schema.TypeString},
				Optional:    true,
				Description: "List of hostnames",
			},
			"bareips": {
				Type:        schema.TypeList,
				Elem:        &schema.Schema{Type: schema.TypeString},
				Optional:    true,
				Description: "List of bare ips",
			},
			"categoryname": {
				Type:        schema.TypeString,
				Optional:    true,
				Default:     "Uncategorized",
				Description: "Category Name",
			},
			"apptemplateid": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "App Template ID (if applicable)",
			},
			"routingtype": {
				Type:        schema.TypeString,
				Optional:    true,
				Default:     "DIRECT",
				Description: "Routing Type - DIRECT or CUSTOM",
			},
			"routingid": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Routing ID - required when routingtype is CUSTOM",
			},
			"routingdnstype": {
				Type:        schema.TypeString,
				Optional:    true,
				Default:     "IPv6",
				Description: "Routing IP DNS Resolution Type - IPv4 or IPv6 (default is IPv6)",
			},
			"securityriskcontrolenabled": {
				Type:        schema.TypeBool,
				Optional:    true,
				Default:     false,
				Description: "Enable device risk security controls for ZTNA App policy",
			},
			"securityriskcontrolthreshold": {
				Type:        schema.TypeString,
				Optional:    true,
				Default:     "HIGH",
				Description: "Risk level threshold (when enabled), options of HIGH, MEDIUM, LOW",
			},
			"securityriskcontrolnotifications": {
				Type:        schema.TypeBool,
				Optional:    true,
				Default:     false,
				Description: "Enable notificatons for device risk security controls",
			},
			"securitydohintegrationblocking": {
				Type:        schema.TypeBool,
				Optional:    true,
				Default:     true,
				Description: "Enable DoH blocking for ZTNA App Policy",
			},
			"securitydohintegrationnotifications": {
				Type:        schema.TypeBool,
				Optional:    true,
				Default:     false,
				Description: "Enable DoH notifications for ZTNA App Policy",
			},
			"securitydevicemanagementbasedaccessenabled": {
				Type:        schema.TypeBool,
				Optional:    true,
				Default:     false,
				Description: "Enable deviceManagementBasedAccess for ZTNA App Policy",
			},
			"securitydevicemanagementbasedaccessnotifications": {
				Type:        schema.TypeBool,
				Optional:    true,
				Default:     false,
				Description: "Enable deviceManagementBasedAccess notifications for ZTNA App Policy",
			},
			"assignmentallusers": {
				Type:        schema.TypeBool,
				Optional:    true,
				Default:     false,
				Description: "Assign ZTNA App to all users",
			},
			"assignmentgroups": {
				Type:        schema.TypeList,
				Elem:        &schema.Schema{Type: schema.TypeString},
				Optional:    true,
				Description: "Groups to assign ZTNA App Policy to",
			},
		},
	}
}

// Define the create function for the mapping resource
func resourcePAGZTNAAppCreate(d *schema.ResourceData, m interface{}) error {

	return nil
}

// Define the read function for the hostname mapping
func resourcePAGZTNAAppRead(d *schema.ResourceData, m interface{}) error {
	// Make a GET request to read the details of mappings

	return nil
}

// Define the update function for the hostname  resource NOT IMPLIMENTED

func resourcePAGZTNAAppUpdate(d *schema.ResourceData, m interface{}) error {

	d.Set("requires_replace", true)
	resourcePAGZTNAAppDelete(d, m)
	resourcePAGZTNAAppCreate(d, m)
	return nil
}

// Define the delete function for the hostname resource
func resourcePAGZTNAAppDelete(d *schema.ResourceData, m interface{}) error {

	return nil
}
