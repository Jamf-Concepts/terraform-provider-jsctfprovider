package main

import (
	"context"
	"fmt"
	"jsctfprovider/endpoints/activationprofiles"
	"jsctfprovider/endpoints/blockpages"
	"jsctfprovider/endpoints/categories"
	"jsctfprovider/endpoints/groups"
	"jsctfprovider/endpoints/hostnamemapping"
	"jsctfprovider/endpoints/idp"
	pagapptemplates "jsctfprovider/endpoints/pag_apptemplates"
	pagvpnroutes "jsctfprovider/endpoints/pag_vpnroutes"
	pagztnaapp "jsctfprovider/endpoints/pag_ztna_app"
	protectpreventlists "jsctfprovider/endpoints/protect_preventlists"
	"jsctfprovider/endpoints/routes"
	"jsctfprovider/endpoints/uemc"
	"jsctfprovider/endpoints/ztna"
	"jsctfprovider/internal/auth"
	"log"
	"os"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/plugin"
)

// Run "go generate" to format example terraform files and generate the docs for the registry/website

// If you do not have terraform installed, you can remove the formatting command, but its suggested to
// ensure the documentation is formatted properly.
//go:generate terraform fmt -recursive ./examples/

// Run the docs generation tool, check its repository for more information on how it works and how docs
// can be customized.
//go:generate go run github.com/hashicorp/terraform-plugin-docs/cmd/tfplugindocs generate --provider-name jsc

var (
	DomainName            string
	Username              string
	Password              string
	Customerid            string
	Applicationid         string
	Applicationsecret     string
	Protectdomainname     string
	Protectclientid       string
	Protectclientpassword string
)

func main() {

	log.SetFlags(log.Flags() &^ (log.Ldate | log.Ltime))

	// Create a new plugin with a specific provider
	plugin.Serve(&plugin.ServeOpts{
		ProviderFunc: func() *schema.Provider {
			return &schema.Provider{
				Schema: map[string]*schema.Schema{
					"domain_name": {
						Type:        schema.TypeString,
						Optional:    true,
						Default:     "radar.wandera.com",
						Description: "The JSC domain.",
					},
					"username": {
						Type:        schema.TypeString,
						Optional:    true,
						Description: "The JSC username used for authentication. Must be local account - SSO or SAML not supported.",
					},
					"password": {
						Type:        schema.TypeString,
						Optional:    true,
						Sensitive:   true,
						Description: "The JSC password used for authentication.",
					},
					"customerid": {
						Type:        schema.TypeString,
						Optional:    true,
						Default:     "empty",
						Description: "The optional customerID. If not provided, the provider will attempt to discover.",
					},
					"applicationid": {
						Type:        schema.TypeString,
						Optional:    true,
						Description: "The optional applicationid. Required for PAG resource types.",
					},
					"applicationsecret": {
						Type:        schema.TypeString,
						Optional:    true,
						Sensitive:   true,
						Description: "The optional applicationsecret. Required for PAG resource types.",
					},
					"protectdomainname": {
						Type:        schema.TypeString,
						Optional:    true,
						Description: "Your Jamf Protect endpoint is your Jamf Protect tenant",
					},
					"protectclientid": {
						Type:        schema.TypeString,
						Optional:    true,
						Description: "The Protect clientID created for authentication.",
					},
					"protectclientpassword": {
						Type:        schema.TypeString,
						Optional:    true,
						Sensitive:   true,
						Description: "The Protect client password (sic) used for authentication.",
					},
				},
				// Define the resources that this provider manages
				ResourcesMap: map[string]*schema.Resource{
					"jsc_oktaidp":             idp.ResourceOktaIdp(),
					"jsc_uemc":                uemc.ResourceUEMC(),
					"jsc_blockpage":           blockpages.ResourceBlockPage(),
					"jsc_ztna":                ztna.Resourceztna(),
					"jsc_ap":                  activationprofiles.ResourceActivationProfile(),
					"jsc_hostnamemapping":     hostnamemapping.ResourceHostnameMapping(),
					"jsc_pag_ztnaapp":         pagztnaapp.ResourcePAGZTNAApp(),
					"jsc_protect_preventlist": protectpreventlists.ResourcePreventlists(),
				},
				// Define the datasources
				DataSourcesMap: map[string]*schema.Resource{
					"jsc_routes":              routes.DataSourceRoutes(),
					"jsc_pag_vpnroutes":       pagvpnroutes.DataSourcePAGVPNRoutes(),
					"jsc_pag_apptemplates":    pagapptemplates.DataSourcePAGAppTemplates(),
					"jsc_pag_ztnaapp":         pagztnaapp.DataSourcePAGZTNAApp(),
					"jsc_categories":          categories.DataSourceCategories(),
					"jsc_groups":              groups.DataSourceGroups(),
					"jsc_hostnamemapping":     hostnamemapping.DataSourceHostnameMapping(),
					"jsc_protect_preventlist": protectpreventlists.DataSourcePreventlists(),
				},
				// Use ConfigureContextFunc so we can return diagnostics and emit a deprecation warning
				ConfigureContextFunc: providerConfigureContext,
			}

		},
	})

}

func providerConfigure(d *schema.ResourceData) (interface{}, error) {
	// Read the domain_name field from the configuration and assign it to domainName
	DomainName = d.Get("domain_name").(string)

	errStore := auth.StoreRadarAuthVars(DomainName)
	if errStore != nil {
		return nil, errStore
	}

	// Assign username and password from configuration
	Username = d.Get("username").(string)
	Password = d.Get("password").(string)
	Customerid = d.Get("customerid").(string)
	Applicationid = d.Get("applicationid").(string)
	Applicationsecret = d.Get("applicationsecret").(string)
	Protectdomainname = d.Get("protectdomainname").(string)
	Protectclientid = d.Get("protectclientid").(string)
	Protectclientpassword = d.Get("protectclientpassword").(string)

	if Username != "" { //prep work for other auth methods
		err := auth.AuthenticateRadarAPI(DomainName, Username, Password, Customerid)
		if err != nil {
			return nil, err
		}
	}
	if Applicationid != "" { //do we have the PAG auth model?
		err := auth.AuthenticatePAG(Applicationid, Applicationsecret)
		if err != nil {
			return nil, err
		}
	}

	if Protectclientid != "" { //do we have the Protect auth model?
		err := auth.AuthenticateProtect(Protectdomainname, Protectclientid, Protectclientpassword)
		if err != nil {
			return nil, err
		}
	}

	return nil, nil
}

// providerConfigureContext wraps the old Configure function to provide
// diagnostics including a deprecation warning. Terraform will show the
// deprecation message when the provider is configured.
func providerConfigureContext(ctx context.Context, d *schema.ResourceData) (interface{}, diag.Diagnostics) {
	var diags diag.Diagnostics

	// Add a deprecation error (will fail provider configuration)
	diags = append(diags, diag.Diagnostic{
		Severity: diag.Warning,
		Summary:  "Provider deprecated",
		Detail:   "This provider is deprecated. Please migrate to Jamf-Concepts/jsctfprovider or contact the maintainers for guidance.",
	})

	// Call existing configure logic
	_, err := providerConfigure(d)
	if err != nil {
		// Return the error as a diagnostic
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  "Provider configuration failed",
			Detail:   err.Error(),
		})
		return nil, diags
	}

	return nil, diags
}

// GetClientPassword retrieves the 'password' value from the Terraform configuration.
// If it's not present in the configuration, it attempts to fetch it from the JSC_PASSWORD environment variable.
func GetClientPassword(d *schema.ResourceData) (string, error) {
	password := d.Get("password").(string)
	if password == "" {
		password = os.Getenv("JSC_PASSWORD")
		if password == "" {
			return "", fmt.Errorf("password must be provided either as an environment variable (JSC_PASSWORD) or in the Terraform configuration")
		}
	}
	return password, nil
}
