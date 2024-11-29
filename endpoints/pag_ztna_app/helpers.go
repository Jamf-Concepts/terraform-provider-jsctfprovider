package pagztnaapp

import (
	"context"
	"fmt"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func validatePAGZTNADataFields(ctx context.Context, diff *schema.ResourceDiff, v interface{}) error {
	routingdnstype, ok := diff.GetOk("routingdnstype")
	if !ok {
		return fmt.Errorf("routingdnstypes must be provided")
	}

	if routingdnstype != "IPv4" && routingdnstype != "IPv6" {
		return fmt.Errorf("routingdnstypes must be either IPv4 or IPv6")
	}

	routingtype, ok := diff.GetOk("routingtype")
	if !ok {
		return fmt.Errorf("routingtype must be provided")
	}

	if routingtype != "CUSTOM" && routingtype != "DIRECT" {
		return fmt.Errorf("routingtype must be either CUSTOM or DIRECT")
	}

	if routingtype == "CUSTOM" {
		routingid, okroutingid := diff.GetOk("routingid")
		if !okroutingid {
			return fmt.Errorf("when routingtype=CUSTOM, you must provide a routingid")
		}
		if routingid == "" {
			return fmt.Errorf("when routingtype=CUSTOM, you must provide a routingid")
		}
	}

	if routingtype == "DIRECT" {
		routingid, okroutingid := diff.GetOk("routingid")
		if okroutingid {
			return fmt.Errorf("when routingtype=DIRECT, you must not provide a routingid")
		}
		if routingid != "" {
			return fmt.Errorf("when routingtype=CUSTOM, you must not provide a routingid")
		}
	}

	securityriskcontrolthreshold, ok := diff.GetOk("securityriskcontrolthreshold")
	if !ok {
		return fmt.Errorf("securityriskcontrolthreshold must be HIGH, MEDIUM, LOW")
	}
	if securityriskcontrolthreshold != "HIGH" && routingdnstype != "MEDIUM" && routingdnstype != "LOW" {
		return fmt.Errorf("ecurityriskcontrolthreshold must be HIGH, MEDIUM, LOW")
	}

	return nil
}
