package activationprofiles

import (
	"fmt"
	"io/ioutil"
	"net/http"

	"jsctfprovider/internal/auth"
)

func getAPSupervisedManagedAppConfig(apID string) string {

	req, err := http.NewRequest("GET", fmt.Sprintf("https://radar.wandera.com/gate/uem-deployment-template-service/v1/activation-profiles/%s/uems/JAMF/platforms/SUPERVISED_IOS/types/MANAGED_APP_CONFIG", apID), nil)
	if err != nil {
		return "payload not found"
	}
	resp, err := auth.MakeRequest((req))

	if err != nil {
		return "payload not found"
	}
	defer resp.Body.Close()
	// Check the response status code
	if resp.StatusCode != http.StatusOK {
		return "payload not found"
	}
	body, err := ioutil.ReadAll(resp.Body)

	return string(body)
}

func getAPSupervisedPlist(apID string) string {

	req, err := http.NewRequest("GET", fmt.Sprintf("https://radar.wandera.com/gate/uem-deployment-template-service/v1/activation-profiles/%s/uems/JAMF/platforms/SUPERVISED_IOS/types/CONFIGURATION_PROFILE", apID), nil)
	if err != nil {
		return "payload not found"
	}
	resp, err := auth.MakeRequest((req))

	if err != nil {
		return "payload not found"
	}
	defer resp.Body.Close()
	// Check the response status code
	if resp.StatusCode != http.StatusOK {
		return "payload not found"
	}
	body, err := ioutil.ReadAll(resp.Body)

	return string(body)
}

func getAPUnSupervisedManagedAppConfig(apID string) string {

	req, err := http.NewRequest("GET", fmt.Sprintf("https://radar.wandera.com/gate/uem-deployment-template-service/v1/activation-profiles/%s/uems/JAMF/platforms/UNSUPERVISED_IOS/types/MANAGED_APP_CONFIG", apID), nil)
	if err != nil {
		return "payload not found"
	}
	resp, err := auth.MakeRequest((req))

	if err != nil {
		return "payload not found"
	}
	defer resp.Body.Close()
	// Check the response status code
	if resp.StatusCode != http.StatusOK {
		return "payload not found"
	}
	body, err := ioutil.ReadAll(resp.Body)

	return string(body)
}
