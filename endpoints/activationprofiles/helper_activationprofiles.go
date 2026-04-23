// Copyright 2025, Jamf Software LLC.
package activationprofiles

import (
	"fmt"
	"io/ioutil"
	"net/http"

	"jsctfprovider/internal/auth"
)

// makeConfigRequest creates a request with proper headers for configuration profile downloads
// These endpoints return binary plist/mobileconfig files, not JSON
func makeConfigRequest(url string) (*http.Response, error) {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	// Set Accept header to indicate we want text/binary content, not JSON
	// The auth.MakeRequest function will respect this if already set
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml,text/plain,*/*")
	return auth.MakeRequest(req)
}

func getAPSupervisedManagedAppConfig(apID string) string {

	req, err := http.NewRequest("GET", fmt.Sprintf("https://radar.wandera.com/gate/uem-deployment-template-service/v1/activation-profiles/%s/uems/JAMF/platforms/SUPERVISED_IOS/types/MANAGED_APP_CONFIG", apID), nil)
	if err != nil {
		return "payload not found"
	}
	// Set Accept header for configuration profile content
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml,text/plain,*/*")
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
	// Set Accept header for configuration profile content
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml,text/plain,*/*")
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
	// Set Accept header for configuration profile content
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml,text/plain,*/*")
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

func getAPUnSupervisedPlist(apID string) string {

	req, err := http.NewRequest("GET", fmt.Sprintf("https://radar.wandera.com/gate/uem-deployment-template-service/v1/activation-profiles/%s/uems/JAMF/platforms/UNSUPERVISED_IOS/types/CONFIGURATION_PROFILE", apID), nil)
	if err != nil {
		return "payload not found"
	}
	// Set Accept header for configuration profile content
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml,text/plain,*/*")
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

func getAPBYODManagedAppConfig(apID string) string {

	req, err := http.NewRequest("GET", fmt.Sprintf("https://radar.wandera.com/gate/uem-deployment-template-service/v1/activation-profiles/%s/uems/JAMF/platforms/BYOD_IOS/types/MANAGED_APP_CONFIG", apID), nil)
	if err != nil {
		return "payload not found"
	}
	// Set Accept header for configuration profile content
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml,text/plain,*/*")
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

func getAPBYODPlist(apID string) string {

	req, err := http.NewRequest("GET", fmt.Sprintf("https://radar.wandera.com/gate/uem-deployment-template-service/v1/activation-profiles/%s/uems/JAMF/platforms/BYOD_IOS/types/CONFIGURATION_PROFILE", apID), nil)
	if err != nil {
		return "payload not found"
	}
	// Set Accept header for configuration profile content
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml,text/plain,*/*")
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

func getAPmacOSPlist(apID string) string {

	req, err := http.NewRequest("GET", fmt.Sprintf("https://radar.wandera.com/gate/uem-deployment-template-service/v1/activation-profiles/%s/uems/JAMF/platforms/SUPERVISED_MAC/types/CONFIGURATION_PROFILE", apID), nil)
	if err != nil {
		return "payload not found"
	}
	// Set Accept header for configuration profile content
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml,text/plain,*/*")
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
