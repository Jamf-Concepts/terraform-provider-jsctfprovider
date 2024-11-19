package auth

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"strings"
)

var xsrfToken string
var sessionCookie string
var pagjwt string
var holdCustomerid string
var providerDomainName string

func AuthenticatePAG(Applicationid string, Applicationsecret string) error {

	// Struct to hold the response data
	type ApiResponse struct {
		Token string `json:"token"`
	}

	const apidomain = "api.wandera.com"

	// Create the Basic Authentication string
	auth := Applicationid + ":" + Applicationsecret
	encodedAuth := base64.StdEncoding.EncodeToString([]byte(auth))

	// Create the request with the Basic Authentication header
	req, err := http.NewRequest("POST", fmt.Sprintf("https://%s/v1/login", apidomain), nil)
	if err != nil {
		return err
	}

	// Add the Authorization header
	req.Header.Add("Authorization", "Basic "+encodedAuth)

	// Make the request
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	// Handle the response
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("failed to login, status: %s", resp.Status)
	}
	// Read the response body
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	// Parse the JSON response
	var apiResponse ApiResponse
	err = json.Unmarshal(body, &apiResponse)
	if err != nil {
		return fmt.Errorf("failed to parse response: %v", err)
	}

	// Return the token
	println(apiResponse.Token)
	pagjwt = apiResponse.Token

	return nil
}

func StoreRadarAuthVars(DomainName string) error {
	providerDomainName = DomainName

	return nil
}

func AuthenticateRadarAPI(DomainName string, Username string, Password string, Customerid string) error {

	// Make a GET request to obtain cookies
	resp, err := http.Get(fmt.Sprintf("https://%s/auth/v1/login-methods?email=%s", DomainName, Username))
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	// Check the response status code
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("failed to get cookies: %s", resp.Status)
	}

	// Extract cookies from the response
	cookies := resp.Cookies()

	// Extract the value of the first cookie
	//var xsrfToken string
	if len(cookies) > 0 {
		xsrfToken = cookies[0].Value
		//fmt.Errorf(xsrfToken)
	}

	// Construct the authentication request body

	authData := map[string]string{
		"username":   Username, //hardcoded in PoC but can come from template or ENV
		"password":   Password,
		"totp":       "",
		"backupCode": "",
	}
	payload, err := json.Marshal(authData)
	if err != nil {
		return err
	}

	// Make a POST request to authenticate with cookies
	client := &http.Client{}
	url := fmt.Sprintf("https://%s/auth/v1/credentials", DomainName)
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(payload))
	if err != nil {
		return err
	}
	for _, cookie := range cookies {
		req.AddCookie(cookie)
	}
	req.Header.Set("Content-Type", "application/json")

	req.Header.Set("X-Xsrf-Token", xsrfToken)

	resp, err = client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	// Check the response status code
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("authentication failed: %s. This provider only support local email:pass combinations and not any SSO/SAML credentials", resp.Status)
	}

	// Read the response body
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	// Parse the response JSON to get the authentication token
	var data map[string]string
	err = json.Unmarshal(body, &data)
	if err != nil {
		return err
	}

	// Store the authentication token
	authcookies := resp.Cookies()

	for _, cookie := range authcookies {
		if cookie.Name == "SESSION" {
			sessionCookie = cookie.Value
		}
	}

	if Customerid == "empty" {
		//Customerid not provided so attempt to find from endpiint
		findCustomerid(DomainName)
	} else {
		holdCustomerid = Customerid
	}
	return nil
}

func findCustomerid(DomainName string) {
	client := &http.Client{}
	url := (fmt.Sprintf("https://%s/auth/v1/me", DomainName))
	//req, err := http.NewRequest("GET", fmt.Sprintf("https://radar.wandera.com/gate/content-block-service/v1/customers/{customerid}/categories"), nil)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		fmt.Println("Error:", err)
		return
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("X-Xsrf-Token", xsrfToken)
	req.AddCookie(&http.Cookie{Name: "SESSION", Value: sessionCookie, Path: "/", SameSite: http.SameSiteLaxMode, Secure: true, HttpOnly: true})
	req.AddCookie(&http.Cookie{Name: "XSRF-TOKEN", Value: xsrfToken})
	resp, err := client.Do(req)
	if err != nil {
		fmt.Println("Error:", err)
		return
	}
	defer resp.Body.Close()
	// Check the response status code
	if resp.StatusCode != http.StatusOK {
		//fmt.Println("customerid checking failed: %s", resp.Status)
		return
	}

	// Read the response body
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		fmt.Println("Error:", err)
		return
	}

	// Parse the response JSON to get the customerid
	// Unmarshal JSON into a map[string]interface{}
	var result map[string]interface{}
	jsonerr := json.Unmarshal(body, &result)
	if err != nil {
		fmt.Println("Error:", jsonerr)
		return
	}
	//check if login user is parent or customer type
	if result["admin"].(map[string]interface{})["entityType"].(string) == "CUSTOMER" {
		// Extract entityId
		entityId := result["admin"].(map[string]interface{})["entityId"].(string)
		fmt.Println("Customer:", entityId)
		holdCustomerid = entityId
	} else {
		urlCheckParent := (fmt.Sprintf("https://%s/gate/user-service/customer/v2/customers/visible-for-admin", DomainName))
		req, err := http.NewRequest("GET", urlCheckParent, nil)
		if err != nil {
			fmt.Println("Error:", err)
			return
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json")
		req.Header.Set("X-Xsrf-Token", xsrfToken)
		req.AddCookie(&http.Cookie{Name: "SESSION", Value: sessionCookie, Path: "/", SameSite: http.SameSiteLaxMode, Secure: true, HttpOnly: true})
		req.AddCookie(&http.Cookie{Name: "XSRF-TOKEN", Value: xsrfToken})
		resp, err := client.Do(req)
		if err != nil {
			fmt.Println("Error:", err)
			return
		}
		defer resp.Body.Close()
		// Check the response status code
		if resp.StatusCode != http.StatusOK {
			//fmt.Println("customerid checking failed: %s", resp.Status)
			return
		}
		// Read the response body
		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			fmt.Println("Error:", err)
			return
		}

		// Parse the response JSON to get the customerid
		// Unmarshal JSON into a map[string]interface{}
		// Unmarshal JSON into an interface slice
		var data []map[string]json.RawMessage
		errmarshall := json.Unmarshal([]byte(body), &data)
		if errmarshall != nil {
			fmt.Println("Error:", err)
			return
		}

		// Filter and collect customerId where leaf is true
		var customerIds []string
		for _, customer := range data {
			var leaf bool
			err := json.Unmarshal(customer["leaf"], &leaf)
			if err != nil {
				fmt.Println("Error:", err)
				continue
			}

			if leaf {
				var customerId string
				err := json.Unmarshal(customer["customerId"], &customerId)
				if err != nil {
					fmt.Println("Error:", err)
					continue
				}
				customerIds = append(customerIds, customerId)
			}
		}
		holdCustomerid = customerIds[0] // can a parent have more than 1 customer - well they can define it manually in the provider then
	}

}
func MakeRequest(req *http.Request) (*http.Response, error) {
	if sessionCookie == "" {
		return nil, fmt.Errorf("RADAR API not authenticated")
	}
	client := &http.Client{}
	log.Println("[INFO] Building the client")
	log.Println("[INFO] incoming url is " + req.URL.Path)
	req.URL.RawQuery += "customerId=" + holdCustomerid

	log.Println("new url query is " + req.URL.RawQuery)
	req.URL.Path = strings.Replace(req.URL.Path, "{customerid}", holdCustomerid, -1)
	req.Host = providerDomainName     //swap out domain if something specific is provided
	req.URL.Host = providerDomainName //in both the path AND the host field
	log.Println("new raw url is " + req.URL.Path)
	log.Println("raw host is " + string(req.Host))

	log.Println("session cookie  is " + sessionCookie)

	// Send the request using the client
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("X-Xsrf-Token", xsrfToken)
	req.AddCookie(&http.Cookie{Name: "SESSION", Value: sessionCookie, Path: "/", SameSite: http.SameSiteLaxMode, Secure: true, HttpOnly: true})
	req.AddCookie(&http.Cookie{Name: "XSRF-TOKEN", Value: xsrfToken})
	resp2, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	//defer resp2.Body.Close()

	return resp2, nil

}

func MakePAGRequest(req *http.Request) (*http.Response, error) {
	if pagjwt == "" {
		return nil, fmt.Errorf("PAG JWT API not authenticated")
	}
	client := &http.Client{}
	log.Println("[INFO] Building the PAG client")
	log.Println("[INFO] incoming url is " + req.URL.Path)
	// Send the request using the client
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	// Add Bearer Token for authentication
	req.Header.Set("Authorization", "Bearer "+pagjwt)

	resp2, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	//defer resp2.Body.Close()

	return resp2, nil
}
