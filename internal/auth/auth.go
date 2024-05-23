package auth

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"log"
)

var authToken string

// Function to authenticate against the API
var xsrfToken string
var sessionCookie string
var holdCustomerid string

func Authenticate(DomainName string, Username string, Password string, Customerid string) error {

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
		return fmt.Errorf("authentication failed: %s", resp.Status)
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
	authToken = data["token"]
	authcookies := resp.Cookies()

	for _, cookie := range authcookies {
		if cookie.Name == "SESSION" {
			sessionCookie = cookie.Value
		}
	}
	holdCustomerid = Customerid
	return nil
}

func MakeRequest(req *http.Request) (*http.Response, error) {
	// Create a new HTTP client
	client := &http.Client{}
	log.Println("Building the client")
	log.Println("incoming url is " + req.URL.Path)
	req.URL.RawQuery += "customerId=" + holdCustomerid
	log.Println("new url is " + req.URL.Path)
	log.Println("new raw url is " + req.URL.RawPath)
	log.Println("raw host is " + string(req.URL.Host))

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
