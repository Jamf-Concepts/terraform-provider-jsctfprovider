package auth

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"

	"golang.org/x/net/html"
)

// AuthenticateViaJamfID authenticates using the Jamf ID (Auth0) flow.
// It emulates a browser to follow redirects, parse forms, and submit credentials.
// Returns sessionCookie and xsrfToken.
func AuthenticateViaJamfID(domain, username, password string) (string, string, error) {
	jar, err := cookiejar.New(nil)
	if err != nil {
		return "", "", fmt.Errorf("failed to create cookie jar: %w", err)
	}

	client := &http.Client{
		Jar: jar,
	}

	// 1. Initial Request to kick off OAuth flow
	initialURL := fmt.Sprintf("https://%s/oauth2/authorization/jamf-auth0-us?connection=jamf-id-db", domain)
	resp, err := client.Get(initialURL)
	if err != nil {
		return "", "", fmt.Errorf("initial request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", "", fmt.Errorf("initial request returned status: %s", resp.Status)
	}

	// 2. We should be at /u/login/identifier via redirects.
	currentURL := resp.Request.URL.String()
	if !strings.Contains(currentURL, "/u/login/identifier") {
		return "", "", fmt.Errorf("unexpected URL after initial redirect: %s", currentURL)
	}

	formData, err := extractFormData(resp.Body)
	if err != nil {
		return "", "", fmt.Errorf("failed to parse identifier form: %w", err)
	}

	// Fill in username
	formData.Set("username", username)
	formData.Set("action", "default")

	// 3. Post to /u/login/identifier
	resp, err = client.PostForm(currentURL, formData)
	if err != nil {
		return "", "", fmt.Errorf("failed to submit identifier: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", "", fmt.Errorf("identifier submission returned status: %s", resp.Status)
	}

	// 4. We should be at /u/login/password
	currentURL = resp.Request.URL.String()
	if strings.Contains(currentURL, "/u/login/identifier") {
		return "", "", errors.New("stuck at identifier step, possibly invalid username")
	}
	// It's possible we are already authenticated or redirected elsewhere?
	// But assuming strict flow:
	if !strings.Contains(currentURL, "/u/login/password") {
		// It might be that we skipped password if session was active?
		// But we have empty cookie jar.
		return "", "", fmt.Errorf("unexpected URL after identifier submission: %s", currentURL)
	}

	formData, err = extractFormData(resp.Body)
	if err != nil {
		return "", "", fmt.Errorf("failed to parse password form: %w", err)
	}

	// Fill in password
	formData.Set("password", password)
	formData.Set("action", "default")

	// 5. Post to /u/login/password
	resp, err = client.PostForm(currentURL, formData)
	if err != nil {
		return "", "", fmt.Errorf("failed to submit password: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		if strings.Contains(resp.Request.URL.String(), "/u/login/password") {
			return "", "", errors.New("login failed: invalid password or stuck at password step")
		}
		return "", "", fmt.Errorf("password submission returned status: %s", resp.Status)
	}

	// 6. Final Redirect back to Radar
	finalURL := resp.Request.URL.String()
	if !strings.Contains(finalURL, domain) {
		fmt.Printf("Warning: Final URL %s does not contain domain %s\n", finalURL, domain)
	}

	// 7. Extract cookies
	u, _ := url.Parse(fmt.Sprintf("https://%s", domain))
	cookies := jar.Cookies(u)
	var sessionCookie, xsrfToken string
	for _, cookie := range cookies {
		if cookie.Name == "SESSION" {
			sessionCookie = cookie.Value
		}
		if cookie.Name == "XSRF-TOKEN" {
			xsrfToken = cookie.Value
		}
	}

	if sessionCookie == "" {
		return "", "", errors.New("SESSION cookie not found after login flow")
	}

	return sessionCookie, xsrfToken, nil
}

// extractFormData parses HTML and returns a url.Values map with all input fields (hidden and otherwise).
func extractFormData(r io.Reader) (url.Values, error) {
	doc, err := html.Parse(r)
	if err != nil {
		return nil, err
	}

	values := url.Values{}

	var traverse func(*html.Node)
	traverse = func(n *html.Node) {
		if n.Type == html.ElementNode && n.Data == "input" {
			var name, value, typeAttr string
			for _, a := range n.Attr {
				switch a.Key {
				case "name":
					name = a.Val
				case "value":
					value = a.Val
				case "type":
					typeAttr = a.Val
				}
			}
			if name != "" {
				if typeAttr == "submit" || typeAttr == "button" || typeAttr == "image" {
					// Skip
				} else {
					values.Add(name, value)
				}
			}
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			traverse(c)
		}
	}

	traverse(doc)
	return values, nil
}
