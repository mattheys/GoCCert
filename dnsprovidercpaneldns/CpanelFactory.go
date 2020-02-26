package dnsprovidercpaneldns

import (
	"bytes"
	"encoding/base64"
	"errors"
	"io/ioutil"
	"net/http"
	"strconv"
	"strings"

	"github.com/tidwall/gjson"
	"golang.org/x/net/publicsuffix"
)

//CpanelFactory stores the data needed to access Cpanel
type CpanelFactory struct {
	url      string
	username string
	password string
}

//NewCpanelFactory create a new thing to access Cpanel
func NewCpanelFactory(url string, username string, password string) *CpanelFactory {
	return &CpanelFactory{url: url, username: username, password: password}
}

func (c *CpanelFactory) getBasicAuth() string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(c.username+":"+c.password))
}

//CheckZone tests to see if a subdomain already exists in a domain and if it does returns it's "line" number for editing
func (c *CpanelFactory) CheckZone(fqdn string) (bool, int, error) {
	zone, err := publicsuffix.EffectiveTLDPlusOne(strings.TrimRight(fqdn, "."))
	if err == nil {
		jsonData := []byte(`{
		"cpanel_jsonapi_apiversion": 2,
		"cpanel_jsonapi_module":     "ZoneEdit",
		"cpanel_jsonapi_func":       "fetchzone",
		"domain":                    "` + zone + `",
		"type":                      "TXT"
	}`)

		request, _ := http.NewRequest("POST", c.url, bytes.NewBuffer(jsonData))
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("Authorization", c.getBasicAuth())

		client := &http.Client{}
		response, err := client.Do(request)

		if err == nil && response.StatusCode == 200 {
			data, _ := ioutil.ReadAll(response.Body)
			//fmt.Println(string(data))
			v := gjson.Get(string(data), "cpanelresult.data.0.record.#[name==\""+fqdn+"\"].Line")
			if v.Value() != nil {
				return true, int(v.Int()), nil
			}
			return false, 0, nil

		}
		return false, 0, errors.New("Failed to get DNS zone")
	}
	return false, 0, errors.New("Could not get TLD+1")
}

//ZoneAdd creates a new subdomain in a domain
func (c *CpanelFactory) ZoneAdd(fqdn string, value string) bool {
	zone, err := publicsuffix.EffectiveTLDPlusOne(strings.TrimRight(fqdn, "."))
	if err == nil {
		jsonData := []byte(`{
		"cpanel_jsonapi_apiversion": 2,
		"cpanel_jsonapi_module":     "ZoneEdit",
		"cpanel_jsonapi_func":       "add_zone_record",
		"domain":                    "` + zone + `",
		"name": 					 "` + fqdn + `",
		"type":                      "TXT",
		"class":"IN",
		"ttl":60,
		"txtdata":"` + value + `"
	}`)

		request, _ := http.NewRequest("POST", c.url, bytes.NewBuffer(jsonData))
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("Authorization", c.getBasicAuth())

		client := &http.Client{}
		response, err := client.Do(request)

		ioutil.ReadAll(response.Body)
		//fmt.Println(string(data))

		if err == nil && response.StatusCode == 200 {
			return true
		}

	}
	return false
}

//ZoneEdit updates an exisitng subdomain in a domain using it's line number
func (c *CpanelFactory) ZoneEdit(fqdn string, value string, line int) bool {
	zone, err := publicsuffix.EffectiveTLDPlusOne(strings.TrimRight(fqdn, "."))
	if err == nil {
		jsonData := []byte(`{
		"cpanel_jsonapi_apiversion": 2,
		"cpanel_jsonapi_module":     "ZoneEdit",
		"cpanel_jsonapi_func":       "edit_zone_record",
		"domain":                    "` + zone + `",
		"name": 					 "` + fqdn + `",
		"type":                      "TXT",
		"class":"IN",
		"ttl":60,
		"line":` + strconv.Itoa(line) + `,
		"txtdata":"` + value + `"
	}`)

		//fmt.Println(string(jsonData))

		request, _ := http.NewRequest("POST", c.url, bytes.NewBuffer(jsonData))
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("Authorization", c.getBasicAuth())

		client := &http.Client{}
		response, err := client.Do(request)

		ioutil.ReadAll(response.Body)
		//fmt.Println(string(data))

		if err == nil && response.StatusCode == 200 {
			return true
		}
	}
	return false
}

//ZoneDelete deletes a domain from the zone record to tidy up
func (c *CpanelFactory) ZoneDelete(fqdn string, line int) bool {
	zone, err := publicsuffix.EffectiveTLDPlusOne(strings.TrimRight(fqdn, "."))
	if err == nil {
		jsonData := []byte(`{
		"cpanel_jsonapi_apiversion": 2,
		"cpanel_jsonapi_module":     "ZoneEdit",
		"cpanel_jsonapi_func":       "remove_zone_record",
		"domain":                    "` + zone + `",
		"line":` + strconv.Itoa(line) + `		
	}`)

		//fmt.Println(string(jsonData))

		request, _ := http.NewRequest("POST", c.url, bytes.NewBuffer(jsonData))
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("Authorization", c.getBasicAuth())

		client := &http.Client{}
		response, err := client.Do(request)

		ioutil.ReadAll(response.Body)
		//fmt.Println(string(data))

		if err == nil && response.StatusCode == 200 {
			return true
		}

	}
	return false
}
