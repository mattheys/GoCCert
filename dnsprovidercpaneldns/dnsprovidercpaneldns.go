package dnsprovidercpaneldns

import (
	"errors"

	"github.com/xenolf/lego/challenge/dns01"
)

//DNSProviderCpanelDNS uses the Cpanel Json API to add, update and delete dns entries for use with Lets Encrypt
type DNSProviderCpanelDNS struct {
	factory CpanelFactory
}

//NewDNSProviderCpanelDNS instansiate new Provider
func NewDNSProviderCpanelDNS(factory CpanelFactory) (*DNSProviderCpanelDNS, error) {
	return &DNSProviderCpanelDNS{factory: factory}, nil
}

//Present Updates or creates the TXT records required to request a certificate
func (d *DNSProviderCpanelDNS) Present(domain, token, keyAuth string) error {
	fqdn, value := dns01.GetRecord(domain, keyAuth)

	success, line, err := d.factory.CheckZone(fqdn)
	if err == nil {
		if success {
			d.factory.ZoneEdit(fqdn, value, line)
		} else {
			d.factory.ZoneAdd(fqdn, value)
		}
	} else {
		return errors.New("could not get zone record")
	}
	return nil
}

//CleanUp Removes the TXT records afterwards for security
func (d *DNSProviderCpanelDNS) CleanUp(domain, token, keyAuth string) error {

	fqdn, _ := dns01.GetRecord(domain, keyAuth)
	found, line, err := d.factory.CheckZone(fqdn)

	if err == nil && found && line > 0 {
		deleted := d.factory.ZoneDelete(fqdn, line)
		if !deleted {
			return errors.New("zone not deleted")
		}
	}

	return nil
}
