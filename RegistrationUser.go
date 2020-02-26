package main

import (
	"crypto"

	"github.com/go-acme/lego/registration"
)

// RegistrationUser You'll need a user or account type that implements acme.User
type RegistrationUser struct {
	Email        string
	Registration *registration.Resource
	key          crypto.PrivateKey
}

//GetEmail returns the email
func (u *RegistrationUser) GetEmail() string {
	return u.Email
}

//GetRegistration returns the registration
func (u RegistrationUser) GetRegistration() *registration.Resource {
	return u.Registration
}

//GetPrivateKey returns the private key
func (u *RegistrationUser) GetPrivateKey() crypto.PrivateKey {
	return u.key
}
