/*
Eclipse XFSC TRAIN Trusted Content Resolver

XFSC TRAIN Trusted Content Resolver REST API

API version: 1.0.0
Contact: denis.sukhoroslov@telekom.com
*/

// Code generated by OpenAPI Generator (https://openapi-generator.tech); DO NOT EDIT.

package tcr

import (
	"encoding/json"
	"fmt"
)

// checks if the ResolveRequest type satisfies the MappedNullable interface at compile time
var _ MappedNullable = &ResolveRequest{}

// ResolveRequest struct for ResolveRequest
type ResolveRequest struct {
	// Issuer details from the VC/VP (e.g., DID/URI)
	Issuer string `json:"issuer"`
	// Trust Framework Pointers (e.g., example.federation1.de)
	TrustSchemePointers []string `json:"trustSchemePointers"`
	// Service endpoint types to be considered during the resolving
	EndpointTypes []string `json:"endpointTypes,omitempty"`
}

type _ResolveRequest ResolveRequest

// NewResolveRequest instantiates a new ResolveRequest object
// This constructor will assign default values to properties that have it defined,
// and makes sure properties required by API are set, but the set of arguments
// will change when the set of required properties is changed
func NewResolveRequest(issuer string, trustSchemePointers []string) *ResolveRequest {
	this := ResolveRequest{}
	this.Issuer = issuer
	this.TrustSchemePointers = trustSchemePointers
	return &this
}

// NewResolveRequestWithDefaults instantiates a new ResolveRequest object
// This constructor will only assign default values to properties that have it defined,
// but it doesn't guarantee that properties required by API are set
func NewResolveRequestWithDefaults() *ResolveRequest {
	this := ResolveRequest{}
	return &this
}

// GetIssuer returns the Issuer field value
func (o *ResolveRequest) GetIssuer() string {
	if o == nil {
		var ret string
		return ret
	}

	return o.Issuer
}

// GetIssuerOk returns a tuple with the Issuer field value
// and a boolean to check if the value has been set.
func (o *ResolveRequest) GetIssuerOk() (*string, bool) {
	if o == nil {
		return nil, false
	}
	return &o.Issuer, true
}

// SetIssuer sets field value
func (o *ResolveRequest) SetIssuer(v string) {
	o.Issuer = v
}

// GetTrustSchemePointers returns the TrustSchemePointers field value
func (o *ResolveRequest) GetTrustSchemePointers() []string {
	if o == nil {
		var ret []string
		return ret
	}

	return o.TrustSchemePointers
}

// GetTrustSchemePointersOk returns a tuple with the TrustSchemePointers field value
// and a boolean to check if the value has been set.
func (o *ResolveRequest) GetTrustSchemePointersOk() ([]string, bool) {
	if o == nil {
		return nil, false
	}
	return o.TrustSchemePointers, true
}

// SetTrustSchemePointers sets field value
func (o *ResolveRequest) SetTrustSchemePointers(v []string) {
	o.TrustSchemePointers = v
}

// GetEndpointTypes returns the EndpointTypes field value if set, zero value otherwise.
func (o *ResolveRequest) GetEndpointTypes() []string {
	if o == nil || IsNil(o.EndpointTypes) {
		var ret []string
		return ret
	}
	return o.EndpointTypes
}

// GetEndpointTypesOk returns a tuple with the EndpointTypes field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *ResolveRequest) GetEndpointTypesOk() ([]string, bool) {
	if o == nil || IsNil(o.EndpointTypes) {
		return nil, false
	}
	return o.EndpointTypes, true
}

// HasEndpointTypes returns a boolean if a field has been set.
func (o *ResolveRequest) HasEndpointTypes() bool {
	if o != nil && !IsNil(o.EndpointTypes) {
		return true
	}

	return false
}

// SetEndpointTypes gets a reference to the given []string and assigns it to the EndpointTypes field.
func (o *ResolveRequest) SetEndpointTypes(v []string) {
	o.EndpointTypes = v
}

func (o ResolveRequest) MarshalJSON() ([]byte, error) {
	toSerialize, err := o.ToMap()
	if err != nil {
		return []byte{}, err
	}
	return json.Marshal(toSerialize)
}

func (o ResolveRequest) ToMap() (map[string]interface{}, error) {
	toSerialize := map[string]interface{}{}
	toSerialize["issuer"] = o.Issuer
	toSerialize["trustSchemePointers"] = o.TrustSchemePointers
	if !IsNil(o.EndpointTypes) {
		toSerialize["endpointTypes"] = o.EndpointTypes
	}
	return toSerialize, nil
}

func (o *ResolveRequest) UnmarshalJSON(bytes []byte) (err error) {
	// This validates that all required properties are included in the JSON object
	// by unmarshalling the object into a generic map with string keys and checking
	// that every required field exists as a key in the generic map.
	requiredProperties := []string{
		"issuer",
		"trustSchemePointers",
	}

	allProperties := make(map[string]interface{})

	err = json.Unmarshal(bytes, &allProperties)

	if err != nil {
		return err
	}

	for _, requiredProperty := range requiredProperties {
		if _, exists := allProperties[requiredProperty]; !exists {
			return fmt.Errorf("no value given for required property %v", requiredProperty)
		}
	}

	varResolveRequest := _ResolveRequest{}

	err = json.Unmarshal(bytes, &varResolveRequest)

	if err != nil {
		return err
	}

	*o = ResolveRequest(varResolveRequest)

	return err
}

type NullableResolveRequest struct {
	value *ResolveRequest
	isSet bool
}

func (v NullableResolveRequest) Get() *ResolveRequest {
	return v.value
}

func (v *NullableResolveRequest) Set(val *ResolveRequest) {
	v.value = val
	v.isSet = true
}

func (v NullableResolveRequest) IsSet() bool {
	return v.isSet
}

func (v *NullableResolveRequest) Unset() {
	v.value = nil
	v.isSet = false
}

func NewNullableResolveRequest(val *ResolveRequest) *NullableResolveRequest {
	return &NullableResolveRequest{value: val, isSet: true}
}

func (v NullableResolveRequest) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.value)
}

func (v *NullableResolveRequest) UnmarshalJSON(src []byte) error {
	v.isSet = true
	return json.Unmarshal(src, &v.value)
}
