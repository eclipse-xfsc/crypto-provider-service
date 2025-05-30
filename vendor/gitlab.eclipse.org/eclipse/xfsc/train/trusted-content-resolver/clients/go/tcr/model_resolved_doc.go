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

// checks if the ResolvedDoc type satisfies the MappedNullable interface at compile time
var _ MappedNullable = &ResolvedDoc{}

// ResolvedDoc struct for ResolvedDoc
type ResolvedDoc struct {
	// DID Document of the DID
	Document map[string]interface{} `json:"document"`
	// Resolved Trust List VC endpoints
	Endpoints []ResolvedTrustList `json:"endpoints,omitempty"`
	// Well-known did-configuration verification result
	DidVerified bool `json:"didVerified"`
}

type _ResolvedDoc ResolvedDoc

// NewResolvedDoc instantiates a new ResolvedDoc object
// This constructor will assign default values to properties that have it defined,
// and makes sure properties required by API are set, but the set of arguments
// will change when the set of required properties is changed
func NewResolvedDoc(document map[string]interface{}, didVerified bool) *ResolvedDoc {
	this := ResolvedDoc{}
	this.Document = document
	this.DidVerified = didVerified
	return &this
}

// NewResolvedDocWithDefaults instantiates a new ResolvedDoc object
// This constructor will only assign default values to properties that have it defined,
// but it doesn't guarantee that properties required by API are set
func NewResolvedDocWithDefaults() *ResolvedDoc {
	this := ResolvedDoc{}
	return &this
}

// GetDocument returns the Document field value
func (o *ResolvedDoc) GetDocument() map[string]interface{} {
	if o == nil {
		var ret map[string]interface{}
		return ret
	}

	return o.Document
}

// GetDocumentOk returns a tuple with the Document field value
// and a boolean to check if the value has been set.
func (o *ResolvedDoc) GetDocumentOk() (map[string]interface{}, bool) {
	if o == nil {
		return map[string]interface{}{}, false
	}
	return o.Document, true
}

// SetDocument sets field value
func (o *ResolvedDoc) SetDocument(v map[string]interface{}) {
	o.Document = v
}

// GetEndpoints returns the Endpoints field value if set, zero value otherwise.
func (o *ResolvedDoc) GetEndpoints() []ResolvedTrustList {
	if o == nil || IsNil(o.Endpoints) {
		var ret []ResolvedTrustList
		return ret
	}
	return o.Endpoints
}

// GetEndpointsOk returns a tuple with the Endpoints field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *ResolvedDoc) GetEndpointsOk() ([]ResolvedTrustList, bool) {
	if o == nil || IsNil(o.Endpoints) {
		return nil, false
	}
	return o.Endpoints, true
}

// HasEndpoints returns a boolean if a field has been set.
func (o *ResolvedDoc) HasEndpoints() bool {
	if o != nil && !IsNil(o.Endpoints) {
		return true
	}

	return false
}

// SetEndpoints gets a reference to the given []ResolvedTrustList and assigns it to the Endpoints field.
func (o *ResolvedDoc) SetEndpoints(v []ResolvedTrustList) {
	o.Endpoints = v
}

// GetDidVerified returns the DidVerified field value
func (o *ResolvedDoc) GetDidVerified() bool {
	if o == nil {
		var ret bool
		return ret
	}

	return o.DidVerified
}

// GetDidVerifiedOk returns a tuple with the DidVerified field value
// and a boolean to check if the value has been set.
func (o *ResolvedDoc) GetDidVerifiedOk() (*bool, bool) {
	if o == nil {
		return nil, false
	}
	return &o.DidVerified, true
}

// SetDidVerified sets field value
func (o *ResolvedDoc) SetDidVerified(v bool) {
	o.DidVerified = v
}

func (o ResolvedDoc) MarshalJSON() ([]byte, error) {
	toSerialize, err := o.ToMap()
	if err != nil {
		return []byte{}, err
	}
	return json.Marshal(toSerialize)
}

func (o ResolvedDoc) ToMap() (map[string]interface{}, error) {
	toSerialize := map[string]interface{}{}
	toSerialize["document"] = o.Document
	if !IsNil(o.Endpoints) {
		toSerialize["endpoints"] = o.Endpoints
	}
	toSerialize["didVerified"] = o.DidVerified
	return toSerialize, nil
}

func (o *ResolvedDoc) UnmarshalJSON(bytes []byte) (err error) {
	// This validates that all required properties are included in the JSON object
	// by unmarshalling the object into a generic map with string keys and checking
	// that every required field exists as a key in the generic map.
	requiredProperties := []string{
		"document",
		"didVerified",
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

	varResolvedDoc := _ResolvedDoc{}

	err = json.Unmarshal(bytes, &varResolvedDoc)

	if err != nil {
		return err
	}

	*o = ResolvedDoc(varResolvedDoc)

	return err
}

type NullableResolvedDoc struct {
	value *ResolvedDoc
	isSet bool
}

func (v NullableResolvedDoc) Get() *ResolvedDoc {
	return v.value
}

func (v *NullableResolvedDoc) Set(val *ResolvedDoc) {
	v.value = val
	v.isSet = true
}

func (v NullableResolvedDoc) IsSet() bool {
	return v.isSet
}

func (v *NullableResolvedDoc) Unset() {
	v.value = nil
	v.isSet = false
}

func NewNullableResolvedDoc(val *ResolvedDoc) *NullableResolvedDoc {
	return &NullableResolvedDoc{value: val, isSet: true}
}

func (v NullableResolvedDoc) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.value)
}

func (v *NullableResolvedDoc) UnmarshalJSON(src []byte) error {
	v.isSet = true
	return json.Unmarshal(src, &v.value)
}
