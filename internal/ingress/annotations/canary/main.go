/*
Copyright 2018 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package canary

import (
	karmadanetworking "github.com/karmada-io/karmada/pkg/apis/networking/v1alpha1"
	networking "k8s.io/api/networking/v1"

	"k8s.io/ingress-nginx/internal/ingress/annotations/parser"
	"k8s.io/ingress-nginx/internal/ingress/errors"
	"k8s.io/ingress-nginx/internal/ingress/resolver"
)

type canary struct {
	r resolver.Resolver
}

// Config returns the configuration rules for setting up the Canary
type Config struct {
	Enabled       bool
	Weight        int
	WeightTotal   int
	Header        string
	HeaderValue   string
	HeaderPattern string
	Cookie        string
}

// NewParser parses the ingress for canary related annotations
func NewParser(r resolver.Resolver) parser.IngressAnnotation {
	return canary{r}
}

// Parse parses the annotations contained in the ingress
// rule used to indicate if the canary should be enabled and with what config
func (c canary) Parse(ing *networking.Ingress) (interface{}, error) {
	config := &Config{}
	var err error

	config.Enabled, err = parser.GetBoolAnnotation("canary", ing)
	if err != nil {
		config.Enabled = false
	}

	config.Weight, err = parser.GetIntAnnotation("canary-weight", ing)
	if err != nil {
		config.Weight = 0
	}

	config.WeightTotal, err = parser.GetIntAnnotation("canary-weight-total", ing)
	if err != nil {
		config.WeightTotal = 100
	}

	config.Header, err = parser.GetStringAnnotation("canary-by-header", ing)
	if err != nil {
		config.Header = ""
	}

	config.HeaderValue, err = parser.GetStringAnnotation("canary-by-header-value", ing)
	if err != nil {
		config.HeaderValue = ""
	}

	config.HeaderPattern, err = parser.GetStringAnnotation("canary-by-header-pattern", ing)
	if err != nil {
		config.HeaderPattern = ""
	}

	config.Cookie, err = parser.GetStringAnnotation("canary-by-cookie", ing)
	if err != nil {
		config.Cookie = ""
	}

	if !config.Enabled && (config.Weight > 0 || len(config.Header) > 0 || len(config.HeaderValue) > 0 || len(config.Cookie) > 0 ||
		len(config.HeaderPattern) > 0) {
		return nil, errors.NewInvalidAnnotationConfiguration("canary", "configured but not enabled")
	}

	return config, nil
}

// ParseByMCI parses the annotations contained in the multiclusteringress
// rule used to indicate if the canary should be enabled and with what config
func (c canary) ParseByMCI(mci *karmadanetworking.MultiClusterIngress) (interface{}, error) {
	config := &Config{}
	var err error

	config.Enabled, err = parser.GetBoolAnnotationFromMCI("canary", mci)
	if err != nil {
		config.Enabled = false
	}

	config.Weight, err = parser.GetIntAnnotationFromMCI("canary-weight", mci)
	if err != nil {
		config.Weight = 0
	}

	config.WeightTotal, err = parser.GetIntAnnotationFromMCI("canary-weight-total", mci)
	if err != nil {
		config.WeightTotal = 100
	}

	config.Header, err = parser.GetStringAnnotationFromMCI("canary-by-header", mci)
	if err != nil {
		config.Header = ""
	}

	config.HeaderValue, err = parser.GetStringAnnotationFromMCI("canary-by-header-value", mci)
	if err != nil {
		config.HeaderValue = ""
	}

	config.HeaderPattern, err = parser.GetStringAnnotationFromMCI("canary-by-header-pattern", mci)
	if err != nil {
		config.HeaderPattern = ""
	}

	config.Cookie, err = parser.GetStringAnnotationFromMCI("canary-by-cookie", mci)
	if err != nil {
		config.Cookie = ""
	}

	if !config.Enabled && (config.Weight > 0 || len(config.Header) > 0 || len(config.HeaderValue) > 0 || len(config.Cookie) > 0 ||
		len(config.HeaderPattern) > 0) {
		return nil, errors.NewInvalidAnnotationConfiguration("canary", "configured but not enabled")
	}

	return config, nil
}
