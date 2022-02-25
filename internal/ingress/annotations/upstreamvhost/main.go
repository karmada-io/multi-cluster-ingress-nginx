/*
Copyright 2017 The Kubernetes Authors.

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

package upstreamvhost

import (
	karmadanetworking "github.com/karmada-io/karmada/pkg/apis/networking/v1alpha1"
	networking "k8s.io/api/networking/v1"

	"k8s.io/ingress-nginx/internal/ingress/annotations/parser"
	"k8s.io/ingress-nginx/internal/ingress/resolver"
)

type upstreamVhost struct {
	r resolver.Resolver
}

// NewParser creates a new upstream VHost annotation parser
func NewParser(r resolver.Resolver) parser.IngressAnnotation {
	return upstreamVhost{r}
}

// Parse parses the annotations contained in the ingress rule
// used to indicate if the location/s contains a fragment of
// configuration to be included inside the paths of the rules
func (a upstreamVhost) Parse(ing *networking.Ingress) (interface{}, error) {
	return parser.GetStringAnnotation("upstream-vhost", ing)
}

// ParseByMCI parses the annotations contained in the multiclusteringress rule
// used to indicate if the location/s contains a fragment of
// configuration to be included inside the paths of the rules
func (a upstreamVhost) ParseByMCI(mci *karmadanetworking.MultiClusterIngress) (interface{}, error) {
	return parser.GetStringAnnotationFromMCI("upstream-vhost", mci)
}
