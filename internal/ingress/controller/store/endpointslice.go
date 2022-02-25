/*
Copyright 2015 The Kubernetes Authors.

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

package store

import (
	"fmt"
	"strings"

	discoveryv1 "k8s.io/api/discovery/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/tools/cache"
)

// EndpointSliceLister makes a Store that lists EndpointSlices.
type EndpointSliceLister struct {
	cache.Store
}

// ByKey returns the EndpointSlices of the Service matching key in the local EndpointSlice Store.
func (s *EndpointSliceLister) ByKey(key string) ([]*discoveryv1.EndpointSlice, error) {
	values := strings.Split(key, "/")
	if len(values) != 2 {
		return nil, fmt.Errorf("key %s is invalid", key)
	}

	namespace, name := values[0], values[1]
	epsSelector := labels.SelectorFromSet(labels.Set{
		discoveryv1.LabelServiceName: name,
	})

	machetes := make([]*discoveryv1.EndpointSlice, 0)
	for _, m := range s.List() {
		eps := m.(*discoveryv1.EndpointSlice)
		if eps.Namespace == namespace && epsSelector.Matches(labels.Set(eps.GetLabels())) {
			machetes = append(machetes, eps)
		}
	}

	return machetes, nil
}
