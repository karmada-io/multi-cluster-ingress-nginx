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
	karmadanetwork "github.com/karmada-io/karmada/pkg/apis/networking/v1alpha1"
	"k8s.io/client-go/tools/cache"

	"k8s.io/ingress-nginx/internal/ingress"
)

// MultiClusterIngressLister makes a Store that lists MultiClusterIngress.
type MultiClusterIngressLister struct {
	cache.Store
}

// ByKey returns the MultiClusterIngress matching key in the local MultiClusterIngress Store.
func (mciLister MultiClusterIngressLister) ByKey(key string) (*karmadanetwork.MultiClusterIngress, error) {
	mci, exists, err := mciLister.GetByKey(key)
	if err != nil {
		return nil, err
	}
	if !exists {
		return nil, NotExistsError(key)
	}
	return mci.(*karmadanetwork.MultiClusterIngress), nil
}

// FilterMultiClusterIngress returns the list of MultiClusterIngresses.
func FilterMultiClusterIngress(mcis []*ingress.MultiClusterIngress, filterFunc MCIFilterFunc) []*ingress.MultiClusterIngress {
	afterFilter := make([]*ingress.MultiClusterIngress, 0)
	for _, mci := range mcis {
		if !filterFunc(mci) {
			afterFilter = append(afterFilter, mci)
		}
	}

	sortMultiClusterIngressSlice(afterFilter)
	return afterFilter
}
