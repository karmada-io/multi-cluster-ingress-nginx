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

package karmada

import (
	karmadanetwork "github.com/karmada-io/karmada/pkg/apis/networking/v1alpha1"
	networkingv1 "k8s.io/api/networking/v1"
)

// default path type is Prefix to not break existing definitions
var defaultPathType = networkingv1.PathTypePrefix

// SetDefaultNGINXPathType sets a default PathType when is not defined.
func SetDefaultNGINXPathType(mci *karmadanetwork.MultiClusterIngress) {
	for _, rule := range mci.Spec.Rules {
		if rule.IngressRuleValue.HTTP == nil {
			continue
		}

		for idx := range rule.IngressRuleValue.HTTP.Paths {
			p := &rule.IngressRuleValue.HTTP.Paths[idx]
			if p.PathType == nil {
				p.PathType = &defaultPathType
			}

			if *p.PathType == networkingv1.PathTypeImplementationSpecific {
				p.PathType = &defaultPathType
			}
		}
	}
}
