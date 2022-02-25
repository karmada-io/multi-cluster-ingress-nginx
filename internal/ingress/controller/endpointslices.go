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

package controller

import (
	"fmt"
	"net"
	"reflect"
	"strconv"
	"strings"

	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/apimachinery/pkg/util/validation"
	"k8s.io/ingress-nginx/internal/ingress"
	"k8s.io/ingress-nginx/internal/k8s"
	"k8s.io/klog/v2"
)

// getEndpointsByEps returns a slice of ingress.Endpoint for a given service/target port combination.
func getEndpointsByEps(svc *corev1.Service, svcPort *corev1.ServicePort, proto corev1.Protocol,
	getServiceEndpointSlices func(string) ([]*discoveryv1.EndpointSlice, error)) []ingress.Endpoint {

	upsServers := make([]ingress.Endpoint, 0)
	// using a map avoids duplicated upstream servers when the service
	// contains multiple svcPort definitions sharing the same targetPort
	processedUpstreamServers := make(map[string]struct{})

	if svc == nil || svcPort == nil {
		return upsServers
	}
	svcKey := k8s.MetaNamespaceKey(svc)

	// ExternalName services
	if svc.Spec.Type == corev1.ServiceTypeExternalName {
		if ip := net.ParseIP(svc.Spec.ExternalName); svc.Spec.ExternalName == "localhost" ||
			(ip != nil && ip.IsLoopback()) {
			klog.Errorf("Invalid attempt to use localhost name %s in %q", svc.Spec.ExternalName, svcKey)
			return upsServers
		}

		klog.V(3).Infof("Ingress using Service %q of type ExternalName.", svcKey)
		targetPort := svcPort.TargetPort.IntValue()
		// if the externalName is not an IP address we need to validate is a valid FQDN
		if net.ParseIP(svc.Spec.ExternalName) == nil {
			externalName := strings.TrimSuffix(svc.Spec.ExternalName, ".")
			if errs := validation.IsDNS1123Subdomain(externalName); len(errs) > 0 {
				klog.Errorf("Invalid DNS name %s: %v", svc.Spec.ExternalName, errs)
				return upsServers
			}
		}

		return append(upsServers, ingress.Endpoint{
			Address: svc.Spec.ExternalName,
			Port:    fmt.Sprintf("%v", targetPort),
		})
	}

	klog.V(3).Infof("Getting Endpoints for Service %q and svcPort %v", svcKey, svcPort.String())
	endpointSlices, err := getServiceEndpointSlices(svcKey)
	if err != nil {
		klog.Errorf("Error obtaining EndpointSlices for Service %q: %v", svcKey, err)
		return upsServers
	}

	for _, endpointSlice := range endpointSlices {
		matchedPortNameFound := false
		for index, epPort := range endpointSlice.Ports {
			if !reflect.DeepEqual(*epPort.Protocol, proto) {
				continue
			}

			var targetPort int32
			if svcPort.Name == "" {
				// svcPort.Name is optional if there is only one port
				targetPort = *epPort.Port
				matchedPortNameFound = true
			} else if svcPort.Name == *epPort.Name {
				targetPort = *epPort.Port
				matchedPortNameFound = true
			}

			if index == len(endpointSlice.Ports)-1 && !matchedPortNameFound && svcPort.TargetPort.Type == intstr.Int {
				// use service target port if it's a number and no port name matched
				// https://github.com/kubernetes/ingress-nginx/issues/7390
				targetPort = svcPort.TargetPort.IntVal
			}
			if targetPort <= 0 {
				continue
			}

			for _, endpoint := range endpointSlice.Endpoints {
				for _, address := range endpoint.Addresses {
					epStr := net.JoinHostPort(address, strconv.Itoa(int(targetPort)))
					if _, exist := processedUpstreamServers[epStr]; exist {
						continue
					}
					upServer := ingress.Endpoint{
						Address: address,
						Port:    fmt.Sprintf("%v", targetPort),
						Target:  endpoint.TargetRef,
					}
					upsServers = append(upsServers, upServer)
					processedUpstreamServers[epStr] = struct{}{}
				}
			}
		}
	}

	klog.V(3).Infof("Endpoints found for Service %q: %+v", svcKey, upsServers)
	return upsServers
}
