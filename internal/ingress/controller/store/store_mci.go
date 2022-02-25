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

package store

import (
	"fmt"
	"sort"

	karmadanetwork "github.com/karmada-io/karmada/pkg/apis/networking/v1alpha1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/klog/v2"

	"k8s.io/ingress-nginx/internal/ingress"
	"k8s.io/ingress-nginx/internal/ingress/annotations/parser"
	"k8s.io/ingress-nginx/internal/ingress/controller/ingressclass"
	"k8s.io/ingress-nginx/internal/ingress/errors"
	"k8s.io/ingress-nginx/internal/k8s"
	"k8s.io/ingress-nginx/internal/karmada"
)

func sortMultiClusterIngressSlice(multiclusteringresses []*ingress.MultiClusterIngress) {
	// sort Ingresses using the CreationTimestamp field
	sort.SliceStable(multiclusteringresses, func(i, j int) bool {
		ir := multiclusteringresses[i].CreationTimestamp
		jr := multiclusteringresses[j].CreationTimestamp
		if ir.Equal(&jr) {
			in := fmt.Sprintf("%v/%v", multiclusteringresses[i].Namespace, multiclusteringresses[i].Name)
			jn := fmt.Sprintf("%v/%v", multiclusteringresses[j].Namespace, multiclusteringresses[j].Name)
			klog.V(3).Infof("MultiClusterIngress %v and %v have identical CreationTimestamp", in, jn)
			return in > jn
		}
		return ir.Before(&jr)
	})
}

// ListMultiClusterIngresses returns the list of MultiClusterIngresses
func (s *k8sStore) ListMultiClusterIngresses() []*ingress.MultiClusterIngress {
	// filter multiclusteringress rules
	multiclusteringresses := make([]*ingress.MultiClusterIngress, 0)
	for _, item := range s.listers.MultiClusterIngressWithAnnotation.List() {
		mci := item.(*ingress.MultiClusterIngress)
		multiclusteringresses = append(multiclusteringresses, mci)
	}

	sortMultiClusterIngressSlice(multiclusteringresses)

	return multiclusteringresses
}

func (s *k8sStore) GetIngressClassByMCI(mci *karmadanetwork.MultiClusterIngress, icConfig *ingressclass.IngressClassConfiguration) (string, error) {
	// First we try ingressClassName
	if !icConfig.IgnoreIngressClass && mci.Spec.IngressClassName != nil {
		ingressClass, err := s.listers.IngressClass.ByKey(*mci.Spec.IngressClassName)
		if err != nil {
			return "", err
		}
		return ingressClass.Name, nil
	}

	// Then we try annotation
	if ingressClass, ok := mci.GetAnnotations()[ingressclass.IngressKey]; ok {
		if ingressClass != icConfig.AnnotationValue {
			return "", fmt.Errorf("ingress class annotation is not equal to the expected by Ingress Controller")
		}
		return ingressClass, nil
	}

	// Then we accept if the WithoutClass is enabled
	if icConfig.WatchWithoutClass {
		// Reserving "_" as a "wildcard" name
		return "_", nil
	}
	return "", fmt.Errorf("ingress does not contain a valid IngressClass")
}

// syncMultiClusterIngress parses multiclusteringress annotations
func (s *k8sStore) syncMultiClusterIngress(mci *karmadanetwork.MultiClusterIngress) {
	key := k8s.MetaNamespaceKey(mci)
	klog.V(3).Infof("updating annotations information for multiclusteringress %v", key)

	copyMci := &karmadanetwork.MultiClusterIngress{}
	mci.ObjectMeta.DeepCopyInto(&copyMci.ObjectMeta)

	if s.backendConfig.AnnotationValueWordBlocklist != "" {
		if err := checkBadAnnotationValue(copyMci.Annotations, s.backendConfig.AnnotationValueWordBlocklist); err != nil {
			klog.Warningf("skipping ingress %s: %s", key, err)
			return
		}
	}

	mci.Spec.DeepCopyInto(&copyMci.Spec)
	mci.Status.DeepCopyInto(&copyMci.Status)

	for ri, rule := range copyMci.Spec.Rules {
		if rule.HTTP == nil {
			continue
		}

		for pi, path := range rule.HTTP.Paths {
			if path.Path == "" {
				copyMci.Spec.Rules[ri].HTTP.Paths[pi].Path = "/"
			}
		}
	}

	karmada.SetDefaultNGINXPathType(copyMci)

	err := s.listers.MultiClusterIngressWithAnnotation.Update(&ingress.MultiClusterIngress{
		MultiClusterIngress: *copyMci,
		ParsedAnnotations:   s.annotations.ExtractFromMCI(mci),
	})
	if err != nil {
		klog.Error(err)
	}
}

// updateSecretMCIMap takes a MultiClusterIngress and updates all Secret objects it
// references in secretMCIMap.
func (s *k8sStore) updateSecretMCIMap(mci *karmadanetwork.MultiClusterIngress) {
	key := k8s.MetaNamespaceKey(mci)
	klog.V(3).Infof("updating references to secrets for multiclusteringress %v", key)

	// delete all existing references first
	s.secretMCIMap.Delete(key)

	var refSecrets []string

	for _, tls := range mci.Spec.TLS {
		secrName := tls.SecretName
		if secrName != "" {
			secrKey := fmt.Sprintf("%v/%v", mci.Namespace, secrName)
			refSecrets = append(refSecrets, secrKey)
		}
	}

	// We can not rely on cached ingress annotations because these are
	// discarded when the referenced secret does not exist in the local
	// store. As a result, adding a secret *after* the ingress(es) which
	// references it would not trigger a resync of that secret.
	secretAnnotations := []string{
		"auth-secret",
		"auth-tls-secret",
		"proxy-ssl-secret",
		"secure-verify-ca-secret",
	}
	for _, ann := range secretAnnotations {
		secrKey, err := objectRefAnnotationNsKeyFromMCI(ann, mci)
		if err != nil && !errors.IsMissingAnnotations(err) {
			klog.Errorf("error reading secret reference in annotation %q: %s", ann, err)
			continue
		}
		if secrKey != "" {
			refSecrets = append(refSecrets, secrKey)
		}
	}

	// populate map with all secret references
	s.secretMCIMap.Insert(key, refSecrets...)
}

// syncSecretsByMCI synchronizes data from all Secrets referenced by the given
// MultiClusterIngress with the local store and file system.
func (s *k8sStore) syncSecretsByMCI(mci *karmadanetwork.MultiClusterIngress) {
	key := k8s.MetaNamespaceKey(mci)
	for _, secrKey := range s.secretMCIMap.ReferencedBy(key) {
		s.syncSecret(secrKey)
	}
}

// getMultiClusterIngress returns the MultiClusterIngress matching key.
func (s *k8sStore) getMultiClusterIngress(key string) (*karmadanetwork.MultiClusterIngress, error) {
	mci, err := s.listers.MultiClusterIngressWithAnnotation.ByKey(key)
	if err != nil {
		return nil, err
	}

	return &mci.MultiClusterIngress, nil
}

func toMultiClusterIngress(obj interface{}) (*karmadanetwork.MultiClusterIngress, bool) {
	if mci, ok := obj.(*karmadanetwork.MultiClusterIngress); ok {
		karmada.SetDefaultNGINXPathType(mci)
		return mci, true
	}

	return nil, false
}

// objectRefAnnotationNsKeyFromMCI returns an object reference formatted as a
// 'namespace/name' key from the given annotation name.
func objectRefAnnotationNsKeyFromMCI(ann string, mci *karmadanetwork.MultiClusterIngress) (string, error) {
	annValue, err := parser.GetStringAnnotationFromMCI(ann, mci)
	if err != nil {
		return "", err
	}

	secrNs, secrName, err := cache.SplitMetaNamespaceKey(annValue)
	if secrName == "" {
		return "", err
	}

	if secrNs == "" {
		return fmt.Sprintf("%v/%v", mci.Namespace, secrName), nil
	}
	return annValue, nil
}
