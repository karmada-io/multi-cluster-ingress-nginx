package controller

import (
	"fmt"
	"sort"
	"strings"
	"time"

	karmadanetwork "github.com/karmada-io/karmada/pkg/apis/networking/v1alpha1"
	apiv1 "k8s.io/api/core/v1"
	networking "k8s.io/api/networking/v1"
	apiequality "k8s.io/apimachinery/pkg/api/equality"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/klog/v2"

	"k8s.io/ingress-nginx/internal/ingress"
	"k8s.io/ingress-nginx/internal/ingress/annotations"
	"k8s.io/ingress-nginx/internal/ingress/annotations/log"
	"k8s.io/ingress-nginx/internal/ingress/annotations/parser"
	"k8s.io/ingress-nginx/internal/ingress/annotations/proxy"
	"k8s.io/ingress-nginx/internal/ingress/controller/store"
	"k8s.io/ingress-nginx/internal/ingress/errors"
	"k8s.io/ingress-nginx/internal/k8s"
	"k8s.io/ingress-nginx/internal/karmada"
)

// getConfigurationFromMCI returns the configuration matching the multiclusteringress
func (n *NGINXController) getConfigurationFromMCI(mcis []*ingress.MultiClusterIngress) (sets.String, []*ingress.Server, *ingress.Configuration) {
	upstreams, servers := n.getBackendServersFromMCIs(mcis)
	var passUpstreams []*ingress.SSLPassthroughBackend

	hosts := sets.NewString()

	for _, server := range servers {
		// If a location is defined by a prefix string that ends with the slash character, and requests are processed by one of
		// proxy_pass, fastcgi_pass, uwsgi_pass, scgi_pass, memcached_pass, or grpc_pass, then the special processing is performed.
		// In response to a request with URI equal to // this string, but without the trailing slash, a permanent redirect with the
		// code 301 will be returned to the requested URI with the slash appended. If this is not desired, an exact match of the
		// URIand location could be defined like this:
		//
		// location /user/ {
		//     proxy_pass http://user.example.com;
		// }
		// location = /user {
		//     proxy_pass http://login.example.com;
		// }
		server.Locations = updateServerLocations(server.Locations)

		if !hosts.Has(server.Hostname) {
			hosts.Insert(server.Hostname)
		}

		for _, alias := range server.Aliases {
			if !hosts.Has(alias) {
				hosts.Insert(alias)
			}
		}

		if !server.SSLPassthrough {
			continue
		}

		for _, loc := range server.Locations {
			if loc.Path != rootLocation {
				klog.Warningf("Ignoring SSL Passthrough for location %q in server %q", loc.Path, server.Hostname)
				continue
			}
			passUpstreams = append(passUpstreams, &ingress.SSLPassthroughBackend{
				Backend:  loc.Backend,
				Hostname: server.Hostname,
				Service:  loc.Service,
				Port:     loc.Port,
			})
			break
		}
	}

	return hosts, servers, &ingress.Configuration{
		Backends:              upstreams,
		Servers:               servers,
		TCPEndpoints:          n.getStreamServices(n.cfg.TCPConfigMapName, apiv1.ProtocolTCP),
		UDPEndpoints:          n.getStreamServices(n.cfg.UDPConfigMapName, apiv1.ProtocolUDP),
		PassthroughBackends:   passUpstreams,
		BackendConfigChecksum: n.store.GetBackendConfiguration().Checksum,
		DefaultSSLCertificate: n.getDefaultSSLCertificate(),
		StreamSnippets:        n.getStreamSnippetsFromMCIs(mcis),
	}
}

// getBackendServersFromMCI returns a list of Upstream and Server to be used by the
// backend.  An upstream can be used in multiple servers if the namespace,
// service name and port are the same.
func (n *NGINXController) getBackendServersFromMCIs(mcis []*ingress.MultiClusterIngress) ([]*ingress.Backend, []*ingress.Server) {
	defaultUpstream := n.getDefaultUpstream()
	upstreams := n.createUpstreamsFromMCIs(mcis, defaultUpstream)
	servers := n.createServersFromMCIs(mcis, upstreams, defaultUpstream)

	var canaryMCIs []*ingress.MultiClusterIngress

	for _, mci := range mcis {
		mciKey := k8s.MetaNamespaceKey(mci)
		anns := mci.ParsedAnnotations

		if !n.store.GetBackendConfiguration().AllowSnippetAnnotations {
			dropSnippetDirectives(anns, mciKey)
		}

		for _, rule := range mci.Spec.Rules {
			host := rule.Host
			if host == "" {
				host = defServerName
			}

			server := servers[host]
			if server == nil {
				server = servers[defServerName]
			}

			if rule.HTTP == nil &&
				host != defServerName {
				klog.V(3).Infof("MultiClusterIngress %q does not contain any HTTP rule, using default backend", mciKey)
				continue
			}

			if server.AuthTLSError == "" && anns.CertificateAuth.AuthTLSError != "" {
				server.AuthTLSError = anns.CertificateAuth.AuthTLSError
			}

			if server.CertificateAuth.CAFileName == "" {
				server.CertificateAuth = anns.CertificateAuth
				if server.CertificateAuth.Secret != "" && server.CertificateAuth.CAFileName == "" {
					klog.V(3).Infof("Secret %q has no 'ca.crt' key, mutual authentication disabled for MultiClusterIngress %q",
						server.CertificateAuth.Secret, mciKey)
				}
			} else {
				klog.V(3).Infof("Server %q is already configured for mutual authentication (MultiClusterIngress %q)",
					server.Hostname, mciKey)
			}

			if !n.store.GetBackendConfiguration().ProxySSLLocationOnly {
				if server.ProxySSL.CAFileName == "" {
					server.ProxySSL = anns.ProxySSL
					if server.ProxySSL.Secret != "" && server.ProxySSL.CAFileName == "" {
						klog.V(3).Infof("Secret %q has no 'ca.crt' key, client cert authentication disabled for MultiClusterIngress %q",
							server.ProxySSL.Secret, mciKey)
					}
				} else {
					klog.V(3).Infof("Server %q is already configured for client cert authentication (MultiClusterIngress %q)",
						server.Hostname, mciKey)
				}
			}

			if rule.HTTP == nil {
				klog.V(3).Infof("MultiClusterIngress %q does not contain any HTTP rule, using default backend", mciKey)
				continue
			}

			for _, path := range rule.HTTP.Paths {
				if path.Backend.Service == nil {
					// skip non-service backends
					klog.V(3).Infof("MultiClusterIngress %q and path %q does not contain a service backend, using default backend", mciKey, path.Path)
					continue
				}

				upsName := upstreamName(mci.Namespace, path.Backend.Service)

				ups := upstreams[upsName]

				// Backend is not referenced to by a server
				if ups.NoServer {
					continue
				}

				nginxPath := rootLocation
				if path.Path != "" {
					nginxPath = path.Path
				}

				addLoc := true
				for _, loc := range server.Locations {
					if loc.Path != nginxPath {
						continue
					}

					// Same paths but different types are allowed
					// (same type means overlap in the path definition)
					if !apiequality.Semantic.DeepEqual(loc.PathType, path.PathType) {
						break
					}

					addLoc = false

					if !loc.IsDefBackend {
						klog.V(3).Infof("Location %q already configured for server %q with upstream %q (MultiClusterIngress %q)",
							loc.Path, server.Hostname, loc.Backend, mciKey)
						break
					}

					klog.V(3).Infof("Replacing location %q for server %q with upstream %q to use upstream %q (MultiClusterIngress %q)",
						loc.Path, server.Hostname, loc.Backend, ups.Name, mciKey)

					loc.Backend = ups.Name
					loc.IsDefBackend = false
					loc.Port = ups.Port
					loc.Service = ups.Service
					loc.MultiClusterIngress = mci

					locationApplyAnnotations(loc, anns)

					if loc.Redirect.FromToWWW {
						server.RedirectFromToWWW = true
					}

					break
				}

				// new location
				if addLoc {
					klog.V(3).Infof("Adding location %q for server %q with upstream %q (MultiClusterIngress %q)",
						nginxPath, server.Hostname, ups.Name, mciKey)
					loc := &ingress.Location{
						Path:                nginxPath,
						PathType:            path.PathType,
						Backend:             ups.Name,
						IsDefBackend:        false,
						Service:             ups.Service,
						Port:                ups.Port,
						MultiClusterIngress: mci,
					}
					locationApplyAnnotations(loc, anns)

					if loc.Redirect.FromToWWW {
						server.RedirectFromToWWW = true
					}
					server.Locations = append(server.Locations, loc)
				}

				if ups.SessionAffinity.AffinityType == "" {
					ups.SessionAffinity.AffinityType = anns.SessionAffinity.Type
				}

				if ups.SessionAffinity.AffinityMode == "" {
					ups.SessionAffinity.AffinityMode = anns.SessionAffinity.Mode
				}

				if anns.SessionAffinity.Type == "cookie" {
					cookiePath := anns.SessionAffinity.Cookie.Path
					if anns.Rewrite.UseRegex && cookiePath == "" {
						klog.Warningf("session-cookie-path should be set when use-regex is true")
					}

					ups.SessionAffinity.CookieSessionAffinity.Name = anns.SessionAffinity.Cookie.Name
					ups.SessionAffinity.CookieSessionAffinity.Expires = anns.SessionAffinity.Cookie.Expires
					ups.SessionAffinity.CookieSessionAffinity.MaxAge = anns.SessionAffinity.Cookie.MaxAge
					ups.SessionAffinity.CookieSessionAffinity.Secure = anns.SessionAffinity.Cookie.Secure
					ups.SessionAffinity.CookieSessionAffinity.Path = cookiePath
					ups.SessionAffinity.CookieSessionAffinity.SameSite = anns.SessionAffinity.Cookie.SameSite
					ups.SessionAffinity.CookieSessionAffinity.ConditionalSameSiteNone = anns.SessionAffinity.Cookie.ConditionalSameSiteNone
					ups.SessionAffinity.CookieSessionAffinity.ChangeOnFailure = anns.SessionAffinity.Cookie.ChangeOnFailure

					locs := ups.SessionAffinity.CookieSessionAffinity.Locations
					if _, ok := locs[host]; !ok {
						locs[host] = []string{}
					}
					locs[host] = append(locs[host], path.Path)

					if len(server.Aliases) > 0 {
						for _, alias := range server.Aliases {
							if _, ok := locs[alias]; !ok {
								locs[alias] = []string{}
							}
							locs[alias] = append(locs[alias], path.Path)
						}
					}
				}
			}
		}

		// set aside canary ingresses to merge later
		if anns.Canary.Enabled {
			canaryMCIs = append(canaryMCIs, mci)
		}
	}

	if nonCanaryMCIExists(mcis, canaryMCIs) {
		for _, canaryMCI := range canaryMCIs {
			mergeAlternativeBackendsByMCI(canaryMCI, upstreams, servers)
		}
	}

	aUpstreams := make([]*ingress.Backend, 0, len(upstreams))

	for _, upstream := range upstreams {
		aUpstreams = append(aUpstreams, upstream)

		if upstream.Name == defUpstreamName {
			continue
		}

		isHTTPSfrom := []*ingress.Server{}
		for _, server := range servers {
			for _, location := range server.Locations {
				// use default backend
				if !shouldCreateUpstreamForLocationDefaultBackend(upstream, location) {
					continue
				}

				if len(location.DefaultBackend.Spec.Ports) == 0 {
					klog.Errorf("Custom default backend service %v/%v has no ports. Ignoring", location.DefaultBackend.Namespace, location.DefaultBackend.Name)
					continue
				}

				sp := location.DefaultBackend.Spec.Ports[0]
				endps := getEndpoints(location.DefaultBackend, &sp, apiv1.ProtocolTCP, n.store.GetServiceEndpoints)
				// custom backend is valid only if contains at least one endpoint
				if len(endps) > 0 {
					name := fmt.Sprintf("custom-default-backend-%v-%v", location.DefaultBackend.GetNamespace(), location.DefaultBackend.GetName())
					klog.V(3).Infof("Creating \"%v\" upstream based on default backend annotation", name)

					nb := upstream.DeepCopy()
					nb.Name = name
					nb.Endpoints = endps
					aUpstreams = append(aUpstreams, nb)
					location.DefaultBackendUpstreamName = name

					if len(upstream.Endpoints) == 0 {
						klog.V(3).Infof("Upstream %q has no active Endpoint, so using custom default backend for location %q in server %q (Service \"%v/%v\")",
							upstream.Name, location.Path, server.Hostname, location.DefaultBackend.Namespace, location.DefaultBackend.Name)

						location.Backend = name
					}
				}

				if server.SSLPassthrough {
					if location.Path == rootLocation {
						if location.Backend == defUpstreamName {
							klog.Warningf("Server %q has no default backend, ignoring SSL Passthrough.", server.Hostname)
							continue
						}
						isHTTPSfrom = append(isHTTPSfrom, server)
					}
				}
			}
		}

		if len(isHTTPSfrom) > 0 {
			upstream.SSLPassthrough = true
		}
	}

	aServers := make([]*ingress.Server, 0, len(servers))
	for _, value := range servers {
		sort.SliceStable(value.Locations, func(i, j int) bool {
			return value.Locations[i].Path > value.Locations[j].Path
		})

		sort.SliceStable(value.Locations, func(i, j int) bool {
			return len(value.Locations[i].Path) > len(value.Locations[j].Path)
		})
		aServers = append(aServers, value)
	}

	sort.SliceStable(aUpstreams, func(a, b int) bool {
		return aUpstreams[a].Name < aUpstreams[b].Name
	})

	sort.SliceStable(aServers, func(i, j int) bool {
		return aServers[i].Hostname < aServers[j].Hostname
	})

	return aUpstreams, aServers
}

// createUpstreamsFromMCI creates the NGINX upstreams (Endpoints) for each Service
// referenced in MultiClusterIngress rules.
func (n *NGINXController) createUpstreamsFromMCIs(mcis []*ingress.MultiClusterIngress, defaultUpstream *ingress.Backend) map[string]*ingress.Backend {
	upstreams := make(map[string]*ingress.Backend)
	upstreams[defUpstreamName] = defaultUpstream

	for _, mci := range mcis {
		mciKey := k8s.MetaNamespaceKey(mci)
		anns := mci.ParsedAnnotations

		if !n.store.GetBackendConfiguration().AllowSnippetAnnotations {
			dropSnippetDirectives(anns, mciKey)
		}

		var defBackend string
		if mci.Spec.DefaultBackend != nil && mci.Spec.DefaultBackend.Service != nil {
			defBackend = upstreamName(mci.Namespace, mci.Spec.DefaultBackend.Service)

			klog.V(3).Infof("Creating upstream %q", defBackend)
			upstreams[defBackend] = newUpstream(defBackend)

			upstreams[defBackend].UpstreamHashBy.UpstreamHashBy = anns.UpstreamHashBy.UpstreamHashBy
			upstreams[defBackend].UpstreamHashBy.UpstreamHashBySubset = anns.UpstreamHashBy.UpstreamHashBySubset
			upstreams[defBackend].UpstreamHashBy.UpstreamHashBySubsetSize = anns.UpstreamHashBy.UpstreamHashBySubsetSize

			upstreams[defBackend].LoadBalancing = anns.LoadBalancing
			if upstreams[defBackend].LoadBalancing == "" {
				upstreams[defBackend].LoadBalancing = n.store.GetBackendConfiguration().LoadBalancing
			}

			svcKey := fmt.Sprintf("%v/%v", mci.Namespace, mci.Spec.DefaultBackend.Service.Name)

			// add the service ClusterIP as a single Endpoint instead of individual Endpoints
			if anns.ServiceUpstream {
				endpoint, err := n.getServiceClusterEndpoint(svcKey, mci.Spec.DefaultBackend)
				if err != nil {
					klog.Errorf("Failed to determine a suitable ClusterIP Endpoint for Service %q: %v", svcKey, err)
				} else {
					upstreams[defBackend].Endpoints = []ingress.Endpoint{endpoint}
				}
			}

			// configure traffic shaping for canary
			if anns.Canary.Enabled {
				upstreams[defBackend].NoServer = true
				upstreams[defBackend].TrafficShapingPolicy = ingress.TrafficShapingPolicy{
					Weight:        anns.Canary.Weight,
					WeightTotal:   anns.Canary.WeightTotal,
					Header:        anns.Canary.Header,
					HeaderValue:   anns.Canary.HeaderValue,
					HeaderPattern: anns.Canary.HeaderPattern,
					Cookie:        anns.Canary.Cookie,
				}
			}

			if len(upstreams[defBackend].Endpoints) == 0 {
				_, port := upstreamServiceNameAndPort(mci.Spec.DefaultBackend.Service)
				endps, err := n.serviceEndpoints(svcKey, port.String())
				upstreams[defBackend].Endpoints = append(upstreams[defBackend].Endpoints, endps...)
				if err != nil {
					klog.Warningf("Error creating upstream %q: %v", defBackend, err)
				}
			}

			s, err := n.store.GetService(svcKey)
			if err != nil {
				klog.Warningf("Error obtaining Service %q: %v", svcKey, err)
			}
			upstreams[defBackend].Service = s
		}

		for _, rule := range mci.Spec.Rules {
			if rule.HTTP == nil {
				continue
			}

			for _, path := range rule.HTTP.Paths {
				if path.Backend.Service == nil {
					// skip non-service backends
					klog.V(3).Infof("MultiClusterIngress %q and path %q does not contain a service backend, using default backend", mciKey, path.Path)
					continue
				}

				name := upstreamName(mci.Namespace, path.Backend.Service)
				svcName, svcPort := upstreamServiceNameAndPort(path.Backend.Service)
				if _, ok := upstreams[name]; ok {
					continue
				}

				klog.V(3).Infof("Creating upstream %q", name)
				upstreams[name] = newUpstream(name)
				upstreams[name].Port = svcPort

				upstreams[name].UpstreamHashBy.UpstreamHashBy = anns.UpstreamHashBy.UpstreamHashBy
				upstreams[name].UpstreamHashBy.UpstreamHashBySubset = anns.UpstreamHashBy.UpstreamHashBySubset
				upstreams[name].UpstreamHashBy.UpstreamHashBySubsetSize = anns.UpstreamHashBy.UpstreamHashBySubsetSize

				upstreams[name].LoadBalancing = anns.LoadBalancing
				if upstreams[name].LoadBalancing == "" {
					upstreams[name].LoadBalancing = n.store.GetBackendConfiguration().LoadBalancing
				}

				svcKey := fmt.Sprintf("%v/%v", mci.Namespace, svcName)

				// add the service ClusterIP as a single Endpoint instead of individual Endpoints
				if anns.ServiceUpstream {
					endpoint, err := n.getServiceClusterEndpoint(svcKey, &path.Backend)
					if err != nil {
						klog.Errorf("Failed to determine a suitable ClusterIP Endpoint for Service %q: %v", svcKey, err)
					} else {
						upstreams[name].Endpoints = []ingress.Endpoint{endpoint}
					}
				}

				// configure traffic shaping for canary
				if anns.Canary.Enabled {
					upstreams[name].NoServer = true
					upstreams[name].TrafficShapingPolicy = ingress.TrafficShapingPolicy{
						Weight:        anns.Canary.Weight,
						Header:        anns.Canary.Header,
						HeaderValue:   anns.Canary.HeaderValue,
						HeaderPattern: anns.Canary.HeaderPattern,
						Cookie:        anns.Canary.Cookie,
					}
				}

				if len(upstreams[name].Endpoints) == 0 {
					_, port := upstreamServiceNameAndPort(path.Backend.Service)
					endp, err := n.serviceEndpoints(svcKey, port.String())
					if err != nil {
						klog.Warningf("Error obtaining Endpoints for Service %q: %v", svcKey, err)
						continue
					}
					upstreams[name].Endpoints = endp
				}

				s, err := n.store.GetService(svcKey)
				if err != nil {
					klog.Warningf("Error obtaining Service %q: %v", svcKey, err)
					continue
				}

				upstreams[name].Service = s
			}
		}
	}

	return upstreams
}

// createServersFromMCI builds a map of host name to Server structs from a map of
// already computed Upstream structs. Each Server is configured with at least
// one root location, which uses a default backend if left unspecified.
func (n *NGINXController) createServersFromMCIs(mcis []*ingress.MultiClusterIngress,
	upstreams map[string]*ingress.Backend,
	defaultUpstream *ingress.Backend) map[string]*ingress.Server {

	servers := make(map[string]*ingress.Server, len(mcis))
	allAliases := make(map[string][]string, len(mcis))

	bdef := n.store.GetDefaultBackend()
	ngxProxy := proxy.Config{
		BodySize:             bdef.ProxyBodySize,
		ConnectTimeout:       bdef.ProxyConnectTimeout,
		SendTimeout:          bdef.ProxySendTimeout,
		ReadTimeout:          bdef.ProxyReadTimeout,
		BuffersNumber:        bdef.ProxyBuffersNumber,
		BufferSize:           bdef.ProxyBufferSize,
		CookieDomain:         bdef.ProxyCookieDomain,
		CookiePath:           bdef.ProxyCookiePath,
		NextUpstream:         bdef.ProxyNextUpstream,
		NextUpstreamTimeout:  bdef.ProxyNextUpstreamTimeout,
		NextUpstreamTries:    bdef.ProxyNextUpstreamTries,
		RequestBuffering:     bdef.ProxyRequestBuffering,
		ProxyRedirectFrom:    bdef.ProxyRedirectFrom,
		ProxyBuffering:       bdef.ProxyBuffering,
		ProxyHTTPVersion:     bdef.ProxyHTTPVersion,
		ProxyMaxTempFileSize: bdef.ProxyMaxTempFileSize,
	}

	// initialize default server and root location
	pathTypePrefix := networking.PathTypePrefix
	servers[defServerName] = &ingress.Server{
		Hostname: defServerName,
		SSLCert:  n.getDefaultSSLCertificate(),
		Locations: []*ingress.Location{
			{
				Path:         rootLocation,
				PathType:     &pathTypePrefix,
				IsDefBackend: true,
				Backend:      defaultUpstream.Name,
				Proxy:        ngxProxy,
				Service:      defaultUpstream.Service,
				Logs: log.Config{
					Access:  n.store.GetBackendConfiguration().EnableAccessLogForDefaultBackend,
					Rewrite: false,
				},
			},
		}}

	// initialize all other servers
	for _, mci := range mcis {
		mciKey := k8s.MetaNamespaceKey(mci)
		anns := mci.ParsedAnnotations

		if !n.store.GetBackendConfiguration().AllowSnippetAnnotations {
			dropSnippetDirectives(anns, mciKey)
		}

		// default upstream name
		un := defaultUpstream.Name

		if anns.Canary.Enabled {
			klog.V(2).Infof("MultiClusterIngress %v is marked as Canary, ignoring", mciKey)
			continue
		}

		if mci.Spec.DefaultBackend != nil && mci.Spec.DefaultBackend.Service != nil {
			defUpstream := upstreamName(mci.Namespace, mci.Spec.DefaultBackend.Service)

			if backendUpstream, ok := upstreams[defUpstream]; ok {
				// use backend specified in MultiClusterIngress as the default backend for all its rules
				un = backendUpstream.Name

				// special "catch all" case, MultiClusterIngress with a backend but no rule
				defLoc := servers[defServerName].Locations[0]
				defLoc.Backend = backendUpstream.Name
				defLoc.Service = backendUpstream.Service
				defLoc.MultiClusterIngress = mci

				if defLoc.IsDefBackend && len(mci.Spec.Rules) == 0 {
					klog.V(2).Infof("MultiClusterIngress %q defines a backend but no rule. Using it to configure the catch-all server %q", mciKey, defServerName)

					defLoc.IsDefBackend = false

					// TODO: Redirect and rewrite can affect the catch all behavior, skip for now
					originalRedirect := defLoc.Redirect
					originalRewrite := defLoc.Rewrite
					locationApplyAnnotations(defLoc, anns)
					defLoc.Redirect = originalRedirect
					defLoc.Rewrite = originalRewrite
				} else {
					klog.V(3).Infof("MultiClusterIngress %q defines both a backend and rules. Using its backend as default upstream for all its rules.", mciKey)
				}
			}
		}

		for _, rule := range mci.Spec.Rules {
			host := rule.Host
			if host == "" {
				host = defServerName
			}

			if _, ok := servers[host]; ok {
				// server already configured
				continue
			}

			loc := &ingress.Location{
				Path:                rootLocation,
				PathType:            &pathTypePrefix,
				IsDefBackend:        true,
				Backend:             un,
				MultiClusterIngress: mci,
				Service:             &apiv1.Service{},
			}
			locationApplyAnnotations(loc, anns)

			servers[host] = &ingress.Server{
				Hostname: host,
				Locations: []*ingress.Location{
					loc,
				},
				SSLPassthrough:         anns.SSLPassthrough,
				SSLCiphers:             anns.SSLCipher.SSLCiphers,
				SSLPreferServerCiphers: anns.SSLCipher.SSLPreferServerCiphers,
			}
		}
	}

	// configure default location, alias, and SSL
	for _, mci := range mcis {
		mciKey := k8s.MetaNamespaceKey(mci)
		anns := mci.ParsedAnnotations

		if !n.store.GetBackendConfiguration().AllowSnippetAnnotations {
			dropSnippetDirectives(anns, mciKey)
		}

		if anns.Canary.Enabled {
			klog.V(2).Infof("MultiClusterIngress %v is marked as Canary, ignoring", mciKey)
			continue
		}

		for _, rule := range mci.Spec.Rules {
			host := rule.Host
			if host == "" {
				host = defServerName
			}

			if len(servers[host].Aliases) == 0 {
				servers[host].Aliases = anns.Aliases
				if aliases := allAliases[host]; len(aliases) == 0 {
					allAliases[host] = anns.Aliases
				}
			} else {
				klog.Warningf("Aliases already configured for server %q, skipping (MultiClusterIngress %q)", host, mciKey)
			}

			if anns.ServerSnippet != "" {
				if servers[host].ServerSnippet == "" {
					servers[host].ServerSnippet = anns.ServerSnippet
				} else {
					klog.Warningf("Server snippet already configured for server %q, skipping (MultiClusterIngress %q)",
						host, mciKey)
				}
			}

			// only add SSL ciphers if the server does not have them previously configured
			if servers[host].SSLCiphers == "" && anns.SSLCipher.SSLCiphers != "" {
				servers[host].SSLCiphers = anns.SSLCipher.SSLCiphers
			}

			// only add SSLPreferServerCiphers if the server does not have them previously configured
			if servers[host].SSLPreferServerCiphers == "" && anns.SSLCipher.SSLPreferServerCiphers != "" {
				servers[host].SSLPreferServerCiphers = anns.SSLCipher.SSLPreferServerCiphers
			}

			// only add a certificate if the server does not have one previously configured
			if servers[host].SSLCert != nil {
				continue
			}

			if len(mci.Spec.TLS) == 0 {
				klog.V(3).Infof("MultiClusterIngress %q does not contains a TLS section.", mciKey)
				continue
			}

			tlsSecretName := extractTLSSecretNameFromMCI(host, mci, n.store.GetLocalSSLCert)
			if tlsSecretName == "" {
				klog.V(3).Infof("Host %q is listed in the TLS section but secretName is empty. Using default certificate", host)
				servers[host].SSLCert = n.getDefaultSSLCertificate()
				continue
			}

			secrKey := fmt.Sprintf("%v/%v", mci.Namespace, tlsSecretName)
			cert, err := n.store.GetLocalSSLCert(secrKey)
			if err != nil {
				klog.Warningf("Error getting SSL certificate %q: %v. Using default certificate", secrKey, err)
				servers[host].SSLCert = n.getDefaultSSLCertificate()
				continue
			}

			if cert.Certificate == nil {
				klog.Warningf("SSL certificate %q does not contain a valid SSL certificate for server %q", secrKey, host)
				klog.Warningf("Using default certificate")
				servers[host].SSLCert = n.getDefaultSSLCertificate()
				continue
			}

			err = cert.Certificate.VerifyHostname(host)
			if err != nil {
				klog.Warningf("Unexpected error validating SSL certificate %q for server %q: %v", secrKey, host, err)
				klog.Warning("Validating certificate against DNS names. This will be deprecated in a future version")
				// check the Common Name field
				// https://github.com/golang/go/issues/22922
				err := verifyHostname(host, cert.Certificate)
				if err != nil {
					klog.Warningf("SSL certificate %q does not contain a Common Name or Subject Alternative Name for server %q: %v", secrKey, host, err)
					klog.Warningf("Using default certificate")
					servers[host].SSLCert = n.getDefaultSSLCertificate()
					continue
				}
			}

			servers[host].SSLCert = cert

			now := time.Now()
			if cert.ExpireTime.Before(now) {
				klog.Warningf("SSL certificate for server %q expired (%v)", host, cert.ExpireTime)
			} else if cert.ExpireTime.Before(now.Add(240 * time.Hour)) {
				klog.Warningf("SSL certificate for server %q is about to expire (%v)", host, cert.ExpireTime)
			}
		}
	}

	for host, hostAliases := range allAliases {
		if _, ok := servers[host]; !ok {
			continue
		}

		uniqAliases := sets.NewString()
		for _, alias := range hostAliases {
			if alias == host {
				continue
			}

			if _, ok := servers[alias]; ok {
				continue
			}

			if uniqAliases.Has(alias) {
				continue
			}

			uniqAliases.Insert(alias)
		}

		servers[host].Aliases = uniqAliases.List()
	}

	return servers
}

// extractTLSSecretNameFromMCI returns the name of the Secret containing a SSL
// certificate for the given host name, or an empty string.
func extractTLSSecretNameFromMCI(host string, mci *ingress.MultiClusterIngress,
	getLocalSSLCert func(string) (*ingress.SSLCert, error)) string {

	if mci == nil {
		return ""
	}

	// naively return Secret name from TLS spec if host name matches
	lowercaseHost := toLowerCaseASCII(host)
	for _, tls := range mci.Spec.TLS {
		for _, tlsHost := range tls.Hosts {
			if toLowerCaseASCII(tlsHost) == lowercaseHost {
				return tls.SecretName
			}
		}
	}

	// no TLS host matching host name, try each TLS host for matching SAN or CN
	for _, tls := range mci.Spec.TLS {

		if tls.SecretName == "" {
			// There's no secretName specified, so it will never be available
			continue
		}

		secrKey := fmt.Sprintf("%v/%v", mci.Namespace, tls.SecretName)

		cert, err := getLocalSSLCert(secrKey)
		if err != nil {
			klog.Warningf("Error getting SSL certificate %q: %v", secrKey, err)
			continue
		}

		if cert == nil || cert.Certificate == nil {
			continue
		}

		err = cert.Certificate.VerifyHostname(host)
		if err != nil {
			continue
		}
		klog.V(3).Infof("Found SSL certificate matching host %q: %q", host, secrKey)
		return tls.SecretName
	}

	return ""
}

// OK to merge canary multiclusteringresses iff there exists one or more multiclusteringresses to potentially merge into
func nonCanaryMCIExists(mcis []*ingress.MultiClusterIngress, canaryMCIs []*ingress.MultiClusterIngress) bool {
	return len(mcis)-len(canaryMCIs) > 0
}

// Compares an Ingress of a potential alternative backend's rules with each existing server and finds matching host + path pairs.
// If a match is found, we know that this server should back the alternative backend and add the alternative backend
// to a backend's alternative list.
// If no match is found, then the serverless backend is deleted.
func mergeAlternativeBackendsByMCI(mci *ingress.MultiClusterIngress, upstreams map[string]*ingress.Backend,
	servers map[string]*ingress.Server) {

	// merge catch-all alternative backends
	if mci.Spec.DefaultBackend != nil {
		upsName := upstreamName(mci.Namespace, mci.Spec.DefaultBackend.Service)

		altUps := upstreams[upsName]

		if altUps == nil {
			klog.Warningf("alternative backend %s has already been removed", upsName)
		} else {

			merged := false
			altEqualsPri := false

			for _, loc := range servers[defServerName].Locations {
				priUps := upstreams[loc.Backend]
				altEqualsPri = altUps.Name == priUps.Name
				if altEqualsPri {
					klog.Warningf("alternative upstream %s in Ingress %s/%s is primary upstream in Other Ingress for location %s%s!",
						altUps.Name, mci.Namespace, mci.Name, servers[defServerName].Hostname, loc.Path)
					break
				}

				if canMergeBackend(priUps, altUps) {
					klog.V(2).Infof("matching backend %v found for alternative backend %v",
						priUps.Name, altUps.Name)

					merged = mergeAlternativeBackendByMCI(mci, priUps, altUps)
				}
			}

			if !altEqualsPri && !merged {
				klog.Warningf("unable to find real backend for alternative backend %v. Deleting.", altUps.Name)
				delete(upstreams, altUps.Name)
			}
		}
	}

	for _, rule := range mci.Spec.Rules {
		host := rule.Host
		if host == "" {
			host = defServerName
		}

		for _, path := range rule.HTTP.Paths {
			if path.Backend.Service == nil {
				// skip non-service backends
				klog.V(3).Infof("Ingress %q and path %q does not contain a service backend, using default backend", k8s.MetaNamespaceKey(mci), path.Path)
				continue
			}

			upsName := upstreamName(mci.Namespace, path.Backend.Service)

			altUps := upstreams[upsName]

			if altUps == nil {
				klog.Warningf("alternative backend %s has already been removed", upsName)
				continue
			}

			merged := false
			altEqualsPri := false

			server, ok := servers[host]
			if !ok {
				klog.Errorf("cannot merge alternative backend %s into hostname %s that does not exist",
					altUps.Name,
					host)

				continue
			}

			// find matching paths
			for _, loc := range server.Locations {
				priUps := upstreams[loc.Backend]
				altEqualsPri = altUps.Name == priUps.Name
				if altEqualsPri {
					klog.Warningf("alternative upstream %s in Ingress %s/%s is primary upstream in Other Ingress for location %s%s!",
						altUps.Name, mci.Namespace, mci.Name, server.Hostname, loc.Path)
					break
				}

				if canMergeBackend(priUps, altUps) && loc.Path == path.Path && *loc.PathType == *path.PathType {
					klog.V(2).Infof("matching backend %v found for alternative backend %v",
						priUps.Name, altUps.Name)

					merged = mergeAlternativeBackendByMCI(mci, priUps, altUps)
				}
			}

			if !altEqualsPri && !merged {
				klog.Warningf("unable to find real backend for alternative backend %v. Deleting.", altUps.Name)
				delete(upstreams, altUps.Name)
			}
		}
	}
}

// Performs the merge action and checks to ensure that one two alternative backends do not merge into each other
func mergeAlternativeBackendByMCI(mci *ingress.MultiClusterIngress, priUps *ingress.Backend, altUps *ingress.Backend) bool {
	if priUps.NoServer {
		klog.Warningf("unable to merge alternative backend %v into primary backend %v because %v is a primary backend",
			altUps.Name, priUps.Name, priUps.Name)
		return false
	}

	for _, ab := range priUps.AlternativeBackends {
		if ab == altUps.Name {
			klog.V(2).Infof("skip merge alternative backend %v into %v, it's already present", altUps.Name, priUps.Name)
			return true
		}
	}

	if mci.ParsedAnnotations != nil && mci.ParsedAnnotations.SessionAffinity.CanaryBehavior != "legacy" {
		priUps.SessionAffinity.DeepCopyInto(&altUps.SessionAffinity)
	}

	priUps.AlternativeBackends =
		append(priUps.AlternativeBackends, altUps.Name)

	return true
}

func (n *NGINXController) getStreamSnippetsFromMCIs(mcis []*ingress.MultiClusterIngress) []string {
	snippets := make([]string, 0, len(mcis))
	for _, mci := range mcis {
		if mci.ParsedAnnotations.StreamSnippet == "" {
			continue
		}
		snippets = append(snippets, mci.ParsedAnnotations.StreamSnippet)
	}
	return snippets
}

func getRemovedMCIs(rucfg, newcfg *ingress.Configuration) []string {
	oldMCIs := sets.NewString()
	newMCIs := sets.NewString()

	for _, server := range rucfg.Servers {
		for _, location := range server.Locations {
			if location.MultiClusterIngress == nil {
				continue
			}

			mciKey := k8s.MetaNamespaceKey(location.MultiClusterIngress)
			if !oldMCIs.Has(mciKey) {
				oldMCIs.Insert(mciKey)
			}
		}
	}

	for _, server := range newcfg.Servers {
		for _, location := range server.Locations {
			if location.MultiClusterIngress == nil {
				continue
			}

			mciKey := k8s.MetaNamespaceKey(location.MultiClusterIngress)
			if !newMCIs.Has(mciKey) {
				newMCIs.Insert(mciKey)
			}
		}
	}

	return oldMCIs.Difference(newMCIs).List()
}

// CheckMCI returns an error in case the provided multiclusteringress, when added
// to the current configuration, generates an invalid configuration
func (n *NGINXController) CheckMCI(mci *karmadanetwork.MultiClusterIngress) error {
	startCheck := time.Now().UnixNano() / 1000000

	if mci == nil {
		// no multiclusteringress to add, no state change
		return nil
	}

	// Skip checks if the multiclusteringress is marked as deleted
	if !mci.DeletionTimestamp.IsZero() {
		return nil
	}

	if n.cfg.Namespace != "" && mci.ObjectMeta.Namespace != n.cfg.Namespace {
		klog.Warningf("ignoring multiclusteringress %v in namespace %v different from the namespace watched %s", mci.Name, mci.ObjectMeta.Namespace, n.cfg.Namespace)
		return nil
	}

	if n.cfg.DisableCatchAll && mci.Spec.DefaultBackend != nil {
		return fmt.Errorf("This deployment is trying to create a catch-all multiclusteringress while DisableCatchAll flag is set to true. Remove '.spec.backend' or set DisableCatchAll flag to false. ")
	}

	startRender := time.Now().UnixNano() / 1000000
	cfg := n.store.GetBackendConfiguration()
	cfg.Resolver = n.resolver

	var arrayBadWords []string
	if cfg.AnnotationValueWordBlocklist != "" {
		arrayBadWords = strings.Split(strings.TrimSpace(cfg.AnnotationValueWordBlocklist), ",")
	}

	for key, value := range mci.ObjectMeta.GetAnnotations() {
		if parser.AnnotationsPrefix != parser.DefaultAnnotationsPrefix {
			if strings.HasPrefix(key, fmt.Sprintf("%s/", parser.DefaultAnnotationsPrefix)) {
				return fmt.Errorf("This deployment has a custom annotation prefix defined. Use '%s' instead of '%s'", parser.AnnotationsPrefix, parser.DefaultAnnotationsPrefix)
			}
		}

		if strings.HasPrefix(key, fmt.Sprintf("%s/", parser.AnnotationsPrefix)) && len(arrayBadWords) != 0 {
			for _, forbiddenvalue := range arrayBadWords {
				if strings.Contains(value, strings.TrimSpace(forbiddenvalue)) {
					return fmt.Errorf("%s annotation contains invalid word %s", key, forbiddenvalue)
				}
			}
		}

		if !cfg.AllowSnippetAnnotations && strings.HasSuffix(key, "-snippet") {
			return fmt.Errorf("%s annotation cannot be used. Snippet directives are disabled by the MultiClusterIngress administrator", key)
		}

		if len(cfg.GlobalRateLimitMemcachedHost) == 0 && strings.HasPrefix(key, fmt.Sprintf("%s/%s", parser.AnnotationsPrefix, "global-rate-limit")) {
			return fmt.Errorf("'global-rate-limit*' annotations require 'global-rate-limit-memcached-host' settings configured in the global configmap")
		}

	}

	karmada.SetDefaultNGINXPathType(mci)

	allMCIs := n.store.ListMultiClusterIngresses()

	filter := func(toCheck *ingress.MultiClusterIngress) bool {
		return toCheck.ObjectMeta.Namespace == mci.ObjectMeta.Namespace &&
			toCheck.ObjectMeta.Name == mci.ObjectMeta.Name
	}
	mcis := store.FilterMultiClusterIngress(allMCIs, filter)
	mcis = append(mcis, &ingress.MultiClusterIngress{
		MultiClusterIngress: *mci,
		ParsedAnnotations:   annotations.NewAnnotationExtractor(n.store).ExtractFromMCI(mci),
	})
	startTest := time.Now().UnixNano() / 1000000
	_, servers, pcfg := n.getConfigurationFromMCI(mcis)

	err := checkOverlapWithMCI(mci, servers)
	if err != nil {
		n.metricCollector.IncCheckErrorCount(mci.ObjectMeta.Namespace, mci.Name)
		return err
	}
	testedSize := len(mcis)
	if n.cfg.DisableFullValidationTest {
		_, _, pcfg = n.getConfigurationFromMCI(mcis[len(mcis)-1:])
		testedSize = 1
	}

	content, err := n.generateTemplate(cfg, *pcfg)
	if err != nil {
		n.metricCollector.IncCheckErrorCount(mci.ObjectMeta.Namespace, mci.Name)
		return err
	}

	err = n.testTemplate(content)
	if err != nil {
		n.metricCollector.IncCheckErrorCount(mci.ObjectMeta.Namespace, mci.Name)
		return err
	}
	n.metricCollector.IncCheckCount(mci.ObjectMeta.Namespace, mci.Name)
	endCheck := time.Now().UnixNano() / 1000000
	n.metricCollector.SetAdmissionMetrics(
		float64(testedSize),
		float64(endCheck-startTest)/1000,
		float64(len(mcis)),
		float64(startTest-startRender)/1000,
		float64(len(content)),
		float64(endCheck-startCheck)/1000,
	)
	return nil
}

func checkOverlapWithMCI(mci *karmadanetwork.MultiClusterIngress, servers []*ingress.Server) error {
	for _, rule := range mci.Spec.Rules {
		if rule.HTTP == nil {
			continue
		}

		if rule.Host == "" {
			rule.Host = defServerName
		}

		for _, path := range rule.HTTP.Paths {
			if path.Backend.Service == nil {
				// skip non-service backends
				klog.V(3).Infof("MultiClusterIngress %q and path %q does not contain a service backend, using default backend", k8s.MetaNamespaceKey(mci), path.Path)
				continue
			}

			if path.Path == "" {
				path.Path = rootLocation
			}

			existingMCIs := mciForHostPath(rule.Host, path.Path, servers)

			// no previous ingress
			if len(existingMCIs) == 0 {
				continue
			}

			// same ingress
			skipValidation := false
			for _, existing := range existingMCIs {
				if existing.ObjectMeta.Namespace == mci.ObjectMeta.Namespace && existing.ObjectMeta.Name == mci.ObjectMeta.Name {
					return nil
				}
			}

			if skipValidation {
				continue
			}

			// path overlap. Check if one of the ingresses has a canary annotation
			isCanaryEnabled, annotationErr := parser.GetBoolAnnotationFromMCI("canary", mci)
			for _, existing := range existingMCIs {
				isExistingCanaryEnabled, existingAnnotationErr := parser.GetBoolAnnotationFromMCI("canary", existing)

				if isCanaryEnabled && isExistingCanaryEnabled {
					return fmt.Errorf(`host "%s" and path "%s" is already defined in multiclusteringress %s/%s`, rule.Host, path.Path, existing.Namespace, existing.Name)
				}

				if annotationErr == errors.ErrMissingAnnotations && existingAnnotationErr == errors.ErrMissingAnnotations {
					return fmt.Errorf(`host "%s" and path "%s" is already defined in multiclusteringress %s/%s`, rule.Host, path.Path, existing.Namespace, existing.Name)
				}
			}

			// no overlap
			return nil
		}
	}

	return nil
}

func mciForHostPath(hostname, path string, servers []*ingress.Server) []*karmadanetwork.MultiClusterIngress {
	mcis := make([]*karmadanetwork.MultiClusterIngress, 0)

	for _, server := range servers {
		if hostname != server.Hostname {
			continue
		}

		for _, location := range server.Locations {
			if location.Path != path {
				continue
			}

			if location.IsDefBackend {
				continue
			}

			mcis = append(mcis, &location.MultiClusterIngress.MultiClusterIngress)
		}
	}

	return mcis
}
