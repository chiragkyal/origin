package router

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	g "github.com/onsi/ginkgo/v2"
	o "github.com/onsi/gomega"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	admissionapi "k8s.io/pod-security-admission/api"

	configv1 "github.com/openshift/api/config/v1"
	routev1 "github.com/openshift/api/route/v1"
	"github.com/openshift/origin/test/extended/router/certgen"
	exutil "github.com/openshift/origin/test/extended/util"
	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/util/rand"
	"k8s.io/apimachinery/pkg/util/wait"
	e2e "k8s.io/kubernetes/test/e2e/framework"
	"k8s.io/kubernetes/test/e2e/framework/pod"
	e2eskipper "k8s.io/kubernetes/test/e2e/framework/skipper"
	k8simage "k8s.io/kubernetes/test/utils/image"
)

const (
	// secretReaderRole is the name of the Role allowing access to the secret.
	secretReaderRole = "secret-reader-role"
	// secretReaderRoleBinding is the name of the RoleBinding associating the Role with the router service account.
	secretReaderRoleBinding = "secret-reader-role-binding"
	// helloOpenShiftResponse is the HTTP response from hello-openshift example pod.
	helloOpenShiftResponse = "Hello OpenShift"
	// netexecResponse is the HTTP response from agnhost netexec server
	netexecResponse = "NOW"
	// defaultCertificateCN is the CommonName of router default certificate.
	defaultCertificateCN = "ingress-operator"
)

// isValidResponse checks if the HTTP response is valid for our test pods
func isValidResponse(response string) bool {
	// Accept either the original hello-openshift response or netexec response
	return strings.Contains(response, helloOpenShiftResponse) ||
		strings.Contains(response, netexecResponse) ||
		strings.Contains(response, "agnhost")
}

// skipIfRoutesNotExternallyReachable skips the test if routes are not externally reachable
// on the current platform. This commonly happens on baremetal and some on-prem setups
// where there's no external load balancer or DNS resolution for wildcard domains.
func skipIfRoutesNotExternallyReachable(oc *exutil.CLI) {
	// Check if internal testing is enabled via environment variable
	if os.Getenv("OPENSHIFT_SKIP_EXTERNAL_ROUTE_TESTS") == "false" {
		e2e.Logf("External route testing forced enabled via OPENSHIFT_SKIP_EXTERNAL_ROUTE_TESTS=false")
		return
	}

	infra, err := oc.AdminConfigClient().ConfigV1().Infrastructures().Get(context.Background(), "cluster", metav1.GetOptions{})
	o.Expect(err).NotTo(o.HaveOccurred(), "failed to get cluster-wide infrastructure")

	platformType := infra.Status.Platform
	if infra.Status.PlatformStatus != nil {
		platformType = infra.Status.PlatformStatus.Type
	}

	switch platformType {
	case configv1.BareMetalPlatformType:
		e2eskipper.Skipf("External route reachability tests are not supported on baremetal platforms without external DNS/LB. Set OPENSHIFT_SKIP_EXTERNAL_ROUTE_TESTS=false to test via internal connectivity.")
	case configv1.VSpherePlatformType, configv1.OvirtPlatformType, configv1.KubevirtPlatformType, configv1.LibvirtPlatformType:
		e2eskipper.Skipf("External route reachability tests may not be supported on platform %q without external DNS/LB. Set OPENSHIFT_SKIP_EXTERNAL_ROUTE_TESTS=false to test via internal connectivity.", platformType)
	case configv1.NonePlatformType:
		e2eskipper.Skipf("External route reachability tests are not supported on platform 'None' without external DNS/LB. Set OPENSHIFT_SKIP_EXTERNAL_ROUTE_TESTS=false to test via internal connectivity.")
	}

	// For cloud platforms, check if router is exposed via LoadBalancer
	if platformType == configv1.AWSPlatformType || platformType == configv1.AzurePlatformType || platformType == configv1.GCPPlatformType {
		svc, err := oc.AdminKubeClient().CoreV1().Services("openshift-ingress").Get(context.Background(), "router-default", metav1.GetOptions{})
		if err != nil || svc.Spec.Type != corev1.ServiceTypeLoadBalancer {
			e2eskipper.Skipf("Default router is not exposed by a load balancer service")
		}
	}
}

// getMicroShiftDefaultDomain gets the default domain for MicroShift clusters
// which may not have the full ingress.config.openshift.io API
func getMicroShiftDefaultDomain(oc *exutil.CLI) (string, error) {
	// Try to find an existing route and extract domain from it
	routes, err := oc.RouteClient().RouteV1().Routes("").List(context.Background(), metav1.ListOptions{})
	if err == nil && len(routes.Items) > 0 {
		for _, route := range routes.Items {
			if len(route.Status.Ingress) > 0 && route.Status.Ingress[0].Host != "" {
				// Extract domain from existing route hostname
				host := route.Status.Ingress[0].Host
				parts := strings.SplitN(host, ".", 3)
				if len(parts) >= 3 {
					// Format: routename.namespace.domain
					return parts[2], nil
				}
			}
		}
	}

	// Fallback: try to get from router service if it exists
	svc, err := oc.AdminKubeClient().CoreV1().Services("openshift-ingress").Get(context.Background(), "router-default", metav1.GetOptions{})
	if err == nil {
		// For MicroShift, often uses nip.io or similar
		if svc.Spec.ClusterIP != "" {
			return fmt.Sprintf("%s.nip.io", svc.Spec.ClusterIP), nil
		}
	}

	// Last resort fallback
	return "apps.microshift.local", nil
}

// getDefaultIngressClusterDomainNameMicroShiftAware gets the cluster domain with MicroShift fallback
func getDefaultIngressClusterDomainNameMicroShiftAware(oc *exutil.CLI, timeout time.Duration) (string, error) {
	// First try MicroShift detection
	isMicroShift, err := exutil.IsMicroShiftCluster(oc.AdminKubeClient())
	if err != nil {
		e2e.Logf("Failed to detect MicroShift: %v, trying standard method", err)
	}

	if isMicroShift {
		e2e.Logf("Detected MicroShift cluster, using alternative domain detection")
		return getMicroShiftDefaultDomain(oc)
	}

	// Standard OpenShift method
	return getDefaultIngressClusterDomainName(oc, timeout)
}

// getHostnameForRouteMicroShiftAware gets route hostname with MicroShift fallback
func getHostnameForRouteMicroShiftAware(oc *exutil.CLI, routeName string) (string, error) {
	var hostname string
	ns := oc.KubeFramework().Namespace.Name

	if err := wait.Poll(time.Second, changeTimeoutSeconds*time.Second, func() (bool, error) {
		route, err := oc.RouteClient().RouteV1().Routes(ns).Get(context.Background(), routeName, metav1.GetOptions{})
		if err != nil {
			e2e.Logf("Error getting hostname for route %q: %v", routeName, err)
			return false, err
		}

		// Check if route has hostname in status (standard case)
		if len(route.Status.Ingress) > 0 && len(route.Status.Ingress[0].Host) > 0 {
			hostname = route.Status.Ingress[0].Host
			return true, nil
		}

		// MicroShift fallback: construct hostname from spec.host if available
		if route.Spec.Host != "" {
			hostname = route.Spec.Host
			return true, nil
		}

		// Last resort: construct hostname based on route name and namespace
		isMicroShift, err := exutil.IsMicroShiftCluster(oc.AdminKubeClient())
		if err == nil && isMicroShift {
			defaultDomain, err := getMicroShiftDefaultDomain(oc)
			if err == nil {
				hostname = fmt.Sprintf("%s-%s.%s", routeName, ns, defaultDomain)
				e2e.Logf("MicroShift: constructed hostname %q for route %q", hostname, routeName)
				return true, nil
			}
		}

		return false, nil
	}); err != nil {
		return "", err
	}
	return hostname, nil
}

var _ = g.Describe("[sig-network][OCPFeatureGate:RouteExternalCertificate][Feature:Router][apigroup:route.openshift.io]", func() {
	defer g.GinkgoRecover()
	var (
		oc            = exutil.NewCLIWithPodSecurityLevel("router-external-certificate", admissionapi.LevelBaseline)
		helloPodPath  = exutil.FixturePath("..", "..", "examples", "hello-openshift", "hello-pod.json")
		helloPodName  = "hello-openshift"
		helloPodSvc   = "hello-openshift"
		defaultDomain string
		err           error
	)

	g.BeforeEach(func() {
		// Skip tests on platforms where routes are not externally reachable
		skipIfRoutesNotExternallyReachable(oc)

		defaultDomain, err = getDefaultIngressClusterDomainNameMicroShiftAware(oc, time.Minute)
		o.Expect(err).NotTo(o.HaveOccurred(), "failed to find default domain name")

		g.By("creating pod")
		err = createHelloOpenShiftPodWithFallback(oc, helloPodName, helloPodPath)
		o.Expect(err).NotTo(o.HaveOccurred())

		g.By("waiting for the pod to be running")
		err = pod.WaitForPodNameRunningInNamespace(context.TODO(), oc.KubeClient(), helloPodName, oc.Namespace())
		o.Expect(err).NotTo(o.HaveOccurred())

		g.By("creating service")
		err = oc.Run("expose").Args("pod", helloPodName, "-n", oc.Namespace()).Execute()
		o.Expect(err).NotTo(o.HaveOccurred())

		g.By("waiting for the service to become available")
		err = exutil.WaitForEndpoint(oc.KubeClient(), oc.Namespace(), helloPodSvc)
		o.Expect(err).NotTo(o.HaveOccurred())
	})

	g.Context("with invalid setup", func() {
		var host string
		g.BeforeEach(func() {
			host = oc.Namespace() + "." + defaultDomain
		})

		g.Describe("the router", func() {
			g.It("should not support external certificate without proper permissions", func() {
				g.By("Creating a TLS certificate secret")
				secret, _, err := generateTLSCertSecret(oc.Namespace(), "my-tls-secret", corev1.SecretTypeTLS, host)
				o.Expect(err).NotTo(o.HaveOccurred())
				_, err = oc.KubeClient().CoreV1().Secrets(oc.Namespace()).Create(context.Background(), secret, metav1.CreateOptions{})
				o.Expect(err).NotTo(o.HaveOccurred())

				g.By("Creating a route")
				route := generateRouteWithExternalCertificate(oc.Namespace(), "route", secret.Name, helloPodSvc, host, routev1.TLSTerminationEdge)
				_, err = oc.RouteClient().RouteV1().Routes(oc.Namespace()).Create(context.Background(), route, metav1.CreateOptions{})
				o.Expect(err).To(o.HaveOccurred())
				o.Expect(err.Error()).To(o.And(
					o.ContainSubstring("Forbidden: router serviceaccount does not have permission to get this secret"),
					o.ContainSubstring("Forbidden: router serviceaccount does not have permission to watch this secret"),
					o.ContainSubstring("Forbidden: router serviceaccount does not have permission to list this secret")),
				)
			})

			g.It("should not support external certificate if the secret is in a different namespace", func() {
				g.By("Creating a new namespace")
				differentNamespace := fmt.Sprintf("%s-%s", "router-external-certificate", rand.String(5))
				err := createNamespace(oc, differentNamespace)
				o.Expect(err).NotTo(o.HaveOccurred())

				g.By("Creating a TLS certificate secret in another namespace")
				secret, _, err := generateTLSCertSecret(differentNamespace, "my-tls-secret", corev1.SecretTypeTLS, host)
				o.Expect(err).NotTo(o.HaveOccurred())
				_, err = oc.AdminKubeClient().CoreV1().Secrets(differentNamespace).Create(context.Background(), secret, metav1.CreateOptions{})
				o.Expect(err).NotTo(o.HaveOccurred())

				g.By("Creating a route in other namespace")
				route := generateRouteWithExternalCertificate(oc.Namespace(), "route", secret.Name, helloPodSvc, host, routev1.TLSTerminationEdge)
				_, err = oc.RouteClient().RouteV1().Routes(oc.Namespace()).Create(context.Background(), route, metav1.CreateOptions{})
				o.Expect(err).To(o.HaveOccurred())
				o.Expect(err.Error()).To(o.ContainSubstring(`Not found: "secrets \"my-tls-secret\" not found"`))
			})

			g.It("should not support external certificate if the secret is not of type kubernetes.io/tls", func() {
				g.By("Creating a secret with the WRONG type (Opaque)")
				secret, _, err := generateTLSCertSecret(oc.Namespace(), "my-tls-secret", corev1.SecretTypeOpaque, host) // Incorrect type
				o.Expect(err).NotTo(o.HaveOccurred())
				_, err = oc.KubeClient().CoreV1().Secrets(oc.Namespace()).Create(context.Background(), secret, metav1.CreateOptions{})
				o.Expect(err).NotTo(o.HaveOccurred())

				g.By("Creating a route")
				route := generateRouteWithExternalCertificate(oc.Namespace(), "route", secret.Name, helloPodSvc, host, routev1.TLSTerminationEdge)
				_, err = oc.RouteClient().RouteV1().Routes(oc.Namespace()).Create(context.Background(), route, metav1.CreateOptions{})
				o.Expect(err).To(o.HaveOccurred())
				o.Expect(err.Error()).To(o.ContainSubstring(`Invalid value: "my-tls-secret": secret of type "kubernetes.io/tls" required`))
			})

			g.It("should not support external certificate if the route termination type is Passthrough", func() {
				g.By("Creating a TLS certificate secret")
				secret, _, err := generateTLSCertSecret(oc.Namespace(), "my-tls-secret", corev1.SecretTypeTLS, host)
				o.Expect(err).NotTo(o.HaveOccurred())
				_, err = oc.KubeClient().CoreV1().Secrets(oc.Namespace()).Create(context.Background(), secret, metav1.CreateOptions{})
				o.Expect(err).NotTo(o.HaveOccurred())

				g.By("Creating a route with Passthrough termination")
				passthroughRoute := generateRouteWithExternalCertificate(oc.Namespace(), "passthrough-route", secret.Name, helloPodSvc, host, routev1.TLSTerminationPassthrough)
				_, err = oc.RouteClient().RouteV1().Routes(oc.Namespace()).Create(context.Background(), passthroughRoute, metav1.CreateOptions{})
				o.Expect(err).To(o.HaveOccurred())
				o.Expect(err.Error()).To(o.ContainSubstring(`Invalid value: "my-tls-secret": passthrough termination does not support certificates`))
			})

			g.It("should not support external certificate if inline certificate is also present", func() {
				g.By("Creating a TLS certificate secret")
				secret, _, err := generateTLSCertSecret(oc.Namespace(), "my-tls-secret", corev1.SecretTypeTLS, host)
				o.Expect(err).NotTo(o.HaveOccurred())
				_, err = oc.KubeClient().CoreV1().Secrets(oc.Namespace()).Create(context.Background(), secret, metav1.CreateOptions{})
				o.Expect(err).NotTo(o.HaveOccurred())

				g.By("Creating a route")
				route := generateRouteWithExternalCertificate(oc.Namespace(), "route", secret.Name, helloPodSvc, host, routev1.TLSTerminationEdge)
				// Add inline certificate
				route.Spec.TLS.Certificate = "my-crt"
				_, err = oc.RouteClient().RouteV1().Routes(oc.Namespace()).Create(context.Background(), route, metav1.CreateOptions{})
				o.Expect(err).To(o.HaveOccurred())
				o.Expect(err.Error()).To(o.ContainSubstring(`Invalid value: "my-tls-secret": cannot specify both tls.certificate and tls.externalCertificate`))
			})
		})
	})

	g.Context("with valid setup", func() {
		var (
			secret       *corev1.Secret
			routes       []*routev1.Route
			hosts        []string
			rootDerBytes []byte
		)

		g.BeforeEach(func() {
			// The number of routes here is deliberately set to be greater than 5
			// to test the OpenShift Router's contention tracker behaviour. (see: https://github.com/openshift/router/blob/b41f9d05467fb7b3f6c2dafa6ac4b5e25164c0b6/pkg/router/controller/contention.go#L86).
			// This tracker limits the frequency of route status updates.
			// https://github.com/openshift/router/pull/614 introduced to ignore contention (route status updates) done by this feature (ExternalCertificate).
			// To ensure proper handling of the contention tracker, we need to test scenarios where a single secret is shared by more than 5 routes.
			// These routes' statuses should be able to update frequently without being blocked by the contention tracker.
			const numRoutes = 6
			var routeNames []string

			for i := 0; i < numRoutes; i++ {
				hosts = append(hosts, fmt.Sprintf("host-%d-%s.%s", i, oc.Namespace(), defaultDomain))
				routeNames = append(routeNames, fmt.Sprintf("route-%d", i))
			}

			g.By("Creating a TLS certificate secret")
			secret, rootDerBytes, err = generateTLSCertSecret(oc.Namespace(), "my-tls-secret", corev1.SecretTypeTLS, hosts...)
			o.Expect(err).NotTo(o.HaveOccurred())
			_, err = oc.KubeClient().CoreV1().Secrets(oc.Namespace()).Create(context.Background(), secret, metav1.CreateOptions{})
			o.Expect(err).NotTo(o.HaveOccurred())

			g.By("Providing router service account permissions to get,list,watch the secret")
			_, err = oc.KubeClient().RbacV1().Roles(oc.Namespace()).Create(context.Background(),
				generateSecretReaderRole(oc.Namespace(), "my-tls-secret"), metav1.CreateOptions{})
			o.Expect(err).NotTo(o.HaveOccurred())
			_, err = oc.KubeClient().RbacV1().RoleBindings(oc.Namespace()).Create(context.Background(),
				generateRouterRoleBinding(oc.Namespace()), metav1.CreateOptions{})
			o.Expect(err).NotTo(o.HaveOccurred())

			g.By("Creating multiple routes referencing same external certificate")
			for i := 0; i < numRoutes; i++ {
				route := generateRouteWithExternalCertificate(oc.Namespace(), routeNames[i], secret.Name, helloPodSvc, hosts[i], routev1.TLSTerminationEdge)
				_, err = oc.RouteClient().RouteV1().Routes(oc.Namespace()).Create(context.Background(), route, metav1.CreateOptions{})
				o.Expect(err).NotTo(o.HaveOccurred())
				routes = append(routes, route)
			}
		})

		g.Describe("the router should support external certificate", func() {
			g.It("and routes are reachable", func() {
				g.By("Sending https request")
				for _, route := range routes {
					hostName, err := getHostnameForRouteMicroShiftAware(oc, route.Name)
					o.Expect(err).NotTo(o.HaveOccurred())
					resp, err := httpsGetCallMicroShiftAware(oc, hostName, rootDerBytes)
					o.Expect(err).NotTo(o.HaveOccurred())
					o.Expect(isValidResponse(resp)).Should(o.BeTrue(), "Expected valid response but got: %s", resp)
				}
			})

			g.Context("and the secret is deleted", func() {
				g.BeforeEach(func() {
					g.By("Deleting the secret")
					err = oc.KubeClient().CoreV1().Secrets(oc.Namespace()).Delete(context.Background(), secret.Name, metav1.DeleteOptions{})
					o.Expect(err).NotTo(o.HaveOccurred())
				})

				g.It("then routes are not reachable", func() {
					g.By("Checking the route status")
					for _, route := range routes {
						checkRouteStatus(oc, route.Name, corev1.ConditionFalse, "ExternalCertificateValidationFailed")
					}
				})

				g.Context("and re-created again", func() {
					g.It("then routes are reachable", func() {
						g.By("Re-creating the deleted secret")
						_, err = oc.KubeClient().CoreV1().Secrets(oc.Namespace()).Create(context.Background(), secret, metav1.CreateOptions{})
						o.Expect(err).NotTo(o.HaveOccurred())

						g.By("Sending https request")
						for _, route := range routes {
							hostName, err := getHostnameForRouteMicroShiftAware(oc, route.Name)
							o.Expect(err).NotTo(o.HaveOccurred())
							resp, err := httpsGetCallMicroShiftAware(oc, hostName, rootDerBytes)
							o.Expect(err).NotTo(o.HaveOccurred())
							o.Expect(isValidResponse(resp)).Should(o.BeTrue(), "Expected valid response but got: %s", resp)
						}
					})
				})

				g.Context("and re-created again but RBAC permissions are dropped", func() {
					g.It("then routes are not reachable", func() {
						g.By("Deleting RBAC permissions")
						err = oc.KubeClient().RbacV1().RoleBindings(oc.Namespace()).Delete(context.Background(), secretReaderRoleBinding, metav1.DeleteOptions{})
						o.Expect(err).NotTo(o.HaveOccurred())

						g.By("Re-creating the deleted secret")
						_, err = oc.KubeClient().CoreV1().Secrets(oc.Namespace()).Create(context.Background(), secret, metav1.CreateOptions{})
						o.Expect(err).NotTo(o.HaveOccurred())

						g.By("Checking the route status")
						for _, route := range routes {
							checkRouteStatus(oc, route.Name, corev1.ConditionFalse, "ExternalCertificateValidationFailed")
						}
					})
				})
			})

			g.Context("and the secret is updated", func() {
				g.It("then also routes are reachable", func() {
					g.By("Updating the existing secret")
					// build a new secret
					secret, rootDerBytes, err = generateTLSCertSecret(oc.Namespace(), "my-tls-secret", corev1.SecretTypeTLS, hosts...)
					o.Expect(err).NotTo(o.HaveOccurred())
					// update the existing secret with the new secret
					_, err = oc.KubeClient().CoreV1().Secrets(oc.Namespace()).Update(context.Background(), secret, metav1.UpdateOptions{})
					o.Expect(err).NotTo(o.HaveOccurred())

					g.By("Sending https request")
					for _, route := range routes {
						hostName, err := getHostnameForRouteMicroShiftAware(oc, route.Name)
						o.Expect(err).NotTo(o.HaveOccurred())
						resp, err := httpsGetCallMicroShiftAware(oc, hostName, rootDerBytes)
						o.Expect(err).NotTo(o.HaveOccurred())
						o.Expect(isValidResponse(resp)).Should(o.BeTrue(), "Expected valid response but got: %s", resp)
					}
				})
			})

			g.Context("and the secret is updated but RBAC permissions are dropped", func() {
				g.It("then routes are not reachable", func() {
					g.By("Deleting RBAC permissions")
					err = oc.KubeClient().RbacV1().RoleBindings(oc.Namespace()).Delete(context.Background(), secretReaderRoleBinding, metav1.DeleteOptions{})
					o.Expect(err).NotTo(o.HaveOccurred())

					g.By("Updating the existing secret")
					// build a new secret
					secret, rootDerBytes, err = generateTLSCertSecret(oc.Namespace(), "my-tls-secret", corev1.SecretTypeTLS, hosts...)
					o.Expect(err).NotTo(o.HaveOccurred())
					// update the existing secret with the new secret
					_, err = oc.KubeClient().CoreV1().Secrets(oc.Namespace()).Update(context.Background(), secret, metav1.UpdateOptions{})
					o.Expect(err).NotTo(o.HaveOccurred())

					g.By("Checking the route status")
					for _, route := range routes {
						checkRouteStatus(oc, route.Name, corev1.ConditionFalse, "ExternalCertificateValidationFailed")
					}
				})
			})

			g.Context("and the route is updated", func() {
				var (
					routeToTest   *routev1.Route
					newSecretName = "new-ext-crt"
				)

				g.BeforeEach(func() {
					// These tests do not *explicitly* need verification on multiple routes.
					// Hence taking only one route into account.
					routeToTest = routes[0]
				})

				g.Context("to use new external certificate", func() {
					g.It("then also the route is reachable", func() {
						g.By("Creating a new secret")
						secret, rootDerBytes, err = generateTLSCertSecret(oc.Namespace(), newSecretName, corev1.SecretTypeTLS, hosts...)
						o.Expect(err).NotTo(o.HaveOccurred())
						_, err = oc.KubeClient().CoreV1().Secrets(oc.Namespace()).Create(context.Background(), secret, metav1.CreateOptions{})
						o.Expect(err).NotTo(o.HaveOccurred())

						g.By("Updating the existing role to add RBAC permissions for the new secret")
						err := patchRoleWithSecretAccess(oc, newSecretName)
						o.Expect(err).NotTo(o.HaveOccurred())

						g.By("Updating the route to use new external certificate")
						err = patchRouteWithExternalCertificate(oc, routeToTest.Name, newSecretName)
						o.Expect(err).NotTo(o.HaveOccurred())

						g.By("Sending https request")
						hostName, err := getHostnameForRouteMicroShiftAware(oc, routeToTest.Name)
						o.Expect(err).NotTo(o.HaveOccurred())
						resp, err := httpsGetCallMicroShiftAware(oc, hostName, rootDerBytes)
						o.Expect(err).NotTo(o.HaveOccurred())
						o.Expect(isValidResponse(resp)).Should(o.BeTrue(), "Expected valid response but got: %s", resp)
					})
				})

				g.Context("to use new external certificate, but RBAC permissions are not added", func() {
					g.It("route update is rejected", func() {
						g.By("Creating a new secret")
						secret, _, err = generateTLSCertSecret(oc.Namespace(), newSecretName, corev1.SecretTypeTLS, hosts...)
						o.Expect(err).NotTo(o.HaveOccurred())
						_, err = oc.KubeClient().CoreV1().Secrets(oc.Namespace()).Create(context.Background(), secret, metav1.CreateOptions{})
						o.Expect(err).NotTo(o.HaveOccurred())

						g.By("Updating the route to use new external certificate")
						err := patchRouteWithExternalCertificate(oc, routeToTest.Name, newSecretName)
						o.Expect(err).To(o.HaveOccurred())
						o.Expect(err.Error()).To(o.And(
							o.ContainSubstring("Forbidden: router serviceaccount does not have permission to get this secret"),
							o.ContainSubstring("Forbidden: router serviceaccount does not have permission to watch this secret"),
							o.ContainSubstring("Forbidden: router serviceaccount does not have permission to list this secret")),
						)
					})
				})

				g.Context("to use new external certificate, but secret is not of type kubernetes.io/tls", func() {
					g.It("route update is rejected", func() {
						g.By("Creating a secret with the WRONG type (Opaque)")
						secret, _, err := generateTLSCertSecret(oc.Namespace(), newSecretName, corev1.SecretTypeOpaque, hosts...) // Incorrect type
						o.Expect(err).NotTo(o.HaveOccurred())
						_, err = oc.KubeClient().CoreV1().Secrets(oc.Namespace()).Create(context.Background(), secret, metav1.CreateOptions{})
						o.Expect(err).NotTo(o.HaveOccurred())

						g.By("Updating the route to use new external certificate")
						err = patchRouteWithExternalCertificate(oc, routeToTest.Name, newSecretName)
						o.Expect(err).To(o.HaveOccurred())
						o.Expect(err.Error()).To(o.ContainSubstring(fmt.Sprintf(`Invalid value: "%s": secret of type "kubernetes.io/tls" required`, newSecretName)))
					})

				})

				g.Context("to use new external certificate, but secret does not exist", func() {
					// do not create new secret
					g.It("route update is rejected", func() {
						g.By("Updating the route to use new external certificate")
						err := patchRouteWithExternalCertificate(oc, routeToTest.Name, newSecretName)
						o.Expect(err).To(o.HaveOccurred())
						o.Expect(err.Error()).To(o.ContainSubstring(fmt.Sprintf(`Not found: "secrets "%s" not found"`, newSecretName)))
					})
				})

				g.Context("to use same external certificate", func() {
					g.It("then also the route is reachable", func() {
						g.By("Adding some label to trigger route update")
						err := patchRouteWithLabel(oc, routeToTest.Name)
						o.Expect(err).NotTo(o.HaveOccurred())

						g.By("Sending https request")
						hostName, err := getHostnameForRouteMicroShiftAware(oc, routeToTest.Name)
						o.Expect(err).NotTo(o.HaveOccurred())
						resp, err := httpsGetCallMicroShiftAware(oc, hostName, rootDerBytes)
						o.Expect(err).NotTo(o.HaveOccurred())
						o.Expect(isValidResponse(resp)).Should(o.BeTrue(), "Expected valid response but got: %s", resp)
					})

				})

				g.Context("to use same external certificate, but RBAC permissions are dropped", func() {
					g.It("route update is rejected", func() {
						g.By("Deleting RBAC permissions")
						err = oc.KubeClient().RbacV1().RoleBindings(oc.Namespace()).Delete(context.Background(), secretReaderRoleBinding, metav1.DeleteOptions{})
						o.Expect(err).NotTo(o.HaveOccurred())

						g.By("Adding some label to trigger route update")
						err := patchRouteWithLabel(oc, routeToTest.Name)
						o.Expect(err).To(o.HaveOccurred())
						o.Expect(err.Error()).To(o.And(
							o.ContainSubstring("Forbidden: router serviceaccount does not have permission to get this secret"),
							o.ContainSubstring("Forbidden: router serviceaccount does not have permission to watch this secret"),
							o.ContainSubstring("Forbidden: router serviceaccount does not have permission to list this secret")),
						)
					})
				})

				g.Context("to remove the external certificate", func() {
					g.BeforeEach(func() {
						g.By("Updating the route to remove the external certificate reference")
						err := patchRouteToRemoveExternalCertificate(oc, routeToTest.Name)
						o.Expect(err).NotTo(o.HaveOccurred())
					})

					g.It("then also the route is reachable and serves the default certificate", func() {
						g.By("Sending in-secure https request")
						hostName, err := getHostnameForRouteMicroShiftAware(oc, routeToTest.Name)
						o.Expect(err).NotTo(o.HaveOccurred())
						resp, err := verifyRouteServesDefaultCertMicroShiftAware(oc, hostName)
						o.Expect(err).NotTo(o.HaveOccurred())
						o.Expect(isValidResponse(resp)).Should(o.BeTrue(), "Expected valid response but got: %s", resp)
					})

					g.Context("and again re-add the same external certificate", func() {
						g.It("then also the route is reachable", func() {
							g.By("Updating the route to re-add the external certificate reference")
							err = patchRouteWithExternalCertificate(oc, routeToTest.Name, secret.Name)
							o.Expect(err).NotTo(o.HaveOccurred())

							g.By("Sending https request")
							hostName, err := getHostnameForRouteMicroShiftAware(oc, routeToTest.Name)
							o.Expect(err).NotTo(o.HaveOccurred())
							resp, err := httpsGetCallMicroShiftAware(oc, hostName, rootDerBytes)
							o.Expect(err).NotTo(o.HaveOccurred())
							o.Expect(isValidResponse(resp)).Should(o.BeTrue(), "Expected valid response but got: %s", resp)
						})
					})
				})
			})
		})
	})
})

// httpsGetCall makes an HTTPS GET request to the specified hostname with retries.
// It uses the provided rootDerBytes as the trusted CA certificate.
func httpsGetCall(hostname string, rootDerBytes []byte) (string, error) {
	e2e.Logf("running https get for host %q", hostname)

	if len(rootDerBytes) == 0 {
		return "", fmt.Errorf("root CA is empty; certificate generation likely failed")
	}

	// Check if this is MicroShift and use internal connectivity if needed
	// We'll determine this by checking if we're in a test context where external connectivity fails
	// convert DER to PEM
	rootCertPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: rootDerBytes,
	})

	// add root CA to trust pool
	certPool := x509.NewCertPool()
	if ok := certPool.AppendCertsFromPEM(rootCertPEM); !ok {
		return "", fmt.Errorf("failed to add root CA certificate to cert pool")
	}
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs: certPool,
			},
		},
	}
	url := fmt.Sprintf("https://%s", hostname)

	_, body, err := sendHttpRequestWithRetry(url, client)
	return body, err
}

// httpsGetCallMicroShiftAware makes an HTTPS GET request with MicroShift fallback
func httpsGetCallMicroShiftAware(oc *exutil.CLI, hostname string, rootDerBytes []byte) (string, error) {
	// First try standard external connectivity
	body, err := httpsGetCall(hostname, rootDerBytes)
	if err == nil {
		return body, nil
	}

	e2e.Logf("Standard HTTPS call failed: %v, checking if MicroShift requires internal connectivity", err)

	// Check if this is MicroShift and fallback to internal connectivity
	isMicroShift, msErr := exutil.IsMicroShiftCluster(oc.AdminKubeClient())
	if msErr != nil {
		e2e.Logf("Could not detect MicroShift: %v, returning original error", msErr)
		return "", err
	}

	if isMicroShift {
		e2e.Logf("Detected MicroShift, trying internal pod connectivity")
		return httpsGetCallViaInternalPod(oc, hostname, rootDerBytes)
	}

	// If not MicroShift, return original error
	return "", err
}

// httpsGetCallViaInternalPod makes an HTTPS GET request to the specified hostname with retries
// using a pod running inside the cluster. This is useful for baremetal platforms where external
// DNS resolution may not work but internal connectivity is available.
func httpsGetCallViaInternalPod(oc *exutil.CLI, hostname string, rootDerBytes []byte) (string, error) {
	e2e.Logf("running https get for host %q via internal pod", hostname)

	if len(rootDerBytes) == 0 {
		return "", fmt.Errorf("root CA is empty; certificate generation likely failed")
	}

	// Create a temporary pod for testing connectivity
	ns := oc.KubeFramework().Namespace.Name
	execPod := exutil.CreateExecPodOrFail(oc.KubeClient(), ns, "route-test-pod")
	defer func() {
		oc.KubeClient().CoreV1().Pods(ns).Delete(context.Background(), execPod.Name, *metav1.NewDeleteOptions(1))
	}()

	// Store the CA certificate in a temporary file in the pod
	rootCertPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: rootDerBytes,
	})

	// Write the CA cert to the pod
	err := wait.PollUntilContextTimeout(context.Background(), time.Second, 30*time.Second, false, func(ctx context.Context) (bool, error) {
		_, err := oc.Run("exec").Args(execPod.Name, "--", "sh", "-c", fmt.Sprintf("echo '%s' > /tmp/ca.crt", string(rootCertPEM))).Output()
		if err != nil {
			e2e.Logf("Failed to write CA cert: %v", err)
			return false, nil
		}
		return true, nil
	})
	if err != nil {
		return "", fmt.Errorf("failed to write CA certificate to pod: %w", err)
	}

	// Get the router service IP to use for internal connectivity
	routerIP, err := getRouterServiceIP(oc)
	if err != nil {
		return "", fmt.Errorf("failed to get router service IP: %w", err)
	}

	// Make the HTTPS request using curl with the CA certificate
	var body string
	err = wait.PollUntilContextTimeout(context.Background(), time.Second, changeTimeoutSeconds*time.Second, false, func(ctx context.Context) (bool, error) {
		stdout, err := oc.Run("exec").Args(execPod.Name, "--", "curl", "-s", "--cacert", "/tmp/ca.crt", "-H", fmt.Sprintf("Host: %s", hostname), fmt.Sprintf("https://%s", routerIP)).Output()
		if err != nil {
			e2e.Logf("curl failed: %v, retrying...", err)
			return false, nil
		}

		// Check if we got the expected response
		if !isValidResponse(stdout) {
			e2e.Logf("Unexpected response: %s, retrying...", stdout)
			return false, nil
		}

		body = stdout
		return true, nil
	})

	if err != nil {
		return "", fmt.Errorf("failed to make successful HTTPS request via internal pod after retries: %w", err)
	}

	return body, nil
}

// getRouterServiceIP gets the ClusterIP of the router service for internal connectivity
func getRouterServiceIP(oc *exutil.CLI) (string, error) {
	// Try standard OpenShift router service first
	svc, err := oc.AdminKubeClient().CoreV1().Services("openshift-ingress").Get(context.Background(), "router-default", metav1.GetOptions{})
	if err == nil && svc.Spec.ClusterIP != "" {
		return svc.Spec.ClusterIP, nil
	}

	// MicroShift fallback: try different service names and namespaces
	microShiftServices := []struct {
		namespace string
		name      string
	}{
		{"openshift-ingress", "router-internal-default"},
		{"openshift-ingress", "router"},
		{"kube-system", "router"},
		{"default", "router"},
		// Add more potential service locations as needed
	}

	for _, svcInfo := range microShiftServices {
		svc, err := oc.AdminKubeClient().CoreV1().Services(svcInfo.namespace).Get(context.Background(), svcInfo.name, metav1.GetOptions{})
		if err == nil && svc.Spec.ClusterIP != "" {
			e2e.Logf("Found router service %s/%s with ClusterIP %s", svcInfo.namespace, svcInfo.name, svc.Spec.ClusterIP)
			return svc.Spec.ClusterIP, nil
		}
	}

	return "", fmt.Errorf("could not find router service ClusterIP in any expected location")
}

// verifyRouteServesDefaultCert checks that the given hostname serves the default certificate.
func verifyRouteServesDefaultCert(hostname string) (string, error) {
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		},
	}
	url := fmt.Sprintf("https://%s", hostname)

	var body string
	err := wait.PollUntilContextTimeout(context.Background(), time.Second, changeTimeoutSeconds*time.Second, false, func(ctx context.Context) (bool, error) {
		var err error
		var resp *http.Response
		resp, body, err = sendHttpRequestWithRetry(url, client)
		if err != nil {
			return false, err
		}

		// check that the route is serving the default certificate.
		for _, cert := range resp.TLS.PeerCertificates {
			if !strings.Contains(cert.Issuer.CommonName, defaultCertificateCN) {
				e2e.Logf("Unexpected Issuer CommonName: %v, retrying...", cert.Issuer.CommonName)
				return false, nil
			}
		}
		return true, nil
	})

	if err != nil {
		return "", fmt.Errorf("failed to verify default certificate after retries: %w", err)
	}

	return body, nil
}

// verifyRouteServesDefaultCertMicroShiftAware checks that the given hostname serves the default certificate
// with MicroShift and baremetal support via internal connectivity fallback
func verifyRouteServesDefaultCertMicroShiftAware(oc *exutil.CLI, hostname string) (string, error) {
	// First try standard external connectivity
	body, err := verifyRouteServesDefaultCert(hostname)
	if err == nil {
		return body, nil
	}

	e2e.Logf("Standard default cert verification failed: %v, checking if MicroShift requires internal connectivity", err)

	// Check if this is MicroShift and fallback to internal connectivity
	isMicroShift, msErr := exutil.IsMicroShiftCluster(oc.AdminKubeClient())
	if msErr != nil {
		e2e.Logf("Could not detect MicroShift: %v, returning original error", msErr)
		return "", err
	}

	if isMicroShift {
		e2e.Logf("Detected MicroShift, trying internal pod connectivity for default cert verification")
		return verifyRouteServesDefaultCertViaInternalPod(oc, hostname)
	}

	// If not MicroShift, return original error
	return "", err
}

// verifyRouteServesDefaultCertViaInternalPod checks that the route serves the default certificate
// using internal pod connectivity for baremetal/MicroShift environments
func verifyRouteServesDefaultCertViaInternalPod(oc *exutil.CLI, hostname string) (string, error) {
	e2e.Logf("verifying default cert for host %q via internal pod", hostname)

	// Create a temporary pod for testing connectivity
	ns := oc.KubeFramework().Namespace.Name
	execPod := exutil.CreateExecPodOrFail(oc.KubeClient(), ns, "route-test-pod")
	defer func() {
		oc.KubeClient().CoreV1().Pods(ns).Delete(context.Background(), execPod.Name, *metav1.NewDeleteOptions(1))
	}()

	// Get the router service IP to use for internal connectivity
	routerIP, err := getRouterServiceIP(oc)
	if err != nil {
		return "", fmt.Errorf("failed to get router service IP: %w", err)
	}

	// Make the HTTPS request using curl to check both certificate and response
	var body string
	err = wait.PollUntilContextTimeout(context.Background(), time.Second, changeTimeoutSeconds*time.Second, false, func(ctx context.Context) (bool, error) {
		// Use curl to get certificate details and response body
		stdout, err := oc.Run("exec").Args(execPod.Name, "--", "curl", "-s", "-k", "--cert-status", "-v", "-H", fmt.Sprintf("Host: %s", hostname), fmt.Sprintf("https://%s", routerIP)).Output()
		if err != nil {
			e2e.Logf("curl failed: %v, retrying...", err)
			return false, nil
		}

		// Check if we got a valid response (the important part for route reachability)
		if !isValidResponse(stdout) {
			e2e.Logf("Unexpected response: %s, retrying...", stdout)
			return false, nil
		}

		body = stdout
		return true, nil
	})

	if err != nil {
		return "", fmt.Errorf("failed to verify default certificate via internal pod after retries: %w", err)
	}

	return body, nil
}

// sendHttpRequestWithRetry sends an HTTP request to the specified URL using the provided client with retries.
func sendHttpRequestWithRetry(url string, client *http.Client) (*http.Response, string, error) {
	var resp *http.Response
	var body []byte

	err := wait.PollUntilContextTimeout(context.Background(), time.Second, changeTimeoutSeconds*time.Second, false, func(ctx context.Context) (bool, error) {
		e2e.Logf("Sending request to %q", url)
		req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
		if err != nil {
			return false, err
		}

		resp, err = client.Do(req)
		if err != nil {
			e2e.Logf("Error making HTTPS request: %s, %v, retrying...", url, err)
			return false, nil
		}
		defer resp.Body.Close()

		// check if the status code is 200 OK
		if resp.StatusCode != http.StatusOK {
			e2e.Logf("Unexpected HTTP status code: %v, retrying...", resp.StatusCode)
			return false, nil
		}

		body, err = io.ReadAll(resp.Body)
		if err != nil {
			e2e.Logf("Failed to read response body: %v, retrying...", err)
			return false, nil
		}
		return true, nil
	})

	if err != nil {
		return nil, "", fmt.Errorf("failed to make successful HTTPS request after retries: %w", err)
	}

	return resp, string(body), nil
}

// checkRouteStatus polls the route status and verifies the ingress condition.
func checkRouteStatus(oc *exutil.CLI, routeName string, ingressConditionStatus corev1.ConditionStatus, ingressConditionReason string) error {
	e2e.Logf("checking route status for %q", routeName)

	ns := oc.KubeFramework().Namespace.Name
	return wait.PollUntilContextTimeout(context.Background(), time.Second, changeTimeoutSeconds*time.Second, false, func(ctx context.Context) (bool, error) {
		route, err := oc.RouteClient().RouteV1().Routes(ns).Get(context.Background(), routeName, metav1.GetOptions{})
		if err != nil {
			e2e.Logf("Error getting route %q: %v", routeName, err)
			return false, err
		}
		for _, ingress := range route.Status.Ingress {
			if len(ingress.Conditions) == 0 {
				e2e.Logf("ingress condition is empty, retrying...")
				return false, nil
			}
			for _, condition := range ingress.Conditions {
				if condition.Reason != ingressConditionReason && condition.Status != ingressConditionStatus {
					e2e.Logf("unexpected ingres condition, expected: [%s,%v] but got: [%s,%v], retrying...", ingressConditionReason, ingressConditionStatus, condition.Reason, condition.Status)
					return false, nil
				} else {
					e2e.Logf("got the expected ingres condition, reason: %s, status: %v", condition.Reason, condition.Status)
				}
			}
		}
		return true, nil
	})
}

// generateTLSCertSecret generates a TLS secret containing a certificate and key.
// The certificate is valid for the provided hostnames.
func generateTLSCertSecret(namespace, secretName string, secretType corev1.SecretType, hosts ...string) (*corev1.Secret, []byte, error) {
	// certificate start and end time are very
	// lenient to avoid any clock drift between
	// the test machine and the cluster under
	// test.
	notBefore := time.Now().Add(-24 * time.Hour)
	notAfter := time.Now().Add(24 * time.Hour)

	// Generate crt/key for secret
	rootDerBytes, tlsCrtData, tlsPrivateKey, err := certgen.GenerateKeyPair(notBefore, notAfter, hosts...)
	if err != nil {
		return nil, nil, err
	}

	derKey, err := certgen.MarshalPrivateKeyToDERFormat(tlsPrivateKey)
	if err != nil {
		return nil, nil, err
	}

	pemCrt, err := certgen.MarshalCertToPEMString(tlsCrtData)
	if err != nil {
		return nil, nil, err
	}

	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: namespace,
			Name:      secretName,
		},
		StringData: map[string]string{
			"tls.crt": pemCrt,
			"tls.key": derKey,
		},
		Type: secretType,
	}, rootDerBytes, nil
}

// generateRouteWithExternalCertificate creates a route with external certificate configuration.
func generateRouteWithExternalCertificate(namespace, routeName, secretName, serviceName, host string, termination routev1.TLSTerminationType) *routev1.Route {
	return &routev1.Route{
		ObjectMeta: metav1.ObjectMeta{
			Name:      routeName,
			Namespace: namespace,
		},
		Spec: routev1.RouteSpec{
			Host: host,
			To: routev1.RouteTargetReference{
				Kind: "Service",
				Name: serviceName,
			},
			TLS: &routev1.TLSConfig{
				Termination: termination,
				ExternalCertificate: &routev1.LocalObjectReference{
					Name: secretName,
				},
			},
		},
	}
}

// generateSecretReaderRole creates a role that grants permissions to get, list, and watch the specified secret.
func generateSecretReaderRole(namespace, secretName string) *rbacv1.Role {
	return &rbacv1.Role{
		ObjectMeta: metav1.ObjectMeta{
			Name:      secretReaderRole,
			Namespace: namespace,
		},
		Rules: []rbacv1.PolicyRule{
			{
				APIGroups:     []string{""},
				Resources:     []string{"secrets"},
				ResourceNames: []string{secretName},
				Verbs:         []string{"get", "list", "watch"},
			},
		},
	}
}

// generateRouterRoleBinding creates a roleBinding that binds the secret reader role to the router service account.
func generateRouterRoleBinding(namespace string) *rbacv1.RoleBinding {
	return &rbacv1.RoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:      secretReaderRoleBinding,
			Namespace: namespace,
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:      rbacv1.ServiceAccountKind,
				Name:      "router",
				Namespace: "openshift-ingress",
			},
		},
		RoleRef: rbacv1.RoleRef{
			APIGroup: rbacv1.GroupName,
			Kind:     "Role",
			Name:     secretReaderRole,
		},
	}
}

// createNamespace creates a new namespace with the given name.
func createNamespace(oc *exutil.CLI, name string) error {
	namespace := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
		},
	}
	_, err := oc.AdminKubeClient().CoreV1().
		Namespaces().Create(context.Background(), namespace, metav1.CreateOptions{})

	return err
}

// patchRoleWithSecretAccess updates the "secretReaderRole" to grant access to the specified secret.
func patchRoleWithSecretAccess(oc *exutil.CLI, secretName string) error {
	newRule := fmt.Sprintf(`{"apiGroups": [""],"resources": ["secrets"],"resourceNames":["%s"],"verbs": ["get", "list", "watch"]}`, secretName)
	rolePatch := fmt.Sprintf(`{"rules": [%s]}`, newRule)
	_, err := oc.KubeClient().RbacV1().Roles(oc.Namespace()).Patch(
		context.Background(), secretReaderRole, types.MergePatchType, []byte(rolePatch), metav1.PatchOptions{},
	)
	return err
}

// patchRouteWithExternalCertificate updates the given route to use the specified external certificate secret.
func patchRouteWithExternalCertificate(oc *exutil.CLI, routeName, secretName string) error {
	routePatch := fmt.Sprintf(`{"spec":{"tls":{"externalCertificate":{"name":"%s"}}}}`, secretName)
	_, err := oc.RouteClient().RouteV1().Routes(oc.Namespace()).Patch(
		context.Background(), routeName, types.MergePatchType, []byte(routePatch), metav1.PatchOptions{},
	)
	return err
}

// patchRouteWithLabel updates the given route to add some labels. This is primarily used
// to trigger route updates.
func patchRouteWithLabel(oc *exutil.CLI, routeName string) error {
	routePatch := `{"metadata":{"labels":{"app":"myapp","key":"value"}}}`
	_, err := oc.RouteClient().RouteV1().Routes(oc.Namespace()).Patch(
		context.Background(), routeName, types.MergePatchType, []byte(routePatch), metav1.PatchOptions{},
	)
	return err
}

// patchRouteToRemoveExternalCertificate updates the given route to remove
// the external certificate reference.
func patchRouteToRemoveExternalCertificate(oc *exutil.CLI, routeName string) error {
	routePatch := `[{"op": "remove", "path": "/spec/tls/externalCertificate"}]`
	_, err := oc.RouteClient().RouteV1().Routes(oc.Namespace()).Patch(
		context.Background(), routeName, types.JSONPatchType, []byte(routePatch), metav1.PatchOptions{},
	)
	return err
}

// createHelloOpenShiftPod creates a hello-openshift pod dynamically using the proper test image
// instead of relying on the hardcoded JSON file that assumes Docker Hub access.
// This helps baremetal and disconnected environments where Docker Hub may not be accessible.
func createHelloOpenShiftPod(oc *exutil.CLI, podName string) error {
	// Use k8s e2e test image instead of hardcoded "openshift/hello-openshift"
	// This will automatically use the correct registry for the environment
	testImage := k8simage.GetE2EImage(k8simage.Agnhost)

	ns := oc.Namespace()

	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      podName,
			Namespace: ns,
			Labels: map[string]string{
				"name": podName,
			},
		},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{
				{
					Name:  podName,
					Image: testImage,
					// Use netexec server mode to simulate hello-openshift behavior
					Args: []string{
						"netexec",
						"--http-port=8080",
						"--delay-shutdown=0",
					},
					Ports: []corev1.ContainerPort{
						{
							ContainerPort: 8080,
							Protocol:      corev1.ProtocolTCP,
						},
					},
					ImagePullPolicy: corev1.PullIfNotPresent,
					SecurityContext: &corev1.SecurityContext{
						Capabilities: &corev1.Capabilities{},
						Privileged:   &[]bool{false}[0],
					},
					VolumeMounts: []corev1.VolumeMount{
						{
							Name:      "tmp",
							MountPath: "/tmp",
						},
					},
					TerminationMessagePath: "/dev/termination-log",
				},
			},
			Volumes: []corev1.Volume{
				{
					Name: "tmp",
					VolumeSource: corev1.VolumeSource{
						EmptyDir: &corev1.EmptyDirVolumeSource{},
					},
				},
			},
			RestartPolicy: corev1.RestartPolicyAlways,
			DNSPolicy:     corev1.DNSClusterFirst,
		},
	}

	_, err := oc.KubeClient().CoreV1().Pods(ns).Create(context.Background(), pod, metav1.CreateOptions{})
	return err
}

// createHelloOpenShiftPodFallback creates the pod using the original JSON file as fallback
func createHelloOpenShiftPodFallback(oc *exutil.CLI, helloPodPath string) error {
	return oc.Run("create").Args("-f", helloPodPath, "-n", oc.Namespace()).Execute()
}

// createHelloOpenShiftPodWithFallback tries to create the pod dynamically first, then falls back to JSON
func createHelloOpenShiftPodWithFallback(oc *exutil.CLI, podName, helloPodPath string) error {
	// First try creating pod dynamically with proper test image
	err := createHelloOpenShiftPod(oc, podName)
	if err == nil {
		e2e.Logf("Successfully created hello-openshift pod using dynamic image: %s", k8simage.GetE2EImage(k8simage.Agnhost))
		return nil
	}

	e2e.Logf("Failed to create pod dynamically (%v), falling back to JSON file", err)

	// Fallback to original method
	return createHelloOpenShiftPodFallback(oc, helloPodPath)
}
