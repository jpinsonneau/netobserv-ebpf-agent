// Package cluster cointains the base setup for the test environment. This is:
//   - Deployment manifests for a base cluster: Loki, permissions, flowlogs-processor and the
//     local version of the agent. As well as the cluster configuration for ports exposure.
//   - Utility classes to programmatically manage the Kind cluster and some of its components
//     (e.g. Loki)
package cluster

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path"
	rt2 "runtime"
	"sort"
	"syscall"
	"testing"
	"time"

	"github.com/netobserv/netobserv-ebpf-agent/e2e/cluster/tester"

	"github.com/sirupsen/logrus"
	"github.com/vladimirvivien/gexe"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer/yaml"
	yamlutil "k8s.io/apimachinery/pkg/util/yaml"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/restmapper"
	"sigs.k8s.io/e2e-framework/pkg/env"
	"sigs.k8s.io/e2e-framework/pkg/envconf"
	"sigs.k8s.io/e2e-framework/pkg/envfuncs"
	"sigs.k8s.io/e2e-framework/support/kind"
)

// DeployOrder specifies the order in which a Deployment must be executed, from lower to higher
// priority
type DeployOrder int

const (
	// AfterAgent DeployOrder would deploy related manifests after the NetObserv agent has been
	// deployed
	AfterAgent DeployOrder = iota
	// WithAgent DeployOrder would deploy related manifests with the NetObserv agent, after the
	// rest of NetObservServices have been deployed.
	WithAgent
	// NetObservServices DeployOrder would deploy related manifests after all the external services
	// have been deployed, and before deploying the Agent.
	NetObservServices
	// ExternalServices DeployOrder is aimed for external services (e.g. Loki, Kafka...), which will
	// be deployed before the rest of NetObservServices.
	ExternalServices
	// Preconditions DeployOrder is aimed to these Resources that define a given cluster status
	// before tests start (e.g. namespaces, permissions, etc...).
	Preconditions
)

// DeployID is an optional identifier for a deployment. It is used to override/replace default
// base deployments with a different file (e.g. override the default flowlogs-pipeline
// with a different configuration).
type DeployID string

const (
	PermissionsSetup DeployID = "permissions"
	Loki             DeployID = "loki"
	FlowLogsPipeline DeployID = "flp"
	Agent            DeployID = "agent"
)

const (
	agentContainerName = "localhost/ebpf-agent:test"
	kindImage          = "kindest/node:v1.27.3"
	namespace          = "default"
	logsSubDir         = "e2e-logs"
	localArchiveName   = "ebpf-agent.tar"
)

var log = logrus.WithField("component", "cluster.Kind")

// defaultBaseDeployments are a list of components that are common to any test environment
var defaultBaseDeployments = map[DeployID]Deployment{
	PermissionsSetup: {
		Order: Preconditions, ManifestFile: path.Join(packageDir(), "base", "01-permissions.yml"),
	},
	Loki: {
		Order:        ExternalServices,
		ManifestFile: path.Join(packageDir(), "base", "02-loki.yml"),
		Ready: &Readiness{
			Function:    func(*envconf.Config) error { return (&tester.Loki{BaseURL: "http://localhost:30100"}).Ready() },
			Description: "Check that http://localhost:30100 is reachable (Loki NodePort)",
			Timeout:     5 * time.Minute,
			Retry:       5 * time.Second,
		},
	},
	FlowLogsPipeline: {
		Order: NetObservServices, ManifestFile: path.Join(packageDir(), "base", "03-flp.yml"),
		Ready: &Readiness{
			Function:    testPodsReady("flp"),
			Description: "Check that flp pods are up and running",
			Timeout:     5 * time.Minute,
			Retry:       5 * time.Second,
		},
	},
	Agent: {
		Order: WithAgent, ManifestFile: path.Join(packageDir(), "base", "04-agent.yml"),
		Ready: &Readiness{
			Function:    testPodsReady("netobserv-ebpf-agent"),
			Description: "Check that agent pods are up and running",
			Timeout:     5 * time.Minute,
			Retry:       5 * time.Second,
		},
	},
}

func testPodsReady(dsName string) func(*envconf.Config) error {
	return func(cfg *envconf.Config) error {
		pods, err := tester.NewPods(cfg)
		if err != nil {
			return err
		}
		return pods.DSReady(context.Background(), "default", dsName)
	}
}

// Deployment of components. Not only K8s deployments but also Pods, Services, DaemonSets, ...
type Deployment struct {
	// Order of the deployment. Deployments with the same order will be executed by alphabetical
	// order of its manifest file
	Order DeployOrder
	// ManifestFile path to the kubectl-like YAML manifest file
	ManifestFile string
	Ready        *Readiness
}

type Readiness struct {
	Function    func(*envconf.Config) error
	Description string
	Timeout     time.Duration
	Retry       time.Duration
}

// Kind cluster deployed by each TestMain function, prepared for a given test scenario.
type Kind struct {
	clusterName     string
	baseDir         string
	deployManifests map[DeployID]Deployment
	testEnv         env.Environment
	timeout         time.Duration
}

// Option that can be passed to the NewKind function in order to change the configuration
// of the test cluster
type Option func(k *Kind)

// Override can be passed to NewKind to override some components of the base deployment (identified
// by the passed DeployID instance).
func Override(id DeployID, def Deployment) Option {
	return func(k *Kind) {
		k.deployManifests[id] = def
	}
}

// Deploy can be passed to NewKind to deploy extra components, in addition to the base deployment.
func Deploy(def Deployment) Option {
	// unique ID for this given deployment
	id := fmt.Sprintf("%d-%s", def.Order, def.ManifestFile)
	return func(k *Kind) {
		k.deployManifests[DeployID(id)] = def
	}
}

// Timeout for long-running operations (e.g. deployments, readiness probes...)
func Timeout(t time.Duration) Option {
	log.Infof("Timeout set to %s", t.String())
	return func(k *Kind) {
		k.timeout = t
	}
}

// NewKind creates a kind cluster given a name and set of Option instances. The base dir
// must point to the folder where the logs are going to be stored and, in case your docker
// backend doesn't provide access to the local images, where the ebpf-agent.tar container image
// is located. Usually it will be the project root.
func NewKind(kindClusterName, baseDir string, options ...Option) *Kind {
	fmt.Println()
	fmt.Println()
	log.Infof("Starting KIND cluster %s", kindClusterName)
	k := &Kind{
		testEnv:         env.New(),
		baseDir:         baseDir,
		clusterName:     kindClusterName,
		deployManifests: defaultBaseDeployments,
		timeout:         2 * time.Minute,
	}
	for _, option := range options {
		option(k)
	}
	return k
}

// Run the Kind cluster for the later execution of tests.
func (k *Kind) Run(m *testing.M) {
	envFuncs := []env.Func{
		envfuncs.CreateClusterWithConfig(
			kind.NewProvider(),
			k.clusterName,
			path.Join(packageDir(), "base", "00-kind.yml"),
			kind.WithImage(kindImage)),
		k.loadLocalImage(),
	}
	// Deploy base cluster dependencies and wait for readiness (if needed)
	// Readiness checks are grouped by deploy orders: first, we deploy all the
	// elements with the same order, then we execute all the isReady functions, if any.
	var readyFuncs []env.Func
	currentOrder := Preconditions
	for _, c := range k.orderedManifests() {
		if c.Order != currentOrder {
			envFuncs = append(envFuncs, readyFuncs...)
			readyFuncs = nil
			currentOrder = c.Order
		}
		envFuncs = append(envFuncs, deploy(c))
		readyFuncs = append(readyFuncs, isReady(c))
	}
	envFuncs = append(envFuncs, readyFuncs...)

	exit := make(chan os.Signal, 1)
	signal.Notify(exit, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-exit
		fmt.Println("SIGTERM received, cluster might still be running")
		fmt.Printf("To clean up, run: \033[33mkind delete cluster --name %s\033[0m\n", k.clusterName)
		os.Exit(1)
	}()

	log.Info("starting kind setup")
	code := k.testEnv.Setup(envFuncs...).
		Finish(
			k.exportLogs(),
			envfuncs.DestroyCluster(k.clusterName),
		).Run(m)
	log.WithField("returnCode", code).Info("tests finished run")
}

func (k *Kind) orderedManifests() []Deployment {
	type sortable struct {
		id DeployID
		d  Deployment
	}
	var sorted []sortable
	for id, manifest := range k.deployManifests {
		sorted = append(sorted, sortable{id: id, d: manifest})
	}
	sort.SliceStable(sorted, func(i, j int) bool {
		if sorted[i].d.Order == sorted[j].d.Order {
			return sorted[i].id < sorted[j].id
		}
		return sorted[i].d.Order > sorted[j].d.Order
	})
	var deployments []Deployment
	for _, s := range sorted {
		deployments = append(deployments, s.d)
	}
	return deployments
}

// export logs into the e2e-logs folder of the base directory.
func (k *Kind) exportLogs() env.Func {
	return func(ctx context.Context, _ *envconf.Config) (context.Context, error) {
		logsDir := path.Join(k.baseDir, logsSubDir)
		log.WithField("directory", logsDir).Info("exporting cluster logs")
		exe := gexe.New()
		out := exe.Run("kind export logs " + logsDir + " --name " + k.clusterName)
		log.WithField("out", out).Debug("exported cluster logs")
		return ctx, nil
	}
}

func (k *Kind) TestEnv() env.Environment {
	return k.testEnv
}

// Loki client pointing to the Loki instance inside the test cluster
func (k *Kind) Loki() *tester.Loki {
	return &tester.Loki{BaseURL: "http://localhost:30100"}
}

func deploy(definition Deployment) env.Func {
	return func(ctx context.Context, cfg *envconf.Config) (context.Context, error) {
		kclient, err := kubernetes.NewForConfig(cfg.Client().RESTConfig())
		if err != nil {
			return ctx, fmt.Errorf("creating kubernetes client: %w", err)
		}
		if err := deployManifestFile(definition, cfg, kclient); err != nil {
			return ctx, fmt.Errorf("deploying manifest file: %w", err)
		}
		return ctx, nil
	}
}

// deploys a yaml manifest file
// credits to https://gist.github.com/pytimer/0ad436972a073bb37b8b6b8b474520fc
func deployManifestFile(definition Deployment,
	cfg *envconf.Config,
	kclient *kubernetes.Clientset,
) error {
	log.WithField("file", definition.ManifestFile).Info("deploying manifest file")

	b, err := os.ReadFile(definition.ManifestFile)
	if err != nil {
		return fmt.Errorf("reading manifest file %q: %w", definition.ManifestFile, err)
	}

	dd, err := dynamic.NewForConfig(cfg.Client().RESTConfig())
	if err != nil {
		return fmt.Errorf("creating kubernetes dynamic client: %w", err)
	}

	decoder := yamlutil.NewYAMLOrJSONDecoder(bytes.NewReader(b), 100)
	for {
		var rawObj runtime.RawExtension
		if err = decoder.Decode(&rawObj); err != nil {
			if !errors.Is(err, io.EOF) {
				return fmt.Errorf("decoding manifest raw object: %w", err)
			}
			log.WithField("file", definition.ManifestFile).Info("done") // eof
			return nil
		}

		obj, gvk, err := yaml.NewDecodingSerializer(unstructured.UnstructuredJSONScheme).Decode(rawObj.Raw, nil, nil)
		if err != nil {
			return fmt.Errorf("creating yaml decoding serializer: %w", err)
		}
		unstructuredMap, err := runtime.DefaultUnstructuredConverter.ToUnstructured(obj)
		if err != nil {
			return fmt.Errorf("deserializing object in manifest: %w", err)
		}

		unstructuredObj := &unstructured.Unstructured{Object: unstructuredMap}

		gr, err := restmapper.GetAPIGroupResources(kclient.Discovery())
		if err != nil {
			return fmt.Errorf("can't get API group resources: %w", err)
		}

		mapper := restmapper.NewDiscoveryRESTMapper(gr)
		mapping, err := mapper.RESTMapping(gvk.GroupKind(), gvk.Version)
		if err != nil {
			return fmt.Errorf("creating REST Mapping: %w", err)
		}

		var dri dynamic.ResourceInterface
		if mapping.Scope.Name() == meta.RESTScopeNameNamespace {
			if unstructuredObj.GetNamespace() == "" {
				unstructuredObj.SetNamespace(namespace)
			}
			dri = dd.Resource(mapping.Resource).Namespace(unstructuredObj.GetNamespace())
		} else {
			dri = dd.Resource(mapping.Resource)
		}

		if _, err := dri.Create(context.Background(), unstructuredObj, metav1.CreateOptions{}); err != nil {
			log.Fatal(err)
		}
	}
}

// loadLocalImage loads the agent docker image into the test cluster. It tries both available
// methods, which will selectively work depending on the container backend type
func (k *Kind) loadLocalImage() env.Func {
	return func(ctx context.Context, config *envconf.Config) (context.Context, error) {
		log.Debug("trying to load docker image from local registry")
		ctx, err := envfuncs.LoadDockerImageToCluster(
			k.clusterName, agentContainerName)(ctx, config)
		if err == nil {
			return ctx, nil
		}
		log.WithError(err).WithField("archive", localArchiveName).
			Debug("couldn't load image from local registry. Trying from local archive")
		return envfuncs.LoadImageArchiveToCluster(
			k.clusterName, path.Join(k.baseDir, localArchiveName))(ctx, config)
	}
}

// withTimeout retries the execution of an env.Func until it succeeds or a timeout is reached
func withTimeout(f env.Func, timeout, retry time.Duration) env.Func {
	tlog := log.WithField("function", "withTimeout")
	return func(ctx context.Context, config *envconf.Config) (context.Context, error) {
		start := time.Now()
		for {
			ctx, err := f(ctx, config)
			if err == nil {
				return ctx, nil
			}
			if time.Since(start) > timeout {
				return ctx, fmt.Errorf("timeout (%s) trying to execute function: %w", timeout, err)
			}
			tlog.WithError(err).Debugf("function did not succeed. Retrying after %s", retry.String())
			time.Sleep(retry)
		}
	}
}

// isReady succeeds if the passed deployment does not have ReadyFunction, or it succeeds
func isReady(definition Deployment) env.Func {
	if definition.Ready != nil {
		log.WithFields(logrus.Fields{"deployment": definition.ManifestFile, "readiness": definition.Ready.Description}).Infof("Readiness check set with timeout: %s", definition.Ready.Timeout.String())
		return withTimeout(func(ctx context.Context, cfg *envconf.Config) (context.Context, error) {
			if err := definition.Ready.Function(cfg); err != nil {
				return ctx, fmt.Errorf("component not ready: %w", err)
			}
			return ctx, nil
		}, definition.Ready.Timeout, definition.Ready.Retry)
	}
	return func(ctx context.Context, _ *envconf.Config) (context.Context, error) { return ctx, nil }
}

// helper to get the base directory of this package, allowing to load the test deployment
// files whatever the working directory is
func packageDir() string {
	_, file, _, ok := rt2.Caller(1)
	if !ok {
		panic("can't find package directory for (project_dir)/test/cluster")
	}
	return path.Dir(file)
}
