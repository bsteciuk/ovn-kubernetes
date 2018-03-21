// +build windows

package app

import (
	"encoding/json"
	"fmt"
	"net"
	"os/exec"
	"strconv"
	"strings"

	"github.com/sirupsen/logrus"

	"github.com/Microsoft/hcsshim"
	"github.com/containernetworking/cni/pkg/skel"
	"github.com/containernetworking/cni/pkg/types/current"

	"github.com/openvswitch/ovn-kubernetes/go-controller/pkg/config"
	"github.com/openvswitch/ovn-kubernetes/go-controller/pkg/util"
)

// noNameNetNS - This is received for the infra container, in this case we
// have to create the network endpoint and attach it to the infra container
// containerNetNS - This is received for all the other containers from
// the same pod, do not create the network endpoint in this case
// windowsVersionRTM - This is the latest windows version which do not support
// multiple containers per pod. The CNI will act differently on this version
const (
	noNameNetNS       = "none"
	containerNetNS    = "container:"
	windowsVersionRTM = 14393
)

// More details about the above constants can be found in the following PR:
// https://github.com/kubernetes/kubernetes/pull/51063

// getHNSIdFromConfigOrByGatewayIP returns the HNS Id using the Gateway IP or
// the config value
// When the HNS Endpoint is created, it asks for the HNS Id in order to
// attach it to the desired network. This function finds the HNS Id of the
// network based on the gatewayIP. If more than one suitable network it's found,
// return an error asking to give the HNS Network Id in config.
func getHNSIdFromConfigOrByGatewayIP(gatewayIP string) (string, error) {
	if config.CNI.WinHNSNetworkID != "" {
		logrus.Infof("Using HNS Network Id from config: %v", config.CNI.WinHNSNetworkID)
		return config.CNI.WinHNSNetworkID, nil
	}
	hnsNetworkId := ""
	hnsNetworks, err := hcsshim.HNSListNetworkRequest("GET", "", "")
	if err != nil {
		return "", err
	}
	for _, hnsNW := range hnsNetworks {
		for _, hnsNWSubnet := range hnsNW.Subnets {
			if strings.Compare(gatewayIP, hnsNWSubnet.GatewayAddress) == 0 {
				if len(hnsNetworkId) == 0 {
					hnsNetworkId = hnsNW.Id
				} else {
					return "", fmt.Errorf("Found more than one network suitable for containers, " +
						"please specify win-hnsnetwork-id in config")
				}
			}
		}
	}
	if len(hnsNetworkId) != 0 {
		logrus.Infof("HNS Network Id found: %v", hnsNetworkId)
		return hnsNetworkId, nil
	}
	return "", fmt.Errorf("Could not find any suitable network to attach the container")
}

// createHNSEndpoint creates the HNS endpoint with the given configuration.
// On success it returns the created HNS endpoint.
func createHNSEndpoint(hnsConfiguration *hcsshim.HNSEndpoint) (*hcsshim.HNSEndpoint, error) {
	logrus.Infof("Creating HNS endpoint")
	hnsConfigBytes, err := json.Marshal(hnsConfiguration)
	if err != nil {
		return nil, err
	}
	logrus.Infof("hnsConfigBytes: %v", string(hnsConfigBytes))

	createdHNSEndpoint, err := hcsshim.HNSEndpointRequest("POST", "", string(hnsConfigBytes))
	if err != nil {
		logrus.Errorf("Could not create the HNSEndpoint, error: %v", err)
		return nil, err
	}
	logrus.Infof("Created HNS endpoint with ID: %v", createdHNSEndpoint.Id)
	return createdHNSEndpoint, nil
}

// containerHotAttachEndpoint attaches the given endpoint to a running container
func containerHotAttachEndpoint(existingHNSEndpoint *hcsshim.HNSEndpoint, containerID string) error {
	logrus.Infof("Attaching endpoint %v to container %v", existingHNSEndpoint.Id, containerID)
	if err := hcsshim.HotAttachEndpoint(containerID, existingHNSEndpoint.Id); err != nil {
		logrus.Infof("Error attaching the endpoint to the container, error: %v", err)
		return err
	}
	logrus.Infof("Endpoint attached successfully to the container")
	return nil
}

// deleteHNSEndpoint deletes the given endpoint if it exists
func deleteHNSEndpoint(endpointName string) error {
	logrus.Infof("Deleting HNS endpoint: %v", endpointName)
	// The HNS endpoint must be manually deleted
	hnsEndpoint, err := hcsshim.GetHNSEndpointByName(endpointName)
	if err == nil {
		logrus.Infof("Fetched endpoint: %v", endpointName)
		// Endpoint exists, try to delete it
		_, err = hnsEndpoint.Delete()
		if err != nil {
			logrus.Warningf("Failed to delete HNS endpoint: %q", err)
		} else {
			logrus.Infof("HNS endpoint successfully deleted: %q", endpointName)
		}
	} else {
		logrus.Infof("No endpoint with name %v was found, error %v", endpointName, err)
	}
	// Return the error in case it failed, we don't want to leak any HNS Endpoints
	return err
}

// ConfigureInterface sets up the container interface
// Small note on this, the call to this function should be idempotent on Windows.
// The fact that CNI add should be idempotent on Windows is stated here:
// https://github.com/kubernetes/kubernetes/blob/master/pkg/kubelet/network/cni/cni_windows.go#L38
func ConfigureInterface(args *skel.CmdArgs, namespace string, podName string, macAddress string, ipAddress string, gatewayIP string) ([]*current.Interface, error) {
	if strings.HasPrefix(args.Netns, containerNetNS) || strings.Compare(args.Netns, noNameNetNS) != 0 {
		// If it is a normal container from the pod, there is nothing to do.
		// Also, if it is not an infra container, nothing to do in this case as well.
		logrus.Infof("CNI called for normal container or infra container, nothing to do")
		return []*current.Interface{}, nil
	}

	ipAddr, ipNet, err := net.ParseCIDR(ipAddress)
	if err != nil {
		return nil, err
	}
	ipMaskSize, _ := ipNet.Mask.Size()
	endpointName := args.ContainerID

	var hnsNetworkId string
	hnsNetworkId, err = getHNSIdFromConfigOrByGatewayIP(gatewayIP)
	if err != nil {
		logrus.Infof("Error when detecting the HNS Network Id: %q", err)
		return nil, err
	}

	// Ensure that the macAddress is given in xx:xx:xx:xx:xx:xx format
	macAddressIpFormat := strings.Replace(macAddress, ":", "-", -1)

	// Check if endpoint is created, otherwise create it.
	// This is to make the call to add idempotent
	var createdEndpoint *hcsshim.HNSEndpoint
	createdEndpoint, err = hcsshim.GetHNSEndpointByName(endpointName)
	if err != nil {
		logrus.Infof("HNS endpoint %q does not exist", endpointName)
		hnsEndpoint := &hcsshim.HNSEndpoint{
			Name:           endpointName,
			VirtualNetwork: hnsNetworkId,
			IPAddress:      ipAddr,
			MacAddress:     macAddressIpFormat,
			PrefixLength:   uint8(ipMaskSize),
		}
		createdEndpoint, err = createHNSEndpoint(hnsEndpoint)
		if err != nil {
			return nil, err
		}
	} else {
		logrus.Infof("HNS endpoint already exists with name: %q", endpointName)
	}

	err = containerHotAttachEndpoint(createdEndpoint, args.ContainerID)
	if err != nil {
		logrus.Warningf("Failed to hot attach HNS Endpoint %q to container %q, reason: %q", endpointName, args.ContainerID, err)
		// In case the attach failed, delete the endpoint
		errHNSDelete := deleteHNSEndpoint(args.ContainerID)
		if errHNSDelete != nil {
			logrus.Warningf("Failed to delete the HNS Endpoint, reason: %q", errHNSDelete)
		}
		return nil, err
	}

	ifaceID := fmt.Sprintf("%s_%s", namespace, podName)
	// TODO: Revisit this once Hyper-V Containers are supported in Kubernetes
	// "--may-exist"  is added to support the function idempotency
	ovsArgs := []string{
		"--may-exist", "add-port", "br-int", endpointName, "--", "set",
		"interface", endpointName, "type=internal", "--", "set",
		"interface", endpointName,
		fmt.Sprintf("external_ids:attached_mac=%s", macAddress),
		fmt.Sprintf("external_ids:iface-id=%s", ifaceID),
		fmt.Sprintf("external_ids:ip_address=%s", ipAddress),
	}
	var out []byte
	out, err = exec.Command("ovs-vsctl", ovsArgs...).CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("failure in plugging pod interface: %v  %q", err, string(out))
	}

	return []*current.Interface{}, nil
}

// PlatformSpecificCleanup deletes the OVS port and also the corresponding
// HNS Endpoint for the OVS port.
func PlatformSpecificCleanup(args *skel.CmdArgs, argsMap map[string]string) error {
	// argsMap is used only for Windows Server 2016 RTM
	endpointName := args.ContainerID
	windowsVersion, err := getWindowsVersion()
	if err == nil && windowsVersion <= windowsVersionRTM {
		// On Windows Server RTM we don't have to take care of the HNS Endpoint
		namespace := argsMap["K8S_POD_NAMESPACE"]
		podName := argsMap["K8S_POD_NAME"]
		ifaceID := fmt.Sprintf("%s_%s", namespace, podName)
		ovsArgs := []string{
			"--bare", "find", "interface", fmt.Sprintf("external_ids:iface-id=%s", ifaceID),
		}
		outputFind, errFind := exec.Command("ovs-vsctl", ovsArgs...).CombinedOutput()
		if errFind == nil && len(outputFind) != 0 {
			outputFindList := strings.Split(string(outputFind), "Container NIC ")
			endpointName = fmt.Sprintf("Container NIC %s", strings.Split(outputFindList[1], "\r\n")[0])
			logrus.Infof("Found container OVS port: %v", endpointName)
		} else {
			logrus.Infof("Infra container OVS port not found")
			return nil
		}
	}

	ovsArgs := []string{
		"del-port", "br-int", endpointName,
	}
	out, err := exec.Command("ovs-vsctl", ovsArgs...).CombinedOutput()
	if err != nil && !strings.Contains(string(out), "no port named") {
		// DEL should be idempotent; don't return an error just log it
		logrus.Warningf("failed to delete OVS port %s: %v  %q", endpointName, err, string(out))
	}
	if windowsVersion <= windowsVersionRTM {
		return nil
	}
	// Return the error if we can't delete the HNS Endpoint, we don't want any leaks
	return deleteHNSEndpoint(endpointName)
}

func getFakeCNIResult() *current.Result {
	fakeAddr, fakeAddrNet, _ := net.ParseCIDR("1.2.3.4/32")
	fakeResult := &current.Result{
		IPs: []*current.IPConfig{
			{
				Version:   "4",
				Interface: current.Int(1),
				Address:   net.IPNet{IP: fakeAddr, Mask: fakeAddrNet.Mask},
				Gateway:   net.ParseIP("1.2.3.4"),
			},
		},
	}
	return fakeResult
}

// InitialPlatformCheck checks to see if the container is an infra container
// by looking at the namespace prefix. If it's not, then it has nothing to
// do and the CNI should stop here for Windows Server version greated than windowsVersionRTM.
// For Windows Server version windowsVersionRTM it will configure the pod interface.
func InitialPlatformCheck(args *skel.CmdArgs, argsMap map[string]string) (bool, *current.Result, error) {
	windowsVersion, err := getWindowsVersion()
	if err == nil && windowsVersion <= windowsVersionRTM {
		namespace := argsMap["K8S_POD_NAMESPACE"]
		podName := argsMap["K8S_POD_NAME"]
		ifaceID := fmt.Sprintf("%s_%s", namespace, podName)
		if strings.Compare(args.Netns, noNameNetNS) != 0 && !checkContainerOVSPort(ifaceID) {
			result, err := configureInterfaceRTM(args, argsMap)
			return true, result, err
		} else {
			logrus.Infof("InitialPlatformCheck: CNI has nothing to do (called for infra container or network has been setup or container not running")
			return true, getFakeCNIResult(), nil
		}

	}
	if strings.HasPrefix(args.Netns, containerNetNS) || strings.Compare(args.Netns, noNameNetNS) != 0 {
		// If it is a normal container from the pod, there is nothing to do.
		// Also, if it is not an infra container, nothing to do in this case as well.
		logrus.Infof("InitialPlatformCheck: CNI called for normal container or infra container, nothing to do")
		// This result is ignored anyway by Kubernetes.
		return true, getFakeCNIResult(), nil
	}
	return false, &current.Result{}, nil
}

func checkContainerOVSPort(ifaceID string) bool {
	ovsArgs := []string{
		"find", "interface", fmt.Sprintf("external_ids:iface-id=%s", ifaceID),
	}
	outputFind, err := exec.Command("ovs-vsctl", ovsArgs...).CombinedOutput()
	if err == nil && len(outputFind) != 0 {
		return true
	} else {
		return false
	}
}

// Retrieves the Windows build number using wmic
func getWindowsVersion() (int, error) {
	args := []string{"os", "get", "BuildNumber", "/value"}
	out, err := exec.Command("wmic", args...).Output()
	if err != nil {
		return 0, err
	}
	buildInfo := strings.Split(string(strings.Trim(string(out), "\" \n\r")), "=")
	windowsVersion, _ := strconv.Atoi(buildInfo[1])
	logrus.Debugf("Windows Version detected: %d", windowsVersion)
	return windowsVersion, nil
}

func runWMIC(namespace string, class string, whereClause string, propertyToRetrieve string) (string, error) {
	cmd := "wmic"
	query := []string{fmt.Sprintf("/namespace:\\\\%s", namespace),
		"Path", class,
		"WHERE", whereClause,
		"GET", propertyToRetrieve,
		"/format:list",
	}
	logrus.Infof("Running wmic %v", query)
	wmicOutput, err := exec.Command(cmd, query...).Output()
	if err != nil {
		return "", err
	}
	trimmedOutput := strings.TrimSpace(string(wmicOutput))
	wmicOutputList := strings.Split(strings.Trim(trimmedOutput, "\""), "=")
	if len(wmicOutputList) == 1 {
		// wmic will not return any error if there are no instances available, the output will not contain
		// any '=' and the length of the list should be 1
		return "", fmt.Errorf("wmic returned no instances available")
	}
	return wmicOutputList[1], nil
}

func getContainerPortDetails(containerID string) (string, string, error) {
	compGUID, err := runWMIC("root\\standardcimv2", "MSFT_NetCompartment",
		fmt.Sprintf("CompartmentDescription='\\\\Container_%s'", containerID),
		"CompartmentGuid")
	if err != nil {
		return "", "", err
	}

	portElementName, err := runWMIC("root\\virtualization\\v2", "Msvm_EthernetPortAllocationSettingData",
		fmt.Sprintf("CompartmentGuid='%s'", compGUID),
		"ElementName")
	if err != nil {
		return "", "", err
	}
	portElementNameList := strings.Split(string(portElementName), " ")
	containerInterfaceName := fmt.Sprintf("Container NIC %v", portElementNameList[len(portElementNameList)-1])
	return containerInterfaceName, portElementName, nil
}

func getContainerPortIPMacAddressGatewayIP(portElementName string) (string, string, string, error) {
	macAddress, err := runWMIC("root\\virtualization\\v2", "Msvm_LanEndpoint",
		fmt.Sprintf("ElementName='%s' and MACAddress is not null", portElementName),
		"MACAddress")
	if err != nil {
		return "", "", "", err
	}
	// macAddress will have format XXXXXXXXXXXX, we want XX-XX-XX-XX-XX-XX
	for i := 2; i < len(macAddress); i += 3 {
		macAddress = macAddress[:i] + "-" + macAddress[i:]
	}
	logrus.Infof("Found MAC Address %v for port %v", macAddress, portElementName)
	endpointList, err := hcsshim.HNSListEndpointRequest()
	if err != nil {
		return "", "", "", err
	}
	ipAddress := ""
	gatewayIP := ""
	for _, endpoint := range endpointList {
		if strings.Compare(macAddress, endpoint.MacAddress) == 0 {
			ipAddress = fmt.Sprintf("%s/%d", endpoint.IPAddress.String(), endpoint.PrefixLength)
			gatewayIP = endpoint.GatewayAddress
			break
		}
	}
	if len(ipAddress) == 0 {
		return "", "", "", fmt.Errorf("Failed to find the IP for port: %v", portElementName)
	}
	logrus.Infof("Found IP %v for port: %v", ipAddress, portElementName)
	// Ensure that the macAddress has xx:xx:xx:xx:xx:xx format
	macAddress = strings.Replace(macAddress, ":", "-", -1)
	macAddress = strings.ToLower(macAddress)
	return ipAddress, macAddress, gatewayIP, nil
}

func configureInterfaceRTM(args *skel.CmdArgs, argsMap map[string]string) (*current.Result, error) {
	logrus.Infof("Setting up pod network on Windows Server RTM")
	containerInterfaceName, portElementName, err := getContainerPortDetails(args.ContainerID)
	if err != nil {
		return &current.Result{}, fmt.Errorf("Failed to get container port details, error: %v", err)
	}

	ovsArgs := []string{
		"--may-exist", "add-port", "br-int", containerInterfaceName, "--", "set",
		"interface", containerInterfaceName, "type=internal"}
	out, err := exec.Command("ovs-vsctl", ovsArgs...).CombinedOutput()
	if err != nil {
		return &current.Result{}, fmt.Errorf("failure in plugging pod interface: %v  %q", err, string(out))
	}

	namespace := argsMap["K8S_POD_NAMESPACE"]
	podName := argsMap["K8S_POD_NAME"]
	ifaceID := fmt.Sprintf("%s_%s", namespace, podName)
	ipAddress, macAddress, gatewayIP, err := getContainerPortIPMacAddressGatewayIP(portElementName)
	if err != nil {
		return &current.Result{}, fmt.Errorf("error getting ip/mac: %v", err)
	}

	ovsArgs = []string{"--", "set", "interface", containerInterfaceName,
		fmt.Sprintf("external_ids:attached_mac=%s", macAddress),
		fmt.Sprintf("external_ids:iface-id=%s", ifaceID),
		fmt.Sprintf("external_ids:ip_address=%s", ipAddress),
	}
	out, err = exec.Command("ovs-vsctl", ovsArgs...).CombinedOutput()
	if err != nil {
		return &current.Result{}, fmt.Errorf("failure in setting external_ids for pod interface: %v  %q", err, string(out))
	}

	ipAddr, ipAddrNet, _ := net.ParseCIDR(ipAddress)
	winResult := &current.Result{
		IPs: []*current.IPConfig{
			{
				Version:   "4",
				Interface: current.Int(1),
				Address:   net.IPNet{IP: ipAddr, Mask: ipAddrNet.Mask},
				Gateway:   net.ParseIP(gatewayIP),
			},
		},
	}
	// TODO: This will not be needed anymore when OVS will get support to set custom IP/Mac for container port
	// Windows Server RTM doesn't support custom IP/Mac address, we have to update OVN with the given IP/Mac
	stdout, stderr, err := util.RunOVNNbctl("--", "lsp-set-addresses", ifaceID, fmt.Sprintf("%s %s", macAddress, ipAddr.String()))
	if err != nil {
		logrus.Errorf("Failed to set macAddress and IP address, stdout: %q, stderr: %q, error: %v", stdout, stderr, err)
		return &current.Result{}, err
	}
	logrus.Infof("Finished setting up network")
	return winResult, nil
}
