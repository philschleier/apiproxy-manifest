package main

import (
	"crypto/sha512"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"regexp"
	"sort"
	"strings"

	"github.com/go-kit/kit/log"
)

var logger log.Logger

func init() {
	w := log.NewSyncWriter(os.Stderr)
	logger = log.NewLogfmtLogger(w)
}

func main() {
	if len(os.Args) != 2 {
		_ = logger.Log("message", "please give exactly one argument (apiproxy folder)")
		return
	}
	folder := os.Args[1]
	if p := strings.Split(folder, "/"); p[len(p)-1] != "apiproxy" {
		p = append(p, "apiproxy")
		folder = strings.Join(p, "/")
		_ = logger.Log("message", "adding suffix /apiproxy")
	}

	apiproxyFile, apiproxy, err := findProxyFile(folder)
	if err != nil {
		_ = logger.Log("err", err)
		return
	}

	doc := new(Manifest)
	doc.Name = "manifest"
	{
		dir := folder + "/policies"
		policies, err := calculateAll(dir, stripSuffix("xml"))
		if err != nil {
			_ = logger.Log("err", err)
			return
		}
		doc.Policies.VersionInfo = policies
	}
	{
		dir := folder + "/proxies"
		proxies, err := calculateAll(dir, stripSuffix("xml"))
		if err != nil {
			_ = logger.Log("err", err)
			return
		}
		doc.ProxyEndpoints.VersionInfo = proxies
	}
	{
		dir := folder + "/resources"
		resourceDir, err := ioutil.ReadDir(dir)
		if err != nil {
			_ = logger.Log("err", err)
			return
		}
		for _, d := range resourceDir {
			resourceDir := dir + "/" + d.Name()
			resources, err := calculateAll(resourceDir, func(file os.FileInfo) string {
				return d.Name() + "://" + file.Name()
			})
			if err != nil {
				_ = logger.Log("err", err)
				return
			}
			doc.Resources.VersionInfo = append(doc.Resources.VersionInfo, resources...)
		}
	}

	xm, err := marshal(&doc)
	if err != nil {
		_ = logger.Log("err", err)
		return
	}

	f, err := os.Create(folder + "/manifests/manifest.xml")
	if err != nil {
		_ = logger.Log("err", err)
		return
	}
	defer f.Close()

	data := `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>` + "\n" + string(xm) + "\n"
	_, err = f.WriteString(data)
	if err != nil {
		_ = logger.Log("err", err)
		return
	}
	_ = logger.Log("message", "wrote manifest.xml")
	msum, err := sum(folder + "/manifests/manifest.xml")
	if err != nil {
		_ = logger.Log("err", err)
		return
	}
	apiproxy.ManifestVersion = "SHA-512:" + msum
	xm, err = marshal(&apiproxy)
	if err != nil {
		_ = logger.Log("err", err)
		return
	}
	pf, err := os.Create(apiproxyFile)
	if err != nil {
		_ = logger.Log("err", err)
		return
	}
	defer pf.Close()
	data = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>` + "\n" + string(xm) + "\n"
	_, err = pf.WriteString(data)
	if err != nil {
		_ = logger.Log("err", err)
		return
	}
	_ = logger.Log("message", "wrote "+apiproxyFile)
}

func stripSuffix(suffix string) func(file os.FileInfo) string {
	suffix = "." + suffix
	return func(file os.FileInfo) string {
		return strings.TrimSuffix(file.Name(), suffix)
	}
}

func calculateAll(dir string, resourceName func(os.FileInfo) string) ([]VersionInfo, error) {
	files, err := ioutil.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	infos := make([]VersionInfo, len(files))
	resourceNames := make(map[string]string)
	sorted := make([]string, len(files))

	for i, file := range files {
		x := resourceName(file)
		resourceNames[x] = file.Name()
		sorted[i] = x
	}
	sort.Strings(sorted)
	for i, file := range sorted {
		filename := resourceNames[file]
		sha, _ := sum(dir + "/" + filename)
		infos[i] = VersionInfo{
			ResourceName: file,
			Version:      fmt.Sprintf("SHA-512:%s", sha),
		}
	}
	return infos, nil
}

func findProxyFile(folder string) (string, *APIProxy, error) {
	files, err := ioutil.ReadDir(folder)
	if err != nil {
		return "", nil, err
	}
	for _, file := range files {
		if file.IsDir() {
			continue
		}
		if strings.HasSuffix(file.Name(), ".xml") {
			path := folder + "/" + file.Name()
			ok, proxy := checkProxyFile(path)
			if ok {
				return path, proxy, nil
			}
		}
	}
	return "", nil, errors.New("didnt find main proxy file")
}

func checkProxyFile(path string) (bool, *APIProxy) {
	c, err := ioutil.ReadFile(path)
	if err != nil {
		return false, nil
	}
	var p APIProxy
	err = xml.Unmarshal(c, &p)
	if err != nil {
		return false, nil
	}
	return true, &p
}

func sum(filename string) (string, error) {
	f, err := os.Open(filename)
	if err != nil {
		return "", err
	}
	defer f.Close()

	h := sha512.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}

	return fmt.Sprintf("%x", h.Sum(nil)), nil
}

func marshal(v interface{}) ([]byte, error) {
	xm, err := xml.MarshalIndent(v, "", "    ")
	if err != nil {
		return nil, err
	}
	re := regexp.MustCompile("(></\\w+>)")
	replace := []byte("/>")
	xm = re.ReplaceAll(xm, replace) // https://github.com/golang/go/issues/21399
	return xm, nil
}

type Manifest struct {
	Name     string `xml:"name,attr"`
	Policies struct {
		VersionInfo []VersionInfo
	}
	ProxyEndpoints struct {
		VersionInfo []VersionInfo
	}
	Resources struct {
		VersionInfo []VersionInfo
	}
	SharedFlows struct {
		VersionInfo []VersionInfo
	}
	TargetEndpoints struct {
		VersionInfo []VersionInfo
	}
}

type VersionInfo struct {
	ResourceName string `xml:"resourceName,attr"`
	Version      string `xml:"version,attr"`
}

type APIProxy struct {
	Revision             string `xml:"revision,attr"`
	Name                 string `xml:"name,attr"`
	Basepaths            []string
	ConfigurationVersion struct {
		MajorVersion string `xml:"majorVersion,attr"`
		MinorVersion string `xml:"minorVersion,attr"`
	}
	CreatedAt       string
	CreatedBy       string
	Description     string
	DisplayName     string
	LastModifiedAt  string
	LastModifiedBy  string
	ManifestVersion string
	Policies        struct {
		Policy []string
	}
	ProxyEndpoints struct {
		ProxyEndpoint []string
	}
	Resources struct {
		Resource []string
	}
	Spec            string
	TargetServers   string
	TargetEndpoints string
}
