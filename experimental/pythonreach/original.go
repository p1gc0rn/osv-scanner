package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	// 	scalibrfs "github.com/google/osv-scalibr/fs"
)

type ModuleVersion struct {
	Single     string
	UpperBound string
	LowerBound string
}

type FunctionInfo struct {
	Name  string
	Paths []string
}

type ModuleInfo struct {
	Name          string //original module name
	Alias         string // alias i.e. import math as m
	Version       ModuleVersion
	Functions     []*FunctionInfo
	ImportedItems map[string]string // map[alias]original_name
	Dependencies  []*ModuleInfo
}

var (
	directory        string
	pythonFile       string
	requirementsFile string
	importRegex      = regexp.MustCompile(`^\s*import\s+([a-zA-Z0-9_.]+)(?:\s+as\s+([a-zA-Z0-9_]+))?`)
	fromImportRegex  = regexp.MustCompile(`^\s*from\s+([a-zA-Z0-9_.]+)\s+import\s+(.+)`)
	importItemRegex  = regexp.MustCompile(`([a-zA-Z0-9_.*]+)(?:\s+as\s+([a-zA-Z0-9_]+))?`)
)

type PyPIResponse struct {
	Info struct {
		RequiresDist    []string `json:"requires_dist"`
		Vulnerabilities []string `json:"vulnerabilities"`
	} `json:"info"`
}

var moduleInfos []*ModuleInfo

func init() {
	flag.StringVar(&directory, "directory", "directory", "directory to scan")
	flag.StringVar(&pythonFile, "python_file", "example.py", "python file to scan")
	flag.StringVar(&requirementsFile, "requirements_file", "requirements.txt", "requirements.txt to read")
}

func moduleFinder(file *os.File) ([]*ModuleInfo, error) {
	scanner := bufio.NewScanner(file)
	moduleMap := make(map[string]*ModuleInfo)
	var moduleInfos []*ModuleInfo
	for scanner.Scan() {
		text := strings.TrimSpace(scanner.Text())
		// Skip empty lines and comments
		if text == "" || strings.HasPrefix(text, "#") {
			continue
		}

		// Identify import statements
		if match := importRegex.FindStringSubmatch(text); match != nil {
			moduleName := match[1]
			alias := match[2]
			key := moduleName
			if alias != "" {
				key = alias
			}

			if _, exist := moduleMap[key]; !exist {
				moduleInfo := &ModuleInfo{Name: moduleName, Alias: alias}
				moduleMap[key] = moduleInfo
				moduleInfos = append(moduleInfos, moduleInfo)
			}
		} else if match := fromImportRegex.FindStringSubmatch(text); match != nil {
			baseModuleName := match[1]
			items := match[2]

			baseMInfo, exist := moduleMap[baseModuleName]
			if !exist {
				baseMInfo = &ModuleInfo{Name: baseModuleName, ImportedItems: make(map[string]string)}
				moduleMap[baseModuleName] = baseMInfo
				moduleInfos = append(moduleInfos, baseMInfo)
			}

			if strings.TrimSpace(items) == "*" {
				baseMInfo.ImportedItems["*"] = "*"
			} else {
				items := strings.Split(items, ",")
				for _, item := range items {
					item = strings.TrimSpace(item)
					if itemMatch := importItemRegex.FindStringSubmatch(item); itemMatch != nil {
						originalItemName := itemMatch[1]
						itemAlias := itemMatch[2]
						nameOfItemInFile := originalItemName
						if itemAlias != "" {
							nameOfItemInFile = itemAlias
						}
						baseMInfo.ImportedItems[nameOfItemInFile] = originalItemName
					}
				}
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error scanning file: %w", err)
	}

	// Find functions used
	if _, err := file.Seek(0, 0); err != nil {
		return nil, fmt.Errorf("error seeking file: %w", err)
	}

	scanner = bufio.NewScanner(file)
	for scanner.Scan() {
		text := strings.TrimSpace(scanner.Text())
		// Skip empty lines and comments
		if text == "" || strings.HasPrefix(text, "#") || strings.Contains(text, "import") {
			continue
		}

		for i, moduleInfo := range moduleInfos {
			if moduleInfo.Alias != "" {
				s := fmt.Sprintf(`%s\.([a-zA-Z_][a-zA-Z_.]*)`, regexp.QuoteMeta(moduleInfo.Alias))
				re := regexp.MustCompile(s)
				matches := re.FindStringSubmatch(text)
				if len(matches) > 0 {
					moduleInfo.Functions = append(moduleInfo.Functions, &FunctionInfo{Name: matches[1]})
				}
			}

			imported := moduleInfo.ImportedItems
			if len(imported) == 0 {
				continue
			}
			for key := range imported {
				s := fmt.Sprintf(`\b%s\b`, regexp.QuoteMeta(key))
				re := regexp.MustCompile(s)
				matches := re.FindStringSubmatch(text)
				if len(matches) > 0 {
					moduleInfos[i].Functions = append(moduleInfos[i].Functions, &FunctionInfo{Name: matches[0]})
				}
			}
		}

	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error finding function: %w", err)
	}

	return moduleInfos, nil
}

func collectVersion(file *os.File, moduleInfos []*ModuleInfo) []*ModuleInfo {
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		if strings.HasPrefix(scanner.Text(), "#") || scanner.Text() == "" || strings.Contains(scanner.Text(), "python_version") {
			continue
		}

		if strings.Contains(scanner.Text(), "==") {
			part := strings.Split(scanner.Text(), "==")
			found := false
			for _, module := range moduleInfos {
				if strings.EqualFold(module.Name, part[0]) {
					module.Name = part[0]
					module.Version.Single = part[1]
					found = true
					break
				}
			}

			if !found {
				moduleInfos = append(moduleInfos, &ModuleInfo{Name: part[0], Version: ModuleVersion{Single: part[1]}})
			}
			continue
		}

		if strings.Contains(scanner.Text(), ">=") || strings.Contains(scanner.Text(), "<=") || strings.Contains(scanner.Text(), ">") || strings.Contains(scanner.Text(), "<") {
			continue
		}
	}

	return moduleInfos
}

func getPackageDependencies(moduleInfos []*ModuleInfo) ([]*ModuleInfo, error) {
	for _, moduleInfo := range moduleInfos {
		url := fmt.Sprintf("https://pypi.org/pypi/%s/%s/json", moduleInfo.Name, moduleInfo.Version.Single)
		resp, err := http.Get(url)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("HTTP request failed with status code: %d", resp.StatusCode)
		}

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return nil, err
		}

		var pypiResponse PyPIResponse
		err = json.Unmarshal(body, &pypiResponse)
		if err != nil {
			return nil, err
		}

		requiresDist := pypiResponse.Info.RequiresDist
		fmt.Printf("Requires Dist: %v\n", requiresDist)
		for _, dep := range requiresDist {
			//parts := strings.Split(dep, " (")
			m := &ModuleInfo{}
			// Get the version numbers
			re := regexp.MustCompile(`([a-zA-Z_][a-zA-Z_.]*)([<>]=?\d*\.?\d+)`) // Capturing group for symbols and numbers
			matches := re.FindAllStringSubmatch(dep, -1)
			for _, match := range matches {
				m = &ModuleInfo{Name: strings.TrimSpace(match[0])}
				if strings.HasPrefix(match[1], ">=") {
					m.Version.UpperBound = strings.TrimLeft(match[1], ">=")
					continue

				} else if strings.HasPrefix(match[1], ">") {
					m.Version.UpperBound = strings.TrimLeft(match[1], ">")
					continue

				} else if strings.HasPrefix(match[1], "<=") {
					m.Version.LowerBound = strings.TrimLeft(match[1], "<=")
					continue
				} else if strings.HasPrefix(match[1], "<") {
					m.Version.LowerBound = strings.TrimLeft(match[1], "<")
					continue

				}

			}
			moduleInfo.Dependencies = append(moduleInfo.Dependencies, m)
		}
	}
	return moduleInfos, nil
}

func downloadPackageSource(downloadLink string) (string, error) {
	// Get the filename from the URL
	filename := filepath.Base(downloadLink)
	fmt.Printf("Filename: %s\n", filename)
	// Create a temporary file
	tempFile, err := os.CreateTemp("/usr/local/google/home/pnyl/dev/osv-scanner/experimental/pythonreach", filename)
	if err != nil {
		return "", fmt.Errorf("failed to create temp file: %w", err)
	}
	defer tempFile.Close()

	// Get the HTTP response
	resp, err := http.Get(downloadLink)
	if err != nil {
		os.Remove(tempFile.Name()) // Clean up temp file on error
		return "", fmt.Errorf("failed to get URL: %w", err)
	}
	defer resp.Body.Close()

	// Check the HTTP status code
	if resp.StatusCode != http.StatusOK {
		os.Remove(tempFile.Name()) // Clean up temp file on error
		return "", fmt.Errorf("HTTP error: %d", resp.StatusCode)
	}

	// Copy the response body to the temporary file
	_, err = io.Copy(tempFile, resp.Body)
	if err != nil {
		os.Remove(tempFile.Name()) // Clean up temp file on error
		return "", fmt.Errorf("failed to copy: %w", err)
	}

	fmt.Printf("Downloaded %s to %s\n", filename, tempFile.Name())
	return tempFile.Name(), nil
}

func extractCompressedPackageSource(fileName string) error {
	cmd := exec.Command("tar", "-xzf", fileName)
	output, err := cmd.CombinedOutput() // Capture both stdout and stderr
	if err != nil {
		return fmt.Errorf("failed to execute tar command: %w, output: %s", err, string(output))
	}
	return nil
}

func retrievePackageSource(moduleInfo *ModuleInfo) error {
	url := fmt.Sprintf("https://pypi.org/simple/%s/", moduleInfo.Name)
	resp, err := http.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%s HTTP error: %d", moduleInfo.Name, resp.StatusCode)
	}

	s := strings.ToLower(fmt.Sprintf(`%s\-%s\.tar\.gz`, moduleInfo.Name, moduleInfo.Version.Single))
	scanner := bufio.NewScanner(resp.Body)
	for scanner.Scan() {
		line := strings.ToLower(scanner.Text())
		re := regexp.MustCompile(s)
		matches := re.MatchString(line)
		if matches {
			re = regexp.MustCompile(`<a href="([^"]+)"`)
			substring := re.FindStringSubmatch(line)
			fileName, err := downloadPackageSource(substring[1])
			if err != nil {
				return fmt.Errorf("failed to download package source: %w", err)
			}
			err = extractCompressedPackageSource(fileName)
			if err != nil {
				return err
			}
			err = os.Remove(fileName)
			if err != nil {
				return fmt.Errorf("failed to remove file: %w", err)
			}
			return nil
		}
	}

	return nil
}

func findFolder(root, folderName string) (string, error) {
	var name string
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() && strings.Contains(d.Name(), folderName) {
			name = d.Name()
			return filepath.SkipAll
		}
		return nil
	})

	if err != nil {
		return "", err
	}

	return name, nil
}

// Look for the directory matching with module name
// then traverse the directory and find the functions used in the imported packages
// check if the function contains depedenencies
func getFilesInDirectory(moduleInfo *ModuleInfo) error {
	// Find the directory name of module
	moduleFolder, err := findFolder("/usr/local/google/home/pnyl/dev/osv-scanner/experimental/pythonreach", moduleInfo.Name)
	if err != nil {
		return err
	}

	// Traverse the directories of the module
	root := fmt.Sprintf("/usr/local/google/home/pnyl/dev/osv-scanner/experimental/pythonreach/%s", moduleFolder)
	err = filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() {
			if strings.HasSuffix(path, "py") {
				file, err := os.Open(path)
				if err != nil {
					return err
				}
				defer file.Close()

				scanner := bufio.NewScanner(file)
				for scanner.Scan() {
					for _, function := range moduleInfo.Functions {
						searchTerm := fmt.Sprintf("def %s", function.Name)
						if strings.Contains(scanner.Text(), searchTerm) {
							function.Paths = append(function.Paths, path)
						}
					}
				}
			}
		}
		return nil
	})

	if err != nil {
		return err
	}
	return nil
}

func old_main() {
	flag.Parse()

	// 1. read python file
	pythonFile, err := os.Open(pythonFile)
	if err != nil {
		log.Fatal(err)
	}
	defer pythonFile.Close()

	moduleMap, _ := moduleFinder(pythonFile)
	for _, value := range moduleMap {
		fmt.Printf("Module: %s\n", value.Name)
		fmt.Printf("Alias: %s\n", value.Alias)
		//fmt.Printf("importeditems: %v\n", value.ImportedItems)
		for key, item := range value.ImportedItems {
			fmt.Printf("Imported Item key: %s, item: %s\n", key, item)
		}
		for _, function := range value.Functions {
			fmt.Printf("Function: %s\n", function.Name)
		}
	}
}
func main() {
	flag.Parse()

	// 1. read python file
	pythonFile, err := os.Open(pythonFile)
	if err != nil {
		log.Fatal(err)
	}
	defer pythonFile.Close()

	moduleMap, _ := moduleFinder(pythonFile)

	// 2. read requirements.txt file using the librariy in https://github.com/google/osv-scalibr/blob/main/extractor/filesystem/language/python/requirements/requirements.go
	requirementsFile, err := os.Open(requirementsFile)
	if err != nil {
		log.Fatal(err)
	}
	defer requirementsFile.Close()
	moduleMap = collectVersion(requirementsFile, moduleMap)

	// 3. get dependencies & their version from PyPI
	getPackageDependencies(moduleMap)
	// for _, value := range moduleMap {
	// 	fmt.Printf("Module: %s\n", value.Name)
	// 	for _, function := range value.Functions {
	// 		fmt.Printf("Function: %s\n", function)
	// 	}
	// 	fmt.Printf("Version: %s\n", value.Version)
	// 	for _, dep := range value.Dependencies {
	// 		fmt.Printf("Dependency: %s\n", dep)
	// 	}
	// }

	// 4. get the source of the module and their dependencies using pypi-simple
	for _, module := range moduleMap {
		if module.Version.Single == "" {
			continue
		}
		//fmt.Printf("Module: %s\n", module.Name)
		err = retrievePackageSource(module)
		if err != nil {
			log.Printf("Error: %v\n", err)
		}
	}

	// 5. traverse the directory and find the paths of functions used in the imported modules
	for _, module := range moduleMap {
		err := getFilesInDirectory(module)
		if err != nil {
			log.Printf("Error: %v\n", err)
		}
	}
	for _, value := range moduleMap {
		fmt.Printf("Module: %s\n", value.Name)
		for _, function := range value.Functions {
			fmt.Printf("Function Name: %s\n", function.Name)
			fmt.Printf("Function Paths: %s\n", function.Paths)
		}
		fmt.Printf("Version: %s\n", value.Version)
		for _, dep := range value.Dependencies {
			fmt.Printf("Dependency: %s\n", dep.Name)
		}
	}

	// 5b) Call python file with the paths are the arguments to get the dependencies called in those functions
	// We capture the ouptut
	for _, module := range moduleMap {
		if len(module.Functions) > 0 {
			for _, function := range module.Functions {
				if len(function.Paths) > 0 {
					cmd := exec.Command("python3", "function_parser.py", function.Name, strings.Join(function.Paths[:], ","))
					fmt.Printf("Looking for function: %s\n", function.Name)
					//fmt.Println(cmd)
					output, err := cmd.Output()
					if err != nil {
						fmt.Println("Error:", err)
						return
					}
					fmt.Println("Python script output:")
					for _, line := range strings.Split(string(output), "\n") {
						if strings.Contains(line, "Found:") {
							fmt.Println(line)
						} else if strings.Contains(line, "Not Found:") {
							fmt.Println(line)
						}
					}
				}
			}
		}
	}
	// Compare with the dependency in the module info struct
}
