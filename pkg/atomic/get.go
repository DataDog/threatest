package atomic

import (
	"fmt"
	"io"
	"net/http"

	"gopkg.in/yaml.v3"
)

func GetTest(technique, name, version string) (*Test, error) {
	tech, err := GetTechnique(technique, version)
	if err != nil {
		return nil, err
	}

	for _, test := range tech.AtomicTests {
		if test.Name == name {
			return &test, nil
		}
	}

	return nil, fmt.Errorf("test '%s' not found for technique '%s'", technique, name)
}

func GetTechnique(id, version string) (*Technique, error) {
	url := fmt.Sprintf("https://raw.githubusercontent.com/redcanaryco/atomic-red-team/%s/atomics/%s/%s.yaml", version, id, id)

	res, err := http.Get(url)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	body, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}

	var technique *Technique
	if err := yaml.Unmarshal(body, &technique); err != nil {
		return nil, err
	}

	return technique, nil
}
