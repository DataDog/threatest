.PHONY: mocks

MAKEFILE_PATH := $(abspath $(lastword $(MAKEFILE_LIST)))
ROOT_DIR := $(dir $(MAKEFILE_PATH))

thirdparty-licenses:
	go get github.com/google/go-licenses
	go install github.com/google/go-licenses
	$(GOPATH)/bin/go-licenses csv github.com/datadog/threatest/pkg/threatest | sort > $(ROOT_DIR)/LICENSE-3rdparty.csv

mocks:
	mockery --name=Detonator --dir pkg/threatest/detonators/ --output pkg/threatest/detonators/mocks
	mockery --name=AlertGeneratedMatcher --dir pkg/threatest/matchers/ --output pkg/threatest/matchers/mocks
	mockery --name=DatadogSecuritySignalsAPI  --dir pkg/threatest/matchers/datadog --output pkg/threatest/matchers/datadog/mocks
