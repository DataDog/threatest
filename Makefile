.PHONY: mocks

mocks:
	mockery --name=Detonator --dir pkg/threatest/detonators/ --output pkg/threatest/detonators/mocks
	mockery --name=AlertGeneratedMatcher --dir pkg/threatest/matchers/ --output pkg/threatest/matchers/mocks
