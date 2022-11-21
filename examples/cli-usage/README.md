# Sample CLI usage

Sample usage:

```
threatest run scenarios.threatest.yaml --ssh-host test-box --output test-results.json
```

Sample scenario test output file:

```json
[
  {
    "description": "curl metadata service",
    "isSuccess": true,
    "errorMessage": "",
    "durationSeconds": 20.175771331,
    "timeDetonated": "2022-11-15T22:41:28.137922+01:00"
  },
  {
    "description": "opening a security group to the Internet",
    "isSuccess": true,
    "errorMessage": "",
    "durationSeconds": 114.920678743,
    "timeDetonated": "2022-11-15T22:41:28.137932+01:00"
  }
]
```

You can use Threatest's JSONSchema in your editor to benefit from in-IDE linting and autocompletion (see [documentation for VSCode](https://marketplace.visualstudio.com/items?itemName=redhat.vscode-yaml#associating-a-schema-to-a-glob-pattern-via-yaml.schemas) using the [YAML](https://marketplace.visualstudio.com/items?itemName=redhat.vscode-yaml) extension).
