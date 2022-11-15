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