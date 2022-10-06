# Example

## Testing Cloud SIEM rules

[`cloudsiem_alerts_test.go`](./cloudsiem_alerts_test.go) uses Stratus Red Team (through its programmatic interface) to detonate AWS attack ttechniques, then polls the Datadog API to verify that an expected Cloud SIEM signal was created.

Sample usage:

```
go test -timeout 99999s cloudsiem_alerts_test.go -v
```

Sample output:

```
=== RUN   TestCloudSIEMAWSAlerts
Detonating 'aws.initial-access.console-login-without-mfa' with Stratus Red Team
2022/06/16 16:31:08 AWS console login: Confirmed that the expected signal (Datadog security signal 'An IAM user was created') was created in Datadog (took 17 seconds).
2022/06/16 16:31:08 AWS console login: Confirmed that the expected signal (Datadog security signal 'AWS Console login without MFA') was created in Datadog (took 17 seconds).
2022/06/16 16:31:08 AWS console login: All assertions passed

Detonating 'aws.persistence.iam-create-admin-user' with Stratus Red Team
2022/06/16 16:31:14 AWS persistence IAM user: Confirmed that the expected signal (Datadog security signal 'An IAM user was created') was created in Datadog (took 0 seconds).
2022/06/16 16:31:14 AWS persistence IAM user: All assertions passed
--- PASS: TestCloudSIEMAWSAlerts (126.53s)
PASS
```

## Testing CWS rules

[`cws_alerts_tests.go`](./cws_alerts_test.go) assumes you have a machine `test-box` configured in your OpenSSH configuration, and running CWS (for instance using [datadog-security-monitoring-strater](https://github.com/DataDog/datadog-security-monitoring-starter/tree/main/1.virtual-machine)).

It will detonate several commands through SSH on the machine, and poll the Datadog API to verify that the expected CWS signals were generated.

Sample usage:

```
go test cws_alerts_test.go -v
```

Sample output:

```
=== RUN   TestCWSAlerts
Connecting over SSH
Connection succeeded
2022/06/16 16:25:20 curl to metadata service: Confirmed that the expected signal (Datadog security signal 'EC2 Instance Metadata Service Accessed via Network Utility') was created in Datadog (took 12 seconds).
2022/06/16 16:25:20 curl to metadata service: All assertions passed
2022/06/16 16:25:42 Java spawning shell: Confirmed that the expected signal (Datadog security signal 'Java process spawned shell/utility') was created in Datadog (took 19 seconds).
2022/06/16 16:25:42 Java spawning shell: All assertions passed
--- PASS: TestCWSAlerts (45.64s)
```

``` 
=== RUN   TestCWSAlertsV2
Connecting over SSH
Connection succeeded
=== RUN   TestCWSAlertsV2/curl_to_metadata_service
=== PAUSE TestCWSAlertsV2/curl_to_metadata_service
=== RUN   TestCWSAlertsV2/java_spawns_shell
=== PAUSE TestCWSAlertsV2/java_spawns_shell
=== CONT  TestCWSAlertsV2/java_spawns_shell
=== CONT  TestCWSAlertsV2/curl_to_metadata_service
2022/06/16 16:26:02 curl to metadata service: Confirmed that the expected signal (Datadog security signal 'EC2 Instance Metadata Service Accessed via Network Utility') was created in Datadog (took 11 seconds).
2022/06/16 16:26:02 curl to metadata service: All assertions passed
2022/06/16 16:26:02 java spawns shell: Confirmed that the expected signal (Datadog security signal 'Java process spawned shell/utility') was created in Datadog (took 17 seconds).
2022/06/16 16:26:02 java spawns shell: All assertions passed
--- PASS: TestCWSAlertsV2 (0.06s)
    --- PASS: TestCWSAlertsV2/java_spawns_shell (20.12s)
    --- PASS: TestCWSAlertsV2/curl_to_metadata_service (20.24s)
PASS
```

## Using the custom AWS detonator and Terratest to prepare infrastructure

See [custom-aws-detonator-terratest](./custom-aws-detonator-terratest).

## Using the local detonator

Setup: Export DD API key and App key as environment variables
```
export DD_API_KEY=<API_KEY>
export DD_APP_KEY=<APP_KEY>
```

Sample usage:
```
go test local_detonator_test.go -v
```

Sample output:
```
=== RUN   TestLocalDetonator
Executing curl http://169.254.169.254 --connect-timeout 5
Executing cp /bin/bash /tmp/java; /tmp/java -c "curl 1.1.1.1"
Test failed: At least one scenario failed:

curl to metadata service returned: curl to metadata service: 1 assertions did not pass
 => Did not find Datadog security signal 'Network utility executed'
Java spawning shell returned: Java spawning shell: 1 assertions did not pass
 => Did not find Datadog security signal 'Java process spawned shell'

--- FAIL: TestLocalDetonator (361.94s)
FAIL
FAIL	command-line-arguments	361.954s
FAIL
```

```
=== RUN   TestLocalDetonator
Executing curl http://169.254.169.254 --connect-timeout 5
Executing cp /bin/bash /tmp/java; /tmp/java -c "curl 1.1.1.1"
--- PASS: TestLocalDetonator (38.10s)
PASS
ok  	command-line-arguments	38.121s
```
