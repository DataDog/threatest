# Threatest

![unit tests](https://github.com/DataDog/threatest/actions/workflows/test.yml/badge.svg)
![static analysis](https://github.com/DataDog/threatest/actions/workflows/static-analysis.yml/badge.svg)

Threatest is a Go framework for testing threat detection end-to-end.

Threatest allows you to **detonate** an attack technique, and verify that the alert you expect was generated in your favorite security platform.

Read the announcement blog post: https://securitylabs.datadoghq.com/articles/threatest-end-to-end-testing-threat-detection/

## Concepts

### Detonators

A **detonator** describes how and where an attack technique is executed.

Supported detonators:
* Local command execution
* SSH command execution
* Stratus Red Team
* AWS detonator

### Alert matchers

An **alert matcher** is a platform-specific integration that can check if an expected alert was triggered.

Supported alert matchers:
* Datadog security signals

### Detonation and alert correlation

Each detonation is assigned a UUID. This UUID is reflected in the detonation and used to ensure that the matched alert corresponds exactly to this detonation.

The way this is done depends on the detonator; for instance, Stratus Red Team and the AWS Detonator inject it in the user-agent; the SSH detonator uses a parent process containing the UUID.

## Sample usage

See [examples](./examples) for complete usage example.

### Testing Datadog Cloud SIEM signals triggered by Stratus Red Team

```go
threatest := Threatest()

threatest.Scenario("AWS console login").
  WhenDetonating(StratusRedTeamTechnique("aws.initial-access.console-login-without-mfa")).
  Expect(DatadogSecuritySignal("AWS Console login without MFA").WithSeverity("medium")).
  WithTimeout(15 * time.Minute)

assert.NoError(t, threatest.Run())
```

### Testing Datadog Cloud Workload Security signals triggered by running commands over SSH

```go
ssh, _ := NewSSHCommandExecutor("test-box", "", "")

threatest := Threatest()

threatest.Scenario("curl to metadata service").
  WhenDetonating(NewCommandDetonator(ssh, "curl http://169.254.169.254 --connect-timeout 1")).
  Expect(DatadogSecuritySignal("EC2 Instance Metadata Service Accessed via Network Utility"))

assert.NoError(t, threatest.Run())
```
