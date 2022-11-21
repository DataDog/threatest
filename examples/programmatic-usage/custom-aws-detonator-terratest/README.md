This examples shows how to use Threatest with pre-requisite infrastructure spun up by 
[Terratest](https://terratest.gruntwork.io/).

Note that when the attack technique you want to simulate is supported by Stratus Red Team, 
it is simpler to use the Stratus Red Team detonator. 
However, the AWS Detonator allows you to detonate arbitrary code using the AWS SDK, for reproducing custom or more advanced attack techniques.

The AWS detonator injects the detonation UUID inside of the AWS SDK user-agent, allowing to 
correlate the alert with the detonation.

In this test, we attempt to change the S3 bucket of a running CloudTrail trail, simulating
an attacker who attempts to disrupt CloudTrail logging.

You need Terraform installed to run this test.

```
go test -v ./custom_aws_detonator_with_terratest_test.go
```