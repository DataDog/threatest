# Splunk Enterprise Security notable event matcher
To work with the Splunk Enterprise Security notable event matcher, you need to have the following prerequisites:
- A working Splunk instance with the Enterprise Security app installed and the ability to talk to the REST API.
- An account in Splunk with the necessary permissions to create and manage notable events.
- A valid API token for authentication (you can also use basic auth credentials).

Environment variables:
- `SPLUNK_HOST`: The hostname or IP address of the Splunk instance including the port for the REST API (usually 8089).
- `SPLUNK_API_TOKEN`: The API token for authentication (required if no `SPLUNK_USERNAME`/`SPLUNK_PASSWORD`).
  - `SPLUNK_USERNAME`: The username for basic authentication (required if no `SPLUNK_API_TOKEN`).
  - `SPLUNK_PASSWORD`: The password for basic authentication (required if no `SPLUNK_API_TOKEN`).
- `SPLUNK_INSECURE_SKIP_VERIFY`: Default is `false`. Set to `true` to skip SSL verification (not recommended).

Example scenario configuration:
```yaml
scenarios:
  - name: Stop cloudtrail
    detonate:
      stratusRedTeamDetonator:
        attackTechnique: aws.defense-evasion.cloudtrail-stop
    expectations:
      - timeout: 30m
        checkInterval: 2m
        splunkNotableEvent:
          name: "ESCU - AWS Defense Evasion Stop Logging Cloudtrail - Rule"
          startTime: -2h
```
For `splunkNotableEvent`, only `name` and `startTime` is required.

`name` should match the name of the correlation search in Splunk that generates the notable event. 

`startTime` is a relative time string that specifies the earliest time to search for notable events. It can be set to a negative value (e.g., `-2h` for 2 hours ago). This is an important field because you don't want to search the entirety of your notable index for these notables. You can also set `endTime` which works similarly but this is optional.

## Expectations
Here is an overview of how the matcher works:

After a detonation, the matcher will run a search via the Splunk API for notable events that match both the `search_name` and the UUID of the detonation.
```text
search earliest=-2h `notable` | search search_name=\"ESCU - AWS Defense Evasion Stop Logging Cloudtrail - Rule\" a6c34363-397b-4638-85c4-de2682c6933b"
```
If the search job has results, that scenario will be marked as a success and the notable will be closed with the comment "Closed by Threatest".

If there are no results, the matcher will continue to run the search query at the specified interval until the timeout is reached. If the timeout is reached and no results are found, the scenario will be marked as a failure. Finally, Threatest will run another search to look for notables that reference the detection UUID:
```text
output here
```
Any notables that are returned will also be closed with the comment "Closed by Threatest".