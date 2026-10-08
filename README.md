# IDMEFv2-Splunk-Connector
A Splunk SIEM to IDMEFv2 connector

# Main purpose
This connector is designed to convert alerts coming from splunk into IDMEFv2 **2.D.V08** format.

This is the base/generic connector for standard Splunk deployments (any search result, not tied to Splunk Enterprise Security). For Splunk ES lifecycle-aware alerting (notable events, `PredID` chaining, `Status`), see the separate `IDMEFv2-SplunkES-Plugin` project.

# Important 
Once the connector has been installed and the alert set up it is entirely normal for it to not begin loging incidents right away. Splunk alerts can take a few minutes to start but will work as scheduled after the first send, until they are disabled.  

# Requirements
- For this test we are using Splunk version 9.4.1
- It is not necessary to install splunk on docker, but this guide has been tested on a docker container.

# Installation and example setup
1. Download the files from the repository.
2. Run the package-app.sh script with a user that has administrative privileges.
    - The script will automatically create a tar.gz package containing the application, placed in the path release/application_name.tar.gz.
3. Start Splunk and click on Manage in the Apps section.
    - On the new page, click the button in the top-right corner labeled Install App From File.
    - On the next page that appears, upload the .tar.gz package you created in step 2.

Your application has been installed.

4. Now enter into the **log** folder inside this path: /opt/splunk/var
5. Create a file named **auth.json** and write the following json into it. This will be the example file Splunk will monitor.
    ```
    {
        "Category":"Attempt.Login",
        "type":"Cyber",
        "src_ip":"192.168.92.240", 
        "dvc_host":"auth.splunk.com", 
        "dvc_name":"SPLUNK",
        "priority":"medium", 
        "src_host":"DC", 
        "src_port":"-",
        "dest_host":"target_host", 
        "dest_name":"51188", 
        "start_time":"2025-05-19 12:15:42", 
        "unlocation":"IT ROM",
        "description":"User logon with misspelled or bad password", 
        "dvc_category":"SIEM", 
        "vendor_product":"9.4.2"
    }
    ```
6. Restart Splunk and access your account.
7. Click **Settings** -> **Data inputs** -> **Files & Directories** -> **New Local File & Directory**
8. Click **browse**, and select the **auth.json** file. In our case it was in the following path: opt/splunk/var/log/auth.json, then click on **Next**.
9. Click on the dropdown menu **Source Type: Select Source Type** and select **__json** as the type (it may already be selected), then click on **Next**.
10. **App context** should already be set as **Search & Reporting** and **Host field value** as **costant value**. These values are fine.
11. Click on review then submit.

12. Go back to the **Home** page.
13. Find the **Search & Reporting** section under **Apps** and click on it.
14. Now search something using the bar, here's an example:
    - Write the following into the searchbar: "src_ip" = "192.168.92.240"
    - Set the time to **All time**
    - Start the research
15. Click on the **Save as** button located above the searchbar on the right, then select **Alert**.
16. From here you can set your alert however you prefer, here's an example (everything that isn't mentioned can be left as is):
    - *Title*: Example_Alert
    - *Permissions*: Shared in Apps
    - *Alert type*: **Scheduled** -> **Run on Cron Schedule**
    - *Time Range*: **All time**
    - *Cron Expression*: */1 * * * * (This means every minute, you can change it to whatever interval you prefer)
    - *Trigger Actions*: Add two actions
        - **Add to Triggered Alerts** (Select whatever severity you want to see on splunk, this does not affect the connector. It is added to allow you to see when your alert is triggered — without it, Splunk's "Triggered Alerts" page will stay empty even if the connector is sending successfully)
        - **Send Alert in IDMEFv2 format** — configure at least the **Endpoint**. See [Alert action parameters](#alert-action-parameters) below for the rest (authentication, organisation info).
17. Save your alert.
18. Your alert is now in effect. If you've followed our examples Splunk will send a new alert to your IDMEFv2 server every minute until you decide to disable the alert.

# Alert action parameters

| Parameter | Default | Description |
|---|---:|---|
| Endpoint | *(required)* | IDMEFv2 endpoint the generated alert is sent to. |
| Auth Type | `none` | `none`, `bearer` (token), or `basic` (username/password). |
| Bearer Auth Token | empty | Used only when Auth Type is Bearer token. |
| Basic Auth Username / Password | empty | Used only when Auth Type is Basic username/password. |
| Verify SSL | `1` | Verifies the endpoint's TLS certificate. Disable (`0`) only for lab environments or self-signed certificates. |
| Organisation Name | `CHANGE-ME` | IDMEFv2 `OrganisationName` — set this to your actual organisation name. Some receivers may override this server-side based on the authenticated sender's identity, regardless of what's sent here — check with your receiver if the value doesn't appear to stick. |
| Organisation ID | `CHANGE-ME` | IDMEFv2 `OrganisationId` — set this to your actual organisation identifier. |

# Category mapping

The `Category` field is resolved in this order:
1. An explicit category already present in the triggering event (e.g. a `Category` field set by the search itself), when it's already a valid IDMEFv2 V08 category.
2. The same explicit value translated through `IDMEFv2-Splunk/lookups/idmefv2_category_mapping.csv` — an editable lookup for mapping legacy/custom category strings to valid V08 categories, without touching code.
3. A keyword match on the raw event text, as a last-resort fallback.
4. `Other.Undetermined` if nothing above matched.

`Cause` is derived automatically from the resolved `Category`.

# To disable your custom alert
1. From the **Home** page click on the **Search & Reporting** section under **Apps**
2. Click on the **Alerts** tab from the navbar
3. Click on your alert
4. Click on **disable**
