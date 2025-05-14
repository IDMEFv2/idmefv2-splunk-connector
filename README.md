# IDMEFv2-Splunk-Connector
A Splunk SIEM to IDMEFv2 connector

# Main purpose
This connector is designed to convert alerts coming from splunk into the IDMEFv2 format.  

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
     "src_ip": "10.219.15.14",
     "message": "In a 5-second period, between 2025-05-12 11:15:11 and 2025-05-12 11:15:16, for user 4bf69 from the Workstation DC, a constant and high number of events were generated: An account failed to log on, event code 4625. The 52 logins failed due to incorrect username or password (status 0xC000006D), (sub_status 0xC000006A). The same anomalous behavior repeated once more in the 4-hour period under examination.",
     "urgency": "medium",
     "duration": "5.000000",
     "dvc_name": "SPLUNK01",
     "src_host": "DC",
     "src_port": "2396",
     "src_user": "4bf69",
     "start_time": "2025-05-12 11:15:11",
     "unlocation": "IT ROM",
     "description": "User logon with misspelled or bad password",
     "vendor_product": "9.4.1"
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
    - Write the following into the searchbar: "src_ip" = "10.219.15.14"
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
        - **Add to Triggered Alerts** (Select whatever severity you want to see on splunk, this does not affect the connector. It is added to allow you to see when your alert is triggered)
        - **Send Alert in IDMEFv2 format** (Insert your IDMFEFv2 server endpoint)
17. Save your alert.
18. Your alert is now in effect. If you've followed our examples Splunk will send a new alert to your IDMFEFv2 server every minute until you decide to disable the alert.

# To disable your custom alert
1. From the **Home** page click on the **Search & Reporting** section under **Apps**
2. Click on the **Alerts** tab from the navbar
3. Click on your alert
4. Click on **disable**
