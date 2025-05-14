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

> The following steps (4 to 5 and 7 to 12) are optional. The connector works with any Splunk alert that uses the default Splunk event column. We are adding these steps as a guided example.
4. *(optional)* Now enter into the **log** folder inside this path: /opt/splunk/var
5. *(optional)* Create a file named **auth.log** and write the following text into it. This will be the example file Splunk will monitor.
    ```
    Mar 18 12:30:00 server01 sshd[23456]: Failed password for root from 192.168.1.100 port 54321 ssh2
    Mar 18 12:31:00 server01 sshd[23456]: Accepted password for root from 192.168.1.100 port 54321 ssh2
    Mar 18 12:32:00 server01 sshd[23456]: Invalid user guest from 192.168.1.101
    Mar 18 12:33:00 server01 sudo: pam_unix(sudo:auth): authentication failure; logname=root uid=0 euid=0 tty=/dev/pts/0 ruser=root rhost= user=admin
    ```
6. Restart Splunk and access your account.
7. *(optional)* Click **Settings** -> **Data inputs** -> **Files & Directories** -> **New Local File & Directory**
8. *(optional)* Click **browse**, and select the **auth.log** file. In our case it was in the following path: opt/splunk/var/log/auth.log, then click on **Next**.
9. *(optional)* Click on the dropdown menu **Source Type: Select Source Type** and select **linux_secure** as the type, then click on **Next**.
10. *(optional)* **App context** should already be set as **Search & Reporting** and **Host field value** as **costant value**. These values are fine.
11. *(optional)* Click on review then submit.
12. *(optional)* Access the **Settings** tab and click on: **Fields** -> **Field extractions** -> **New Field Extraction**. This is the tab you can use to add your own extraction criterias, here's an example based on our **auth.log** file: 
    - *Name*: Extract Failed password
    - *Apply to*: sourcetype
    - *named*: linux_secure
    - *Extraction/Transform*: Failed password for (?<user>\S+) from (?<ip>\d+\.\d+\.\d+\.\d+) port (?<port>\d+)
    
    Note that this step is optional because the connector will fill in the missing fields with default values.
13. Go back to the **Home** page.
14. Find the **Search & Reporting** section under **Apps** and click on it.
15. Now search something using the bar, here's an example:
    - Write the following into the searchbar: sourcetype="linux_secure" Failed password
    - Set the time to **All time**
    - Start the research
16. *(only if you've followed the optional steps)* Click on the arrow next to the log the search bar returns to expand it and check the following fields
    - ip
    - pid
    - port
    - process
    - user
17. Click on the **Save as** button located above the searchbar on the right, then select **Alert**.
18. From here you can set your alert however you prefer, here's an example (everything that isn't mentioned can be left as is):
    - *Title*: Example_Alert
    - *Permissions*: Shared in Apps
    - *Alert type*: **Scheduled** -> **Run on Cron Schedule**
    - *Time Range*: **All time**
    - *Cron Expression*: */1 * * * * (This means every minute, you can change it to whatever interval you prefer)
    - *Trigger Actions*: Add two actions
        - **Add to Triggered Alerts** (Select whatever severity you want to see on splunk, this does not affect the connector. It is added to allow you to see when your alert is triggered)
        - **Send Alert in IDMEFv2 format** (Insert your IDMFEFv2 server endpoint)
19. Save your alert.
20. Your alert is now in effect. If you've followed our examples Splunk will send a new alert to your IDMFEFv2 server every minute until you decide to disable the alert.

# To disable your custom alert
1. From the **Home** page click on the **Search & Reporting** section under **Apps**
2. Click on the **Alerts** tab from the navbar
3. Click on your alert
4. Click on **disable**