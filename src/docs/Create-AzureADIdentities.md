---
title: 03. Role-Based Access Control
description: POC 03 - Activate Azure with Administration and Governance
ms.author: Microsoft Enterprise Services
ms.date: Oct/08/2020
ms.file: POC03-Role-Based-Access-Control.md
---

| Update: Oct/21/2020 | Duration 30 minutes |

---

<br>

# 3. Role-Based Access Control

---

## 3.1 Objectives

In this section we will be creating Azure Administrative users and groups in the Azure AD tenant as well as configuring Role Based Access Control to manage Azure resources.
It is highly recommended to consider using a seperate admin account from day to day activities for each person that requires high privilige access to Azure environment.

> <div class="alert is-warning">
>
> **IMPORTANT:**
>
> You have the option to either use your existing production tenant as a consolidated directory for both production and non-production purposes, or create a separate tenant for non-production scenarios such as those outlined in this PoC guide.
> <br>
> </div>

<br>

---

## 3.2 Prerequisites

To perform this proof of concept it is necessary to have the following prerequisites:

1. Internet connectivity.

2. A valid customer's Azure Subscription

3. Access to the Azure Portal [https://portal.azure.com](https://portal.azure.com/) and permissions to perform the PoC exercises (Azure subscription owner resources role).

4. Azure Active Directory Global Administrator directory role on the tenant.

<br>

---

## 3.3 Deployment Steps

We will create several Azure AD users and Security Groups, add users to these groups using a PowerShell script, then finally assign roles to the various groups. These roles will be used throughout the remainder of the PoC exercises.

> <div class="alert is-info">
> **NOTE:**
>
> For this exercise, as a convenient reference, use the provided fictitious POC names in the tables below, such as 1. Jay Adams or 2. Maria Perez.
> For a more realistic experience, we suggest that you replace the place-holder customer names with your own. So if, as a customer, your name is Cathy Charlie, under the customerFirstName column, replace cfn01 (cfn stands for customer first name)
> with Cathy and under the customerLastName column, likewise replace cln01 (cln is an abbreviation for customer last name) with Charlie. Continue replacing the place-holder names for the customerDisplayName and customerUserName columns based
> on the image below. We believe that using your actual names may better reflect your own administrative delegation model and provide a more relevant and meaningful scenario for you. The PowerShell script will automatically detect your
> tenants' (Azure AD directory) suffix, so there is no need to manually specify that suffix in this spreadsheet.
>
> Note also that the custom role located at C:\PoCPackage\RBAC\customrole.json will also be automatically provisioned, with the actual subscription id of your subscription used for this custom role definition.
> If you extracted the PoCPackage archive to C:\PoCPackage, the spreadsheet will be available at C:\PocPackage\RBAC\users-and-groups.csv
>
>
> </div>

<br>

### Consolidated Users, Groups and Roles: (Change usernames to customers' IT team)

![_Figure: Consolidated RBAC Spreadsheet_](./media/POC03-Role-Based-Access-Control/3.3-img14-rbacSpreadsheet.png "Consolidated RBAC Spreadsheet"){ width=100% }

If using a new Azure AD tenant, you may need to create new user accounts and groups. Identities can be created directly in Azure AD or synched from on-premises AD, however, to reduce Proof of Concept execution time we provide this guidance to create the users and groups in Azure AD using PowerShell.

Skip this section if you already have a working tenant attached to the Dev/Test subscription with admin users and groups.

<br>

**To create the Azure AD users and Groups, follow these steps:**

1. Sign in to the Azure portal at [https://portal.azure.com](https://portal.azure.com/) using the Azure AD tenant’s Global Administrator account and Subscription Owner privileges. This is required so that later you can verify the new accounts, groups and roles assignments.
2. Open a PowerShell session (VSCode, ISE or the PowerShell console) as an administrator.
3. Run the following command to install AzureAD module in your machine:

   Install-Module AzureAd -Verbose -AllowClobber

4. Navigate to PowerShell script inside your PoCPackage folder, so if it was extracted to C:\PoCPackage, you would browse to C:\PoCPackage\RBAC\Provision-UsersAndGroups.ps1 and open the script in your PowerShell session.
5. In your PowerShell console, run the following command to set the path location for the script, so if the script is located at C:\PoCPackage\RBAC then you would run this command:

    Set-Location -Path C:\PoCPackage\RBAC

6. Next, execute the script with either of the available AzureEnvironment options, which can be 'AzureCloud' for the commercial Azure cloud or 'AzureUSGovernment' for the US Gov cloud.

.\Provision-UsersAndGroups.ps1 -AzureEnvironment AzureCloud -Verbose
<br>
[or]
<br>
.\Provision-UsersAndGroups.ps1 -AzureEnvironment AzureUSGovernment -Verbose

1. A browser based prompt to authenticate to Azure will appear in a new window. Use Azure AD Global Administrator account to sign in.

![_Figure: Prompt to Authenticate to Azure_](./media/POC03-Role-Based-Access-Control/3.3-img15-PromptToAuthenticateToAzure.png "Prompt to Authenticate to Azure"){ width=100% }

7. Next you will be prompted to enter your subscription name from the list of subscriptions associated with your Azure credentials.

![_Figure: Enter Subscription Name_](./media/POC03-Role-Based-Access-Control/3.3-img16-EnterSubscriptionName.png "Enter Subscription Name"){ width=100% }

8. For the next prompt before the script provisions the accounts, groups and assigns roles, you will be asked to enter a password. Although it uses the username adm.infra.user, this is just a placeholder name.

![_Figure: Enter Password_](./media/POC03-Role-Based-Access-Control/3.3-img17-EnterPassword.png "Enter Password"){ width=100% }

9. Since you will be provisioning users and groups, you must also authenticate to your tenant and as a result, a web based prompt will now appear for you to log in using the same Azure credentials as used before for the subscription.

![_Figure: Enter Tenant Credentials_](./media/POC03-Role-Based-Access-Control/3.3-img18-AuthenticateToTenant.png "Enter Tenant Credentials"){ width=100% }

10. The RBAC based roles will then be assigned and the output will appear in the console as each user, group and assignments are provisioned.
<br>
    When the script completes, you will be prompted to open the transcript. Note also that you must still manually add the **Contoso AD Operator** and **Contoso AD Administrator** to the **User Administrator** and **Global Administrator** roles from the Azure portal.

![_Figure: Open Transcript_](./media/POC03-Role-Based-Access-Control/3.3-img19-PromptToOpenTranscript.png "Open Transcript"){ width=100% }

11. Finally, you will be prompted to remove the previously provisioned users and groups. CAUTION! During the PoC delivery, you should normally select **NO** or **N** to use these identities in the PoC exercises.

12. You should only select 'YES' or 'Y' if you are practicing or testing setting up the identities and you wish to re-run the script again for the same subscription and tenant.

![_Figure: Cleanup Azure AD_](./media/POC03-Role-Based-Access-Control/3.3-img20-PromptToCleanupAzureAD.png "Cleanup Azure AD"){ width=100% }

8. From Azure Portal navigate to **Management Groups** and **Subscriptions** to review the Access Control (IAM) blade and verify that the appropriate roles were added to the list.
<br>

![_Figure: Azure AD Users and Groups_](./media/POC03-Role-Based-Access-Control/3.3-img11.png "Azure AD Users and Groups"){ width=100% }

   **Custom Role:**

![_Figure: Azure AD Users and Groups_](./media/POC03-Role-Based-Access-Control/3.3-img12.png "Azure AD Users and Groups"){ width=100% }

![_Figure: Azure AD Users and Groups_](./media/POC03-Role-Based-Access-Control/3.3-img13.png "Azure AD Users and Groups"){ width=100% }

**End of Exercise**

<br>

```