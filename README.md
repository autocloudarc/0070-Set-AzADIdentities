# 1.0 Azure AD Users, Groups and Roles

The goal of this project is to provision Azure AD users, groups and roles for role based access control at the management group level for a single or multiple subscriptions.

1. Target State Diagram
2. Prerequisites
3. Lab Infrastructure
4. Executing the script

## 1.0 Target State Diagram

![Target state diagram](https://...png)

## 2.0 Prerequisites

Decscription of the prerequistes for the deployment

1. An Azure subscription
2. A web browser
3. An Internet connection
4. PowerShell 7.1.x
5. Membership in the local Administrators group on the machine on which you will execute the PowerShell script.
6. The recommended Azure AD identity passwords will have the following characteristics; At least 12 characters and meet complexity requirements, i.e. 3 out of 4 of upper case, lower case, numeric and special characters.

## 3.0 Lab Infrastructure

The lab infrastructure includes the following components:

## 4.0 Executing the script

Windows PowerShell

1. Clone or download the Set-AzAdIdentities.ps1 to a directory where you want to execute the script from.

2. Open your favorite Windows PowerShell host as an administrative user. You can use Visual Studio Code, Visual Studio, PowerShell ISE, PowerShell console, or other 3rd party host.

3. Right-click and unblock the script so that your PowerShell execution policy if set to RemoteSigned will allow it to run.

4. Open and execute the script. The examples below assumes you are already in the current script directory and will install the devault workloads listed in section 3.0 above.

EXAMPLE 1
```powershell
.\Deploy-AzureResourceGroup.ps1 -Verbose`
````

## 5.0 Verifying the results
## 6.0 Implementing RBAC

## 7.0 Notes
## 8.0 References

## 9.0 Tags

`Tags: Azure AD, Identity and Access Management, Azure, Automation, PowerShell`
