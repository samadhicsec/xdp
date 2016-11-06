using System;
using System.Collections;
using System.Collections.Generic;
using System.Data;
using System.Diagnostics;
using System.Security.Cryptography;
using System.IO;
using System.Security.AccessControl;
using Microsoft.Win32;
using System.Security.Principal;
using System.DirectoryServices.AccountManagement;

namespace XDPInstallerHelper
{

    public class XDPInstaller
    {
        private const string DOMAIN_HOSTNAME = "Domain Hostname";
        private const string XDP_DS_ACCOUNT = "XDP Domain Service Account";

        private const string UPDATE_CLIENT_CRYPTO = "Update Client Crypto";
        private const string DEFAULT_UPDATE_CLIENT_CRYPTO = "true";
        private const string DATA_RECOVERY_GROUP_NAME = "Data Recovery Group Name";

        /// <summary>
        /// Perform additional actions when installing the XDP Machine Service
        /// </summary>
        /// <param name="hwnd"></param>
        /// <param name="InstallationDir"></param>
        /// <param name="ExistingAccountName"></param>
        /// <param name="ExistingAccountPassword"></param>
        /// <param name="XDPDSHostname"></param>
        /// <param name="XDPDSAccountName"></param>
        /// <returns></returns>
        public string XDPMachineServiceInstall(IntPtr hwnd, string InstallationDir, string ExistingAccountName, string ExistingAccountPassword, string XDPDSHostname, string XDPDSAccountName)
        {
            // Set up the XDPLMAccount username and password
            string XDPLMUsername = ExistingAccountName;
            string XDPLMPassword = ExistingAccountPassword;

            if (String.IsNullOrEmpty(XDPLMUsername))
            {
                XDPLMUsername = "XDPLMAccount";
                // No point in generating a password unless we are generating a new account
                if (String.IsNullOrEmpty(XDPLMPassword))
                {
                    RNGCryptoServiceProvider rand = new RNGCryptoServiceProvider();
                    byte[] GuidBytes = new byte[16];
                    rand.GetBytes(GuidBytes);
                    XDPLMPassword = (new Guid(GuidBytes)).ToString();
                }
            }

            ProgressReporter.DetailPrint(hwnd, "Using Account name: " + XDPLMUsername);
            ProgressReporter.DetailPrint(hwnd, "Using Account password: " + XDPLMPassword);
            
            // See if the XDPLMUsername exists
            ProgressReporter.DetailPrint(hwnd, "Getting the Local Machine account manager");
            PrincipalContext oPrincipalContext = new PrincipalContext(ContextType.Machine);
            try
            {
                Principal oPrincipal = Principal.FindByIdentity(oPrincipalContext, XDPLMUsername);
                if ((null == oPrincipal) || !(oPrincipal is UserPrincipal))
                {
                    if (String.IsNullOrEmpty(XDPLMPassword))
                    {
                        ProgressReporter.DetailPrint(hwnd, "Cannot create an account with a blank password.  Aborting.");
                        return "Error";
                    }
                    ProgressReporter.DetailPrint(hwnd, "Creating account '" + XDPLMUsername + "'");
                    // Create the new local user
                    UserPrincipal up = new UserPrincipal(oPrincipalContext, XDPLMUsername, XDPLMPassword, true);
                    up.Description = "Used for running the XDPMachineService";
                    up.PasswordNeverExpires = true;
                    up.Save();
                    // When we create a user this way they are not a member of any groups so we achieve the principle least privilege
                }
            }
            catch (Exception e)
            {
                ProgressReporter.DetailPrint(hwnd, "Error creating user: " + e.Message);
                return "Error";
            }

            // Grant access to the install directory
            String XDPLMInstallationDir = Path.Combine(Path.GetFullPath(InstallationDir), "XDPMachineService");
            ProgressReporter.DetailPrint(hwnd, "Granting full control to " + XDPLMInstallationDir);
            if (!Directory.Exists(XDPLMInstallationDir))
            {
                ProgressReporter.DetailPrint(hwnd, "Directory " + XDPLMInstallationDir + " does not exist!");
                return "Installation Error";
            }
            DirectorySecurity oDirSec = Directory.GetAccessControl(XDPLMInstallationDir);
            FileSystemAccessRule fsar = new FileSystemAccessRule(XDPLMUsername, FileSystemRights.FullControl, AccessControlType.Allow);
            oDirSec.SetAccessRule(fsar);
            Directory.SetAccessControl(XDPLMInstallationDir, oDirSec);

            // Make sure user can "Logon as a service" privilege and the "Deny logon locally" privilege
            // See http://support.microsoft.com/default.aspx?scid=kb;EN-US;132958
            // Classes to do this were liberated from http://www.tech-archive.net/Archive/DotNet/microsoft.public.dotnet.languages.csharp/2005-03/2508.html
            //ProgressReporter.DetailPrint(hwnd, "Granting logon as a service (and denying all other logon types)");
            ProgressReporter.DetailPrint(hwnd, "Granting logon as a service");
            try
            {
                using (LsaWrapper lsa = new LsaWrapper())
                {
                    // Add SeServiceLogonRight 
                    lsa.AddPrivileges(XDPLMUsername, "SeServiceLogonRight");
                    // Remove all other logon rights
                    //lsa.AddPrivileges(XDPLMUsername, "SeDenyBatchLogonRight");
                    //lsa.AddPrivileges(XDPLMUsername, "SeDenyInteractiveLogonRight");
                    //lsa.AddPrivileges(XDPLMUsername, "SeDenyNetworkLogonRight");
                    //lsa.AddPrivileges(XDPLMUsername, "SeDenyRemoteInteractiveLogonRight");
                }
            }
            catch (Exception e)
            {
                ProgressReporter.DetailPrint(hwnd, "Error granting privilege: " + e.Message);
                return "Error";
            }

            ProgressReporter.DetailPrint(hwnd, "Granting full access to HKLM\\Software\\XDP registry key");
            try
            {
                // Create XDP registry key.  The service will create the key values if they do not exist and assign default values
                RegistryKey key = Registry.LocalMachine.CreateSubKey("Software\\XDP");
                key.SetValue(DOMAIN_HOSTNAME, XDPDSHostname);
                key.SetValue(XDP_DS_ACCOUNT, XDPDSAccountName);

                // Allow the XDPLMAccount read/write on the registry keys
                RegistrySecurity regsec = key.GetAccessControl();
                RegistryAccessRule rar = new RegistryAccessRule(XDPLMUsername, RegistryRights.FullControl, AccessControlType.Allow);
                regsec.SetAccessRule(rar);
                key.SetAccessControl(regsec);
            }
            catch (Exception e)
            {
                ProgressReporter.DetailPrint(hwnd, "Error setting ACL on registry key: " + e.Message);
                return "Error";
            }

            // Create the XDPLocalMachineService
            ProgressReporter.DetailPrint(hwnd, "Creating service");
            try
            {
                // If service already exists, then we should get no error code trying to start it.  The advantage is we can install over the top of an existing installation without
                // needing to know the password of the XDPMachineService account
                Process sc = Process.Start("net", "start XDPMachineService");
                while (!sc.HasExited)
                    System.Threading.Thread.Sleep(100);
                if (sc.ExitCode == 0)
                {
                    ProgressReporter.DetailPrint(hwnd, "Successfully started XDPMachineService");
                }
                else
                {
                    // We couldn't start the service, so assume it does not exist
                    string args = "create XDPMachineService binPath= \"" + Path.Combine(XDPLMInstallationDir, "XDPMachineService.exe") + "\" start= auto DisplayName= \"XDP Machine Service\" obj= .\\" + XDPLMUsername + " password= " + XDPLMPassword;
                    ProgressReporter.DetailPrint(hwnd, "sc " + args);
                    sc = Process.Start("sc", args);
                    while (!sc.HasExited)
                        System.Threading.Thread.Sleep(100);
                    ProgressReporter.DetailPrint(hwnd, "Exit Code " + sc.ExitCode);
                    if (sc.ExitCode != 0)
                    {
                        // Service install failed, tell user to install manually
                        ProgressReporter.DetailPrint(hwnd, "Service installation did not succeed, use above command to install service manually");
                    }
                    else
                    {
                        args = "description XDPMachineService \"The XDP Local Machine Service allows data to be encrypted to other local and domain users\"";
                        ProgressReporter.DetailPrint(hwnd, "sc " + args);
                        sc = Process.Start("sc", args);
                        while (!sc.HasExited)
                            System.Threading.Thread.Sleep(100);
                        ProgressReporter.DetailPrint(hwnd, "Exit Code " + sc.ExitCode);
                    }
                }
            }
            catch (Exception e)
            {
                ProgressReporter.DetailPrint(hwnd, "Error creating XDPMachineService: " + e.Message);
                return "Error";
            }

            try
            {
                // Install XDP.dll in the GAC
                string GAC = GetGACUtilLocation(hwnd);
                if (!String.IsNullOrEmpty(GAC))
                {
                    ProgressReporter.DetailPrint(hwnd, "Installing XDP.dll in Global Assembly Cache");
                    Process.Start(GAC, "/if /silent \"" + Path.Combine(InstallationDir, "XDP.dll") + "\"");
                }
                else
                {
                    ProgressReporter.DetailPrint(hwnd, "Could not install XDP.dll in GAC as gacutil.exe was not found");
                    return "Error";
                }
            }
            catch (Exception e)
            {
                ProgressReporter.DetailPrint(hwnd, "Error installing XDP.dll in GAC: " + e.Message);
                return "Error";
            }

            return "Finished";
        }

        /// <summary>
        /// Perform additional actions when uninstalling the XDP Machine Service
        /// </summary>
        /// <param name="hwnd"></param>
        /// <returns></returns>
        public string XDPMachineServiceUnstall(IntPtr hwnd)
        {
            // Stop and delete the service
            ProgressReporter.DetailPrint(hwnd, "Stopping and deleting XDPMachineService");
            System.Threading.Thread.Sleep(500);
            try
            {
                ProgressReporter.DetailPrint(hwnd, "net stop XDPMachineService");
                Process sc = Process.Start("net", "stop XDPMachineService");
                while (!sc.HasExited)
                    System.Threading.Thread.Sleep(100);
                ProgressReporter.DetailPrint(hwnd, "Exit Code " + sc.ExitCode);
                ProgressReporter.DetailPrint(hwnd, "sc delete XDPMachineService");
                sc = Process.Start("sc", "delete XDPMachineService");
                while (!sc.HasExited)
                    System.Threading.Thread.Sleep(100);
                ProgressReporter.DetailPrint(hwnd, "Exit Code " + sc.ExitCode);
            }
            catch (Exception e)
            {
                ProgressReporter.DetailPrint(hwnd, e.Message);
            }

            // Delete registry keys
            ProgressReporter.DetailPrint(hwnd, "Deleteing registry keys");
            System.Threading.Thread.Sleep(500);
            try
            {
                // Create XDP registry key.  The service will create the key values if they do not exist and assign default values
                RegistryKey key = Registry.LocalMachine.CreateSubKey("Software\\XDP");
                key.DeleteSubKey(DOMAIN_HOSTNAME, false);
                key.DeleteSubKey(XDP_DS_ACCOUNT, false);
            }
            catch (Exception e)
            {
                ProgressReporter.DetailPrint(hwnd, e.Message);
            }

            // Unstall XDP.dll from the GAC
            string GAC = GetGACUtilLocation(hwnd);
            if (!String.IsNullOrEmpty(GAC))
            {
                ProgressReporter.DetailPrint(hwnd, "Unstalling XDP.dll from the Global Assembly Cache");
                Process.Start(GAC, "/uf /silent XDP.dll");
            }

            return "Finished";
        }

        /// <summary>
        /// Perform additional actions when installing the XDP Domain Service
        /// </summary>
        /// <param name="hwnd"></param>
        /// <param name="InstallationDir"></param>
        /// <param name="ExistingAccountName"></param>
        /// <param name="ExistingAccountPassword"></param>
        /// <param name="DataRecoveryGroupName"></param>
        /// <returns></returns>
        public string XDPDomainServiceInstall(IntPtr hwnd, string InstallationDir, string ExistingAccountName, string ExistingAccountPassword, string DataRecoveryGroupName)
        {
            // Set up the XDPDSAccount username and password
            string XDPDSUsername = ExistingAccountName.Contains("\\") ? ExistingAccountName.Substring(ExistingAccountName.IndexOf("\\") + 1, ExistingAccountName.Length - (ExistingAccountName.IndexOf("\\") + 1)) : ExistingAccountName;
            string XDPDSFullUsername = ExistingAccountName.Contains("\\") ? ExistingAccountName : Environment.UserDomainName + "\\" + ExistingAccountName;
            string XDPDSPassword = ExistingAccountPassword;

            if (String.IsNullOrEmpty(ExistingAccountName))
            {
                XDPDSUsername = "XDPDSAccount";
                XDPDSFullUsername = Environment.UserDomainName + "\\" + "XDPDSAccount";
                // No point in generating a password unless we are generating a new account
                if (String.IsNullOrEmpty(XDPDSPassword))
                {
                    RNGCryptoServiceProvider rand = new RNGCryptoServiceProvider();
                    byte[] GuidBytes = new byte[16];
                    rand.GetBytes(GuidBytes);
                    XDPDSPassword = (new Guid(GuidBytes)).ToString();
                }
            }

            ProgressReporter.DetailPrint(hwnd, "Using Account name: " + XDPDSUsername);
            ProgressReporter.DetailPrint(hwnd, "Using Account password: " + XDPDSPassword);

            // See if the XDPDSUsername exists
            ProgressReporter.DetailPrint(hwnd, "Getting the Domain account manager");
            PrincipalContext oPrincipalContext = new PrincipalContext(ContextType.Domain);
            try
            {
                Principal oPrincipal = Principal.FindByIdentity(oPrincipalContext, XDPDSUsername);

                if ((null == oPrincipal) || !(oPrincipal is UserPrincipal))
                {
                    if (String.IsNullOrEmpty(XDPDSPassword))
                    {
                        ProgressReporter.DetailPrint(hwnd, "Cannot create an account with a blank password.  Aborting.");
                        return "Error";
                    }
                    ProgressReporter.DetailPrint(hwnd, "Creating account '" + XDPDSFullUsername + "'");
                    // Create the new local user
                    UserPrincipal up = new UserPrincipal(oPrincipalContext, XDPDSUsername, XDPDSPassword, true);
                    up.Description = "Used for running the XDPDomainService";
                    up.PasswordNeverExpires = true;
                    up.Save();
                    // When we create a user this way they are not a member of any groups so we achieve the principle of least privilege
                }
            }
            catch (Exception e)
            {
                ProgressReporter.DetailPrint(hwnd, "Error creating user: " + e.Message);
                return "Error";
            }

            // Grant access to the install directory
            String XDPDSInstallationDir = Path.Combine(Path.GetFullPath(InstallationDir), "XDPDomainService");
            ProgressReporter.DetailPrint(hwnd, "Granting full control to " + XDPDSInstallationDir);
            if (!Directory.Exists(XDPDSInstallationDir))
            {
                ProgressReporter.DetailPrint(hwnd, "Directory " + XDPDSInstallationDir + " does not exist!");
                return "Installation Error";
            }
            DirectorySecurity oDirSec = Directory.GetAccessControl(XDPDSInstallationDir);
            FileSystemAccessRule fsar = new FileSystemAccessRule(XDPDSUsername, FileSystemRights.FullControl, AccessControlType.Allow);
            oDirSec.SetAccessRule(fsar);
            Directory.SetAccessControl(XDPDSInstallationDir, oDirSec);

            // Make sure user can "Logon as a service" privilege and the "Deny logon locally" privilege
            // See http://support.microsoft.com/default.aspx?scid=kb;EN-US;132958
            // Classes to do this were liberated from http://www.tech-archive.net/Archive/DotNet/microsoft.public.dotnet.languages.csharp/2005-03/2508.html
            //ProgressReporter.DetailPrint(hwnd, "Granting logon as a service (and denying all other logon types)");
            ProgressReporter.DetailPrint(hwnd, "Granting logon as a service");
            try
            {
                using (LsaWrapper lsa = new LsaWrapper())
                {
                    // Add SeServiceLogonRight 
                    lsa.AddPrivileges(XDPDSUsername, "SeServiceLogonRight");
                }
            }
            catch (Exception e)
            {
                ProgressReporter.DetailPrint(hwnd, "Error granting privilege: " + e.Message);
                return "Error";
            }

            ProgressReporter.DetailPrint(hwnd, "Granting full access to HKLM\\Software\\XDP registry key");
            try
            {
                // Create XDP registry key.  The service will create the key values if they do not exist and assign default values
                RegistryKey key = Registry.LocalMachine.CreateSubKey("Software\\XDP");
                key.SetValue(UPDATE_CLIENT_CRYPTO, DEFAULT_UPDATE_CLIENT_CRYPTO);
                key.SetValue(XDP_DS_ACCOUNT, DataRecoveryGroupName);

                // Allow the XDPLMAccount read/write on the registry keys
                RegistrySecurity regsec = key.GetAccessControl();
                RegistryAccessRule rar = new RegistryAccessRule(XDPDSUsername, RegistryRights.FullControl, AccessControlType.Allow);
                regsec.SetAccessRule(rar);
                key.SetAccessControl(regsec);
            }
            catch (Exception e)
            {
                ProgressReporter.DetailPrint(hwnd, "Error setting ACL on registry key: " + e.Message);
                return "Error";
            }

            // Create the XDPLocalMachineService
            ProgressReporter.DetailPrint(hwnd, "Creating service");
            try
            {
                // If service already exists, then we should get no error code trying to start it.  The advantage is we can install over the top of an existing installation without
                // needing to know the password of the XDPMachineService account
                Process sc = Process.Start("net", "start XDPDomainService");
                while (!sc.HasExited)
                    System.Threading.Thread.Sleep(100);
                if (sc.ExitCode == 0)
                {
                    ProgressReporter.DetailPrint(hwnd, "Successfully started XDPDomainService");
                }
                else
                {
                    string args = "create XDPDomainService binPath= \"" + Path.Combine(XDPDSInstallationDir, "XDPDomainService.exe") + "\" start= auto DisplayName= \"XDP Domain Service\" obj= " + XDPDSFullUsername + " password= " + XDPDSPassword;
                    ProgressReporter.DetailPrint(hwnd, "sc " + args);
                    sc = Process.Start("sc", args);
                    while (!sc.HasExited)
                        System.Threading.Thread.Sleep(100);
                    ProgressReporter.DetailPrint(hwnd, "Exit Code " + sc.ExitCode);
                    if (sc.ExitCode != 0)
                    {
                        // Service install failed, tell user to install manually
                        ProgressReporter.DetailPrint(hwnd, "Service installation did not succeed, use above command to install service manually");
                    }
                    else
                    {
                        args = "description XDPDomainService \"The XDP Domain Machine Service allows data to be encrypted to domain users\"";
                        ProgressReporter.DetailPrint(hwnd, "sc " + args);
                        sc = Process.Start("sc", args);
                        while (!sc.HasExited)
                            System.Threading.Thread.Sleep(100);
                        ProgressReporter.DetailPrint(hwnd, "Exit Code " + sc.ExitCode);
                    }
                }
            }
            catch (Exception e)
            {
                ProgressReporter.DetailPrint(hwnd, "Error creating XDPDomainService: " + e.Message);
                return "Error";
            }

            return "Finished";
        }

        /// <summary>
        /// Performa additional actions when uninstalling the XDP Domain Service
        /// </summary>
        /// <param name="hwnd"></param>
        /// <returns></returns>
        public string XDPDomainMachineUninstall(IntPtr hwnd)
        {
            // Stop and delete the service
            ProgressReporter.DetailPrint(hwnd, "Stopping and deleting XDPDomainService");
            System.Threading.Thread.Sleep(500);
            try
            {
                ProgressReporter.DetailPrint(hwnd, "net stop XDPDomainService");
                Process sc = Process.Start("net", "stop XDPDomainService");
                while (!sc.HasExited)
                    System.Threading.Thread.Sleep(100);
                ProgressReporter.DetailPrint(hwnd, "Exit Code " + sc.ExitCode);
                ProgressReporter.DetailPrint(hwnd, "sc delete XDPDomainService");
                sc = Process.Start("sc", "delete XDPDomainService");
                while (!sc.HasExited)
                    System.Threading.Thread.Sleep(100);
                ProgressReporter.DetailPrint(hwnd, "Exit Code " + sc.ExitCode);
            }
            catch (Exception e)
            {
                ProgressReporter.DetailPrint(hwnd, e.Message);
            }

            // Delete registry keys
            ProgressReporter.DetailPrint(hwnd, "Deleting registry keys");
            System.Threading.Thread.Sleep(500);
            try
            {
                // Get handle XDP registry key.
                RegistryKey key = Registry.LocalMachine.CreateSubKey("Software\\XDP");
                key.DeleteSubKey(UPDATE_CLIENT_CRYPTO, false);
                key.DeleteSubKey(XDP_DS_ACCOUNT, false);
            }
            catch (Exception e)
            {
                ProgressReporter.DetailPrint(hwnd, e.Message);
            }

            return "Finished";
        }



        private string GetGACUtilLocation(IntPtr hwnd)
        {
            // We can always try the current directory
            string GACLoc = Path.Combine(Environment.CurrentDirectory, "gacutil.exe");
            if (!String.IsNullOrEmpty(System.Reflection.Assembly.GetExecutingAssembly().Location))
            {
                // It's better to look in the same directory as th executing assembly, but this doesn't always work?
                GACLoc = Path.Combine(Path.GetDirectoryName(System.Reflection.Assembly.GetExecutingAssembly().Location), "gacutil.exe");
                GACLoc = Environment.ExpandEnvironmentVariables(GACLoc);
            }

            ProgressReporter.DetailPrint(hwnd, "Looking for gacutil.exe at '" + GACLoc + "'");
            if (File.Exists(GACLoc))
                return GACLoc;

            //string GACLoc = @"%WINDIR%\Microsoft.NET\Framework\v1.1.4322\GacUtil.exe";
            //GACLoc = Environment.ExpandEnvironmentVariables(GACLoc);
            //ProgressReporter.DetailPrint(hwnd, "Looking for gacutil.exe at '" + GACLoc + "'");
            //if (File.Exists(GACLoc))
            //    return GACLoc;

            return null;
        }
    }

}
