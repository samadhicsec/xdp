using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Security.Principal;
using System.Runtime.InteropServices;
using XDP.XDPCore;

namespace XDP.MachineService
{
    [GuidAttribute("FFF6048E-337B-4be3-800F-1DCE113838B5")]
    public class ProtectedData : IProtectedData
    {
        /// <summary>
        /// Required for COM interop
        /// </summary>
        public ProtectedData()
        {

        }

        public byte[] Protect(byte[] userData, String[] authorizedUsers)
        {
            byte[] ciphertext = null;

            try
            {
                XDPData oXDPData = new XDPData();
                oXDPData.Encrypt(userData, authorizedUsers);
                ciphertext = oXDPData.Serialize();
            }
            catch (Exception)
            {

            }

            return ciphertext;
        }

        
        public byte[] Unprotect(byte[] encryptedData)
        {
            byte[] decryptedtext = null;

            SecurityIdentifier oPreImpersonationUser = WindowsIdentity.GetCurrent().User;
            
            // Impersonate caller
            NativeWinFunctions.CoImpersonateClient();

            if (WindowsIdentity.GetCurrent().User.Equals(oPreImpersonationUser))
            {
                // Our impersonation failed
                return null;
            }

            try
            {
                // Try to decrypt data
                XDPData oXDPData = new XDPData();
                oXDPData.Deserialize(encryptedData);
                decryptedtext = oXDPData.Decrypt();
            }
            catch (Exception)
            {

            }
            finally
            {
                NativeWinFunctions.CoRevertToSelf();
            }

            return decryptedtext;
        }
    }
}
