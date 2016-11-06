using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;

namespace XDP.MachineService
{
    [GuidAttribute("4316764D-8F15-4a08-82CB-6D830A6E10CC")]
    public interface IProtectedData
    {
        byte[] Protect(byte[] userData, string[] authorizedUsers);

        byte[] Unprotect(byte[] encryptedData);
    }
}
