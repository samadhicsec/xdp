using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.ComponentModel;
using System.ServiceProcess;
using System.Configuration.Install;

namespace XDP.DomainService
{
    public class XDPDSInstaller : Installer
    {
        private ServiceProcessInstaller processInstaller;
        private ServiceInstaller serviceInstaller;

        public XDPDSInstaller()
        {
            processInstaller = new ServiceProcessInstaller();
            serviceInstaller = new ServiceInstaller();

            processInstaller.Account = ServiceAccount.LocalSystem;
            serviceInstaller.StartType = ServiceStartMode.Automatic;
            serviceInstaller.ServiceName = "XDPDomainService";
            serviceInstaller.Description = "The XDP Domain Service allows XDP encryption between domain users and groups";

            Installers.Add(serviceInstaller);
            Installers.Add(processInstaller);
        } 
    }
}
