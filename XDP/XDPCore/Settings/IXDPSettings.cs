/*
 * Copyright 2011 David Soldera, Samadhic Security Ltd
 * <http://www.samadhicsecurity.com>
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *     http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

namespace XDP.XDPCore.Settings
{
    public enum CommunicationSecurityLevel
    {
        Kerberos,
        KerberosOrNtlm
    }

    internal interface IXDPSettings
    {
        CommunicationSecurityLevel CommunicationSecurity { get; }

        IXDPCryptoSettings CryptoSettings { get; }
        
        ushort DomainPort { get; }
        
        uint NetworkTimout { get; }
        
        uint ThreadPoolSize { get; }
    }

    internal interface IXDPMachineSettings : IXDPSettings
    {
        string DomainHostname { get; }

        string XDPDSAccount{ get; }
    }

    
}
