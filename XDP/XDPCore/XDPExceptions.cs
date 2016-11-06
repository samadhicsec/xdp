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
using System;
using log4net;

namespace XDP.XDPCore
{
    internal class XDPException : Exception
    {
        protected static readonly ILog log = LogManager.GetLogger(typeof(XDPException));
        public XDPException(String message) : base(message) { }
    }

    internal class XDPBadStateException : XDPException
    {
        public XDPBadStateException(String message) : base(message) { log.Debug("XDPBadStateException", this); }
    }

    internal class XDPBadParameterException : XDPException
    {
        public String Parameter;
        public String Reason;

        public XDPBadParameterException(String Parameter, String Reason)
            : base(String.Empty)
        {
            log.Debug("XDPBadParameterException: Parameter: " + Parameter + " Reason: " + Reason);
            this.Parameter = Parameter;
            this.Reason = Reason;
        }
    }

    internal class XDPNullArgumentException : XDPException
    {
        public XDPNullArgumentException(String message) : base(message) { log.Debug("XDPNullArgumentException", this); }
    }

    internal class XDPZeroLengthArrayException : XDPException
    {
        public XDPZeroLengthArrayException(String message) : base(message) { log.Debug("XDPZeroLengthArrayException", this); }
    }

    internal class XDPAuthorizationException : XDPException
    {
        public XDPAuthorizationException(String message) : base(message) { log.Debug("XDPAuthorizationException", this); }
    }

    /// <summary>
    /// Indicates XDP was unable to resolve an identity
    /// </summary>
    internal class XDPInvalidIdentityException : XDPException
    {
        public XDPInvalidIdentityException(String message) : base(message) { log.Debug("XDPInvalidIdentityException", this); }
    }

    internal class XDPSignatureVerificationException : XDPException
    {
        public XDPSignatureVerificationException(String message) : base(message) { log.Debug("XDPSignatureVerificationException", this); }
    }

    internal class XDPCommunicationsException : XDPException
    {
        public XDPCommunicationsException(String message) : base(message) { log.Debug("XDPCommunicationsException", this); }
    }

    /// <summary>
    /// Thrown when settings were updated and encryption process needs to be restarted
    /// </summary>
    internal class XDPUpdatedSettingsException : XDPException
    {
        public XDPUpdatedSettingsException()
            : base("") { }
    }
}
