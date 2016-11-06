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

namespace XDP
{
    /// <summary>
    /// A non-specific exception
    /// </summary>
    public class XDPException : Exception
    {
        public XDPException(String message) : base(message) { }
    }

    /// <summary>
    /// Either a method was called with, or a message contained, an invlaid parameter value.
    /// </summary>
    public class XDPBadParameterException : XDPException
    {
        public String Parameter;
        public String Reason;

        public XDPBadParameterException(String Parameter, String Reason)
            : base(String.Empty)
        {
            this.Parameter = Parameter;
            this.Reason = Reason;
        }
    }

    /// <summary>
    /// The internal signature did not verify.  It was likely tampered with.
    /// </summary>
    public class XDPSignatureVerificationException : XDPException
    {
        public XDPSignatureVerificationException(String message) : base(message) { }
    }

    /// <summary>
    /// The user requesting decryption was an AuthorizedIdentity
    /// </summary>
    public class XDPAuthorizationException : XDPException
    {
        public XDPAuthorizationException(String message) : base(message) { }
    }

    /// <summary>
    /// Indicates XDP was unable to resolve an identity
    /// </summary>
    public class XDPInvalidIdentityException : XDPException
    {
        public XDPInvalidIdentityException(String message) : base(message) { }
    }
}
