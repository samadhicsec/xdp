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
using XDP.XDPCore.Messaging;

namespace XDP.XDPCore.Messages
{
    internal class XDPExceptionHelper
    {
        private static readonly ILog log = LogManager.GetLogger(typeof(XDPExceptionHelper));

        MessageSender m_oMessageSender;

        internal XDPExceptionHelper(MessageSender oMessageSender)
        {
            m_oMessageSender = oMessageSender;
        }

        /// <summary>
        /// Sends a XDPExceptionResponse.XDPBadParameter to the client
        /// </summary>
        /// <param name="ErrorMessage"></param>
        internal void SendBadParameterException(String Parameter, String Reason)
        {
            log.Debug("BadParameter (" + Parameter + "): " + Reason);
            XDPExceptionXDPBadParameter oBPE = new XDPExceptionXDPBadParameter();
            oBPE.Parameter = Parameter;
            oBPE.Reason = Reason;
            SendException(oBPE, XDPExceptionType.XDPBadParameter);
        }

        /// <summary>
        /// Sends a XDPExceptionResponse.XDPNotAutorized to the client
        /// </summary>
        /// <param name="ErrorMessage"></param>
        internal void SendNotAutorizedException(String ErrorMessage)
        {
            log.Debug(ErrorMessage);
            SendException(ErrorMessage, XDPExceptionType.XDPNotAuthorized);
        }

        /// <summary>
        /// Sends a XDPExceptionResponse.XDPBadSignature to the client
        /// </summary>
        /// <param name="ErrorMessage"></param>
        internal void SendBadSignatureException(String ErrorMessage)
        {
            log.Debug(ErrorMessage);
            SendException(ErrorMessage, XDPExceptionType.XDPBadSignature);
        }

        /// <summary>
        /// Sends a XDPExceptionResponse.XDPUnknownIdentity to the client
        /// </summary>
        /// <param name="ErrorMessage"></param>
        internal void SendUnknownIdentityException(String ErrorMessage)
        {
            log.Debug(ErrorMessage);
            SendException(ErrorMessage, XDPExceptionType.XDPUnknownIdentity);
        }

        /// <summary>
        /// Sends a XDPExceptionResponse.XDPGeneralException to the client
        /// </summary>
        /// <param name="ErrorMessage"></param>
        internal void SendGeneralExceptionException(String ErrorMessage)
        {
            log.Debug(ErrorMessage);
            SendException(ErrorMessage, XDPExceptionType.XDPGeneralException);
        }

        /// <summary>
        /// Sends an exception of the specified type and information
        /// </summary>
        /// <param name="ExceptionInfo"></param>
        /// <param name="ExceptionType"></param>
        internal void SendException(object ExceptionInfo, XDPExceptionType ExceptionType)
        {
            XDPExceptionResponse oExceptionResponse = new XDPExceptionResponse();
            oExceptionResponse.ItemElementName = ExceptionType;
            oExceptionResponse.Item = ExceptionInfo;
            // Send back unauthenticated exception
            m_oMessageSender.SendWithNoResponseExpected(oExceptionResponse);
        }
    }
}
