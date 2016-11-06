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
using System.Collections.Generic;
using System.IO;
using log4net;

namespace XDP.XDPCore.Messaging
{
    /// <summary>
    /// Handles client requests and responds with exception information when necessary.
    /// </summary>
    class RequestProcessor
    {
        private static readonly ILog log = LogManager.GetLogger(typeof(RequestProcessor));
        protected MessageSender m_oMessageSender;

        private Dictionary<Type, MessageProcessorCallback> m_oMessageCallbacks;

        public RequestProcessor(MessageSender oMessageSender, Dictionary<Type, MessageProcessorCallback> oMessageCallbacks)
        {
            m_oMessageSender = oMessageSender;

            m_oMessageCallbacks = oMessageCallbacks;
        }

        /// <summary>
        /// Process an incoming message to the XDP Domain Service
        /// </summary>
        /// <param name="oRequestStream"></param>
        public void Process(MemoryStream oRequestStream)
        {
            log.Debug("Entering " + System.Reflection.MethodInfo.GetCurrentMethod().Name);
            MessageProcessor oMessageProcessor = new MessageProcessor(m_oMessageCallbacks, m_oMessageSender);

            try
            {
                // MessageProcessor will invoke a delegate from m_oDomainRequests based on the type of incoming message
                oMessageProcessor.Process(oRequestStream.ToArray());
            }
            catch (XDPUnknownMessageException)
            {
                // Send back an XDPUnknownMessage
                m_oMessageSender.SendWithNoResponseExpected(new XDP.XDPCore.Messages.XDPUnknownMessage());
            }
            catch (Exception e)
            {
                log.Error("An unknown error occurred", e);
                // Send back an 
                SendGeneralExceptionException("An unknown error occurred");
            }
            log.Debug("Exiting " + System.Reflection.MethodInfo.GetCurrentMethod().Name);
        }

        /// <summary>
        /// Sends a XDPExceptionResponse.XDPGeneralException to the client
        /// </summary>
        /// <param name="ErrorMessage"></param>
        private void SendGeneralExceptionException(String ErrorMessage)
        {
            log.Debug(ErrorMessage);
            SendException(ErrorMessage, XDP.XDPCore.Messages.XDPExceptionType.XDPGeneralException);
        }

        /// <summary>
        /// Sends an exception of the specified type and information
        /// </summary>
        /// <param name="ExceptionInfo"></param>
        /// <param name="ExceptionType"></param>
        private void SendException(object ExceptionInfo, XDP.XDPCore.Messages.XDPExceptionType ExceptionType)
        {
            XDP.XDPCore.Messages.XDPExceptionResponse oExceptionResponse = new XDP.XDPCore.Messages.XDPExceptionResponse();
            oExceptionResponse.ItemElementName = ExceptionType;
            oExceptionResponse.Item = ExceptionInfo;
            // Send back unauthenticated exception
            m_oMessageSender.SendWithNoResponseExpected(oExceptionResponse);
        }
    }
}
