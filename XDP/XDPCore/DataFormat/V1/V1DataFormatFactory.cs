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
using log4net;

namespace XDP.XDPCore.DataFormat.V1
{
    internal class V1DataFormatFactory : XDP.XDPCore.DataFormat.IDataFormatFactory
    {
        private static readonly ILog log = LogManager.GetLogger(typeof(V1DataFormatFactory));
        #region IDataFormatFactory Members

        public IXDPInternalHeader CreateInternalHeader(XDP.XDPCore.Settings.IXDPMachineSettings oSettings)
        {
            log.Debug("Creating XDPInternalHeaderV1 internal header");
            return new XDPInternalHeaderV1(oSettings as XDP.XDPCore.Settings.XDPMachineSettings);
        }

        #endregion
    }
}
