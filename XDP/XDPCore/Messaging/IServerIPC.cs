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
using System.IO;

namespace XDP.XDPCore.Messaging
{
    /// <summary>
    /// Contains functionality specifically for Server IPC
    /// </summary>
    public interface IServerIPC : IIPC
    {
        object CreateServerListener();

        IAsyncResult BeginWaitForClient(AsyncCallback callback, Object state);

        object EndWaitForClient(IAsyncResult asyncResult);

        Stream GetClientStream(object oClient);

        object ClientIdentity { get; }
    }
}
