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
using System.Collections;
using System.Diagnostics;

namespace XDP.XDPCore
{

    internal static class XDPLogging
    {
        public static bool LogToFile = false;
        private static Stack MethodStartTimes = new Stack();
        private static System.Diagnostics.EventLog m_oEventLog;

        static XDPLogging()
        {
            m_oEventLog = null;
            try
            {
                if (System.Diagnostics.EventLog.SourceExists(System.Reflection.Assembly.GetEntryAssembly().FullName))
                    m_oEventLog = new EventLog("Application");
            }
            catch { }
        }

        internal static void Output(string message)
        {
            string td = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss.FF");
            String output = td + " : " + message;
            if (XDPLogging.LogToFile)
            {
                object lockobj = "";
                lock (lockobj)
                {
                    string path = System.IO.Path.Combine(System.IO.Path.GetDirectoryName(System.Reflection.Assembly.GetEntryAssembly().Location), "XDPLog.txt");
                    System.IO.File.AppendAllText(path, output + Environment.NewLine);
                }
            }
            Console.WriteLine(output);
        }

        [Conditional("DEBUG")]
        internal static void Entry()
        {
            MethodStartTimes.Push(DateTime.Now);
            Output("Entering " + (new StackFrame(1)).GetMethod().Name);
        }

        [Conditional("DEBUG")]
        internal static void Exit()
        {
            String time = String.Empty;
            if(MethodStartTimes.Count > 0)
                time = DateTime.Now.Subtract((DateTime)MethodStartTimes.Pop()).ToString();
            Output("Exiting " + (new StackFrame(1)).GetMethod().Name + " (" + time + ")");
        }

        [Conditional("DEBUG")]
        internal static void Log(string message)
        {
            Output(message);
        }

        internal static void EventLog(string message, EventLogEntryType eType)
        {
            if (null != m_oEventLog)
            {
                m_oEventLog.WriteEntry(message, eType);
            }
            else
                Output(message);
        }
    }
}
