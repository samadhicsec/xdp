using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading;

namespace XDP.MachineService
{
    /// <summary>
    /// The sole purpose of this is to sit in the background and do nothing until it is time for the service to stop.  It does this so the process remains in memory.
    /// </summary>
    internal class BackgroundThread
    {
        private AutoResetEvent terminationWaitHandle = new AutoResetEvent(false);

        public void Wait(object state)
        {
            terminationWaitHandle.WaitOne();
        }

        public void Terminate()
        {
            terminationWaitHandle.Set();
        }
    }
}
