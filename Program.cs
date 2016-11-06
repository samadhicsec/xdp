using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace XDP.DomainService
{
    class Program
    {
        static void Main(string[] args)
        {
            Listener oListener = new Listener();
            oListener.Listen();
        }
    }
}
