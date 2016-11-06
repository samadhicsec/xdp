using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.IO;
using System.Threading;
using System.Net;
using System.Net.Sockets;
using System.Net.Security;
using System.Security.Principal;
using System.Security.Authentication;
using XDP.XDPCore;

namespace XDP.DomainService
{
    class Listener
    {
        private bool bStopListening = false; 
        private AutoResetEvent connectionWaitHandle = new AutoResetEvent(false); 

        public Listener()
        {
            int workerthreads = 0;
            int iocompthreads = 0;
            //ThreadPool.GetMaxThreads(out workerthreads, out compthreads);
            //Console.WriteLine("ThreadPool.GetMaxThreads:" + workerthreads + " (worker), " + compthreads + "(completion)");
            ThreadPool.GetMinThreads(out workerthreads, out iocompthreads);
            //Console.WriteLine("ThreadPool.GetMinThreads:" + workerthreads + " (worker), " + compthreads + "(completion)");
            //ThreadPool.GetAvailableThreads(out workerthreads, out compthreads);
            //Console.WriteLine("ThreadPool.GetAvailableThreads:" + workerthreads + " (worker), " + compthreads + "(completion)");

            // Probably should do more research into what are appropriate values here.  By defaul the minimum thread pool is equal to the number of processors. 
            // It seems to make sense to increase this as we want to easily support many requests, however not a truly high volume.
            //if ((int)XDPDomainSettings.ThreadPoolSize > iocompthreads)
            //    iocompthreads = (int)XDPDomainSettings.ThreadPoolSize;
            
            // Set the minimum number of threads for the Thread Pool
            ThreadPool.SetMinThreads(workerthreads, iocompthreads);
        }

        /// <summary>
        /// Listen for incoming requests and handle a new request on a seperate thread
        /// </summary>
        public void Listen(object state)
        {
            XDPLogging.Entry();

            TcpListener listener = new TcpListener(IPAddress.Any, XDPDomainSettings.Settings.DomainPort);
            listener.Start();

            while (true)
            {
                IAsyncResult result = listener.BeginAcceptTcpClient(HandleAsyncConnection, listener);
                connectionWaitHandle.WaitOne(); //Wait until a client has begun handling an event 

                // Check if we are supposed to stop listening
                if (bStopListening)
                    break;
            }

            XDPLogging.Exit();
        }

        public void StopListening()
        {
            bStopListening = true;
            connectionWaitHandle.Set();
        }

        /// <summary>
        /// Handle the newincoming connection
        /// </summary>
        /// <param name="result"></param>
        private void HandleAsyncConnection(IAsyncResult result)
        {
            XDPLogging.Entry();

            TcpClient client = null;
            try
            {
                TcpListener listener = (TcpListener)result.AsyncState;
                client = listener.EndAcceptTcpClient(result);
                connectionWaitHandle.Set(); //Inform the main thread this connection is now handled 

                // Allocate space to read message
                MemoryStream MessageStream = new MemoryStream();
                byte[] ReadBuffer = new byte[4096];

                AutoResetEvent oWait = new AutoResetEvent(false);
                NetworkStream AvailableBytes = client.GetStream();
                NegotiateStream oKerb = new NegotiateStream(AvailableBytes, false);

                try
                {
                    oKerb.AuthenticateAsServer(CredentialCache.DefaultNetworkCredentials, ProtectionLevel.EncryptAndSign, TokenImpersonationLevel.Identification);
                }
                catch (InvalidCredentialException ice)
                {
                    XDPLogging.EventLog("Authentication failed for an incoming connection" + Environment.NewLine + ice.Message, System.Diagnostics.EventLogEntryType.Warning);
                    throw;
                }
                catch (AuthenticationException ae)
                {
                    XDPLogging.EventLog("Authentication failed for an incoming connection" + Environment.NewLine + ae.Message, System.Diagnostics.EventLogEntryType.Warning);
                    throw;
                }
                catch (Exception e)
                {
                    XDPLogging.EventLog("An incoming connection could not be established securely" + Environment.NewLine + e.Message, System.Diagnostics.EventLogEntryType.Warning);
                    throw;
                }
                // TODO Research if there is any such thing as a cipher downgrade attack against Kerberos
                // There is no point checking for mutual auth on a server as server always authn's the client and that is all we care about on the server,
                // and it's pointless for server to verify that client has checked who it is, because if the client connects to a rogue server then our 
                // server code is not even running
                XDPLogging.Log("The client " + oKerb.RemoteIdentity.Name + " connected");

                // BeginRead will wait until there is data to be read or an error occurs
                oKerb.BeginRead(ReadBuffer, 0, ReadBuffer.Length,
                    delegate(IAsyncResult target)
                    {
                        try
                        {
                            int bytesRead = oKerb.EndRead(target);
                            MessageStream.Write(ReadBuffer, 0, bytesRead);

                            while (client.Connected && (client.Available > 0))
                            {
                                bytesRead = oKerb.Read(ReadBuffer, 0, ReadBuffer.Length);
                                MessageStream.Write(ReadBuffer, 0, bytesRead);
                            }
                        }
                        catch (Exception se)
                        {
                            // If there is an exception then when we process the received bytes (if any), RequestProcessor will attempt to send back an 
                            // XDPUnknownMessage, if the connection is still open
                            XDPLogging.Log("Error reading from client connection" + Environment.NewLine + se.Message);
                            client.Close();
                        }
                        oWait.Set();
                    }, null);

                // TODO Should the timeout for reading client data really be the Network Timeout value?
                // Wait for the asynchronous read callback to finish reading or for a timeout to occur
                if (!oWait.WaitOne((int)XDPDomainSettings.Settings.NetworkTimout))
                {
                    client.Close();
                    XDPLogging.Log("Network timeout");
                    return;
                }

                XDPLogging.Log("Received a total of " + MessageStream.Length + " bytes");

                // Process the received request
                //DomainRequestProcessor oRequestProcessor = new DomainRequestProcessor(client, oKerb);
                //oRequestProcessor.Process(MessageStream);

                client.Close();
            }
            catch (Exception ex)
            {
                // This is the exception handler of last resort.  If we had a meaningful exception we would have written it to the Event Log already, so just log this
                // exception to what ever log might be in operation
                XDPLogging.Log(ex.ToString());
                // Try to close the client to free up any unmanaged resources
                try
                {
                    if (null != client)
                        client.Close();
                }
                catch { }
            }
            finally
            {
                XDPLogging.Exit();
            }
        } 

    }
}
