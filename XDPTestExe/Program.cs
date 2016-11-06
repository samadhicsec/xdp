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
using System.Text;

namespace XDPTestExe
{
    class Program
    {
        static void Main(string[] args)
        {
            try
            {
                if (args[0] == "-e")
                {
                    //Encrypt
                    Encrypt(args);
                }
                else if (args[0] == "-d")
                {
                    // Decrypt
                    Decrypt(args);
                }
            }
            catch (Exception e)
            {
                Console.WriteLine(e.GetType().ToString() + ": " + e.Message);
                Console.WriteLine("Usage:");
                Console.WriteLine("\tXDPTestExe.exe [-e|-d] <options>");
                Console.WriteLine("\tencrypt options:");
                Console.WriteLine("\t\t-i\tinput file");
                Console.WriteLine("\t\t-o\toutput file");
                Console.WriteLine("\t\t-u\tuser that can decrypt (can specify more than once for multiple users)");
                Console.WriteLine("\tdecrypt options:");
                Console.WriteLine("\t\t-i\tinput file");
                Console.WriteLine("\t\t-o\toutput file");
            }
        }

        static void Encrypt(String[] args)
        {
            Console.WriteLine("Entering Encrypt");

            try
            {
                string InputFilename = null;
                string OutputFilename = null;
                List<string> targetusers = new List<string>();

                int index = 1;
                while (index < args.Length)
                {
                    switch (args[index])
                    {
                        case "-i":  // Input file
                            InputFilename = args[index + 1];
                            break;
                        case "-o":  // Output file
                            OutputFilename = args[index + 1];
                            break;
                        case "-u":  // User that can decrypt
                            targetusers.Add(args[index + 1]);
                            break;
                    }
                    index += 2;
                }

                if (String.IsNullOrEmpty(InputFilename) || String.IsNullOrEmpty(OutputFilename) || (0 == targetusers.Count))
                    throw new Exception("missing input parameter");

                // Read in the input file
                string strToEncrypt = File.ReadAllText(InputFilename);

                byte[] ciphertext = XDP.ProtectedData.Protect(ASCIIEncoding.ASCII.GetBytes(strToEncrypt), targetusers);

                using (FileStream fs = new FileStream(OutputFilename, FileMode.Create, FileAccess.Write, FileShare.ReadWrite))
                {
                    fs.Write(ciphertext, 0, ciphertext.Length);
                }

                Console.WriteLine("Wrote ciphertext to '" + OutputFilename + "'");
            }
            catch (XDP.XDPException xe)
            {
                Console.WriteLine("XDPException: " + xe.Message);
            }
            catch (Exception ex)
            {
                Console.WriteLine("Exception: " + ex.ToString());
            }
            Console.WriteLine("Exiting Encrypt");
        }

        static void Decrypt(String[] args)
        {
            Console.WriteLine("Entering Decrypt");

            string InputFilename = String.Empty;
            string OutputFilename = String.Empty;
            string username = String.Empty;
            string password = String.Empty;

            int index = 1;
            while(index < args.Length)
            {
                switch (args[index])
                {
                    case "-i":  // Input file
                        InputFilename = args[index + 1];
                        break;
                    case "-o":  // Output file
                        OutputFilename = args[index + 1];
                        break;
                    case "-u":  // Username
                        username = args[index+1];
                        break;
                    case "-p":  // Password
                        password = args[index + 1];
                        break;
                }
                index +=2;
            }

            if (String.IsNullOrEmpty(InputFilename) || String.IsNullOrEmpty(OutputFilename))
                throw new Exception("missing input parameter");

            // Read in the input file
            byte[] bytesToDecrypt = File.ReadAllBytes(InputFilename);

            byte[] decryptedtext = XDP.ProtectedData.Unprotect(bytesToDecrypt);
            
            File.WriteAllBytes(OutputFilename, decryptedtext);

            Console.WriteLine("Exiting Decrypt");
        }
    }
}
