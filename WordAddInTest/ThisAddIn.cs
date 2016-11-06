using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Xml.Linq;
using Word = Microsoft.Office.Interop.Word;
using Office = Microsoft.Office.Core;
using Microsoft.Office.Tools.Word;

namespace WordAddInTest
{

    public partial class ThisAddIn
    {
        [System.Runtime.InteropServices.DllImport("kernel32.dll", CharSet = System.Runtime.InteropServices.CharSet.Auto)]
        private static extern IntPtr GetCommandLine();

        private bool called = false;

        private void ThisAddIn_Startup(object sender, System.EventArgs e)
        {
            this.Application.DocumentBeforeSave +=
                new Word.ApplicationEvents4_DocumentBeforeSaveEventHandler(Application_DocumentBeforeSave);

            this.Application.DocumentChange +=
                new Word.ApplicationEvents4_DocumentChangeEventHandler(Application_DocumentChange);

            //Word.ApplicationEvents4_DocumentOpenEventHandler cur = this.Application.DocumentOpen;
            this.Application.DocumentOpen += new Word.ApplicationEvents4_DocumentOpenEventHandler(Application_DocumentOpen);


            this.Application.DocumentBeforeClose +=
                new Word.ApplicationEvents4_DocumentBeforeCloseEventHandler(Application_DocumentBeforeClose);

            //System.Windows.Forms.MessageBox.Show("ThisAddIn_Startup");
        }

        private void ThisAddIn_Shutdown(object sender, System.EventArgs e)
        {
        }

        void Application_DocumentBeforeSave(Word.Document Doc, ref bool SaveAsUI, ref bool Cancel)
        {
            //Doc.Paragraphs[1].Range.InsertParagraphBefore();
            //Doc.Paragraphs[1].Range.Text = "This text was added by using code.";
        }

        void Application_DocumentChange()
        {
            if ((!called))
            {
                IntPtr ptr = GetCommandLine();
                string commandLine = System.Runtime.InteropServices.Marshal.PtrToStringAuto(ptr);
                this.
                //System.Windows.Forms.MessageBox.Show("Application.Documents.Count " + this.Application.Documents.Count);
                System.Windows.Forms.MessageBox.Show(commandLine);
                called = true;
            }
        }

        void Application_DocumentOpen(Word.Document Doc)
        {
            //System.Windows.Forms.MessageBox.Show("Application_DocumentOpen called");
            //if(Doc.HasPassword)
            //    Doc.Password = "test";
            // See if this is an XDP encrypted doc

            // Get embedded file and save to disk

            // Read in encrypted file

            // Decrypt bytes

            // Write to disk

            // Close current document

            // Open decrypted document
        }

        void Application_DocumentBeforeClose(Word.Document Doc, ref bool Cancel)
        {
            // Check settings to see if user wants to encrypt document

            // Verify list of AuthorisedIdentities

            // Save document to disk

            // Read in document bytes

            // Encrypt document bytes

            // Write encrypted document to disk

            // Create new document

            // Embed encrypted document in new document

            // Save new document to disk
            
        }

        #region VSTO generated code

        /// <summary>
        /// Required method for Designer support - do not modify
        /// the contents of this method with the code editor.
        /// </summary>
        private void InternalStartup()
        {
            this.Startup += new System.EventHandler(ThisAddIn_Startup);
            this.Shutdown += new System.EventHandler(ThisAddIn_Shutdown);
        }
        
        #endregion
    }
}
