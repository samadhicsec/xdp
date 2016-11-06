using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace XDPInstallerHelper
{
    class ProgressReporter
    {
        //Here's the key function that writes to the Details list.
        public static void DetailPrint(IntPtr hwnd, string entry)
        {
            try
            {
                int lParam = 0;
                //Get current list count
                int c = Win32Functions.SendMessage(hwnd, Win32Functions.LVM_GETITEMCOUNT, 0, ref lParam) + 1;
                //Setup a LVITEM structure for the Insert message
                Win32Functions.LVITEM lv = new Win32Functions.LVITEM();
                lv.iItem = c;
                lv.pszText = entry;
                lv.mask = Win32Functions.LVIF_TEXT;
                lv.stateMask = Win32Functions.LVIS_FOCUSED;
                lv.state = Win32Functions.LVIS_FOCUSED;
                //Insert the LVITEM into the list
                c = Win32Functions.SendMessageLV(hwnd, Win32Functions.LVM_INSERTITEM, 0, ref lv);
                //Scroll the list so the item is visible
                lParam = 12;
                Win32Functions.SendMessage(hwnd, Win32Functions.LVM_SCROLL, 0, ref lParam);
            }
            catch (Exception)
            {
                //Do Nothing, no sense throwing an error just for logging.
            }
        }
    }
}
