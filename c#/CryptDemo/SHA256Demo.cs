using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Security.Cryptography;

namespace Crypt
{
    class SHA256Demo
    {
        public static byte[] Digest(byte[] text)
        {
            SHA256 mySHA256 = SHA256Managed.Create();
            return mySHA256.ComputeHash(text);
        }

        public static String Digest(String text)
        {
            byte []dgBytes = Digest(System.Text.Encoding.Default.GetBytes(text));
            return System.Convert.ToBase64String(dgBytes);
        }
    }
}
