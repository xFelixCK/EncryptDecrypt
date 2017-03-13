using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Security.Cryptography;

namespace Crypt
{
    class RSADemo
    {
        public static byte[] Encrypt(string pubKey, byte[] text)
        {
            RSACryptoServiceProvider rsa = new RSACryptoServiceProvider();
            rsa.FromXmlString(pubKey);
            

            return rsa.Encrypt(text, false);  
        }

        public static byte[] Decrypt(string priKey, byte[] cipherText)
        {
            RSACryptoServiceProvider rsa = new RSACryptoServiceProvider();
            rsa.FromXmlString(priKey);

            return rsa.Decrypt(cipherText, false);
        }
    }
}
