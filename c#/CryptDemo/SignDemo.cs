using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Security.Cryptography;

namespace Crypt
{
    class SignDemo
    {
        public static byte[] Sign(string priKey, byte[] text)
        {
            RSACryptoServiceProvider rsa = new RSACryptoServiceProvider();
            rsa.FromXmlString(priKey);

            RSAPKCS1SignatureFormatter fromatter = new RSAPKCS1SignatureFormatter(rsa);

            fromatter.SetHashAlgorithm("SHA256");

            //get hash
            SHA256 mySHA256 = SHA256Managed.Create();
            byte []rgbHash = mySHA256.ComputeHash(text);

            return fromatter.CreateSignature(rgbHash);
        }

        public static bool VerifySign(string pubKey, byte[] text, byte []sign)
        {
            RSACryptoServiceProvider rsa = new RSACryptoServiceProvider();
            rsa.FromXmlString(pubKey);

            RSAPKCS1SignatureDeformatter deformatter = new RSAPKCS1SignatureDeformatter(rsa);
            deformatter.SetHashAlgorithm("SHA256");

            //get hash
            SHA256 mySHA256 = SHA256Managed.Create();
            byte[] rgbHash = mySHA256.ComputeHash(text);

            return deformatter.VerifySignature(rgbHash, sign);
        }
    }
}
