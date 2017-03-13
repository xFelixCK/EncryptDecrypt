using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using Crypt;
using System.Security.Cryptography;

namespace CryptDemo
{
    class Program
    {
        static void Main(string[] args)
        {
            TestAes256();
            TestSHA256();
            TestPBKDF2();
            TestRSA();
            TestSign();
        }
        
        public static void TestAes256()
        {
		    Console.WriteLine("Test aes 256");
            string key = "78B31088F0E44A86B749429D9F774AA0";
            string plain = "www.ctrip.com1234";
            string cipher = AES256Demo.Encrypt(key, plain);
		    Console.WriteLine("明文: " + plain);
		    Console.WriteLine("加密后: " + cipher);
            string plain1 = AES256Demo.Decrypt(key, cipher);
		    Console.WriteLine("解密后: " + plain1);
	    }

        public static void TestSHA256()
        {
		    Console.WriteLine("\nTest sha 256");
		    String text = "Test sha 256 abcdefghijklmnopqrstuvwxyz";
            String digest = SHA256Demo.Digest(text);
		    Console.WriteLine("明文: " + text);
		    Console.WriteLine("摘要值: " + digest);
	    }

        public static void TestRSA()
        {   
		    Console.WriteLine("\nTest rsa 2048");
		    string text =  "Test RSA, 1234abcd";

            RSACryptoServiceProvider rsa = new RSACryptoServiceProvider(2048);
            string pubKey = rsa.ToXmlString(false);
            string priKey = rsa.ToXmlString(true);

		    Console.WriteLine("明文: " + text);
            byte[] cip = RSADemo.Encrypt(pubKey, System.Text.Encoding.Default.GetBytes(text));
            string str = Convert.ToBase64String(cip);
		    Console.WriteLine("加密后:	" + str);
            Console.WriteLine("加密后长度:	" + str.Length);
            byte[] plain = RSADemo.Decrypt(priKey, cip);
		    Console.WriteLine("解密后:	" + System.Text.Encoding.Default.GetString(plain));
	    }

        public static void TestSign()
        {
            Console.WriteLine("\nTest rsa 2048");
            string text = "Test Sign, 1234abcd";

            RSACryptoServiceProvider rsa = new RSACryptoServiceProvider(2048);
            string pubKey = rsa.ToXmlString(false);
            string priKey = rsa.ToXmlString(true);

            Console.WriteLine("明文: " + text);
            byte[] sign = SignDemo.Sign(priKey, System.Text.Encoding.Default.GetBytes(text));
            string strSign = Convert.ToBase64String(sign);

            Console.WriteLine("签名值:	" + strSign);
            Console.WriteLine("签名值长度:	" + strSign.Length);

            bool bVerify = SignDemo.VerifySign(pubKey, System.Text.Encoding.Default.GetBytes(text), sign);
            Console.WriteLine("签名验证结果：" + bVerify);
        }

        public static void TestPBKDF2()
        {
		    Console.WriteLine("\nTest pbkdf2");

            string psw = "password01!";
		    byte []dk = PBKDF2Demo.DeriveKey(psw);
			
		    Console.WriteLine("密码:	" + psw);
		    string strdk = System.Convert.ToBase64String(dk);
		    Console.WriteLine("pbkdf2后:	" + strdk);
			
		    Console.WriteLine("Verify:		" + PBKDF2Demo.Verify(psw, dk));
	    }
    }
}
