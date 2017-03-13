using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Security.Cryptography;

namespace Crypt
{
    class PBKDF2Demo
    {
        public static byte [] DeriveKey(String password)
        {
            byte[] salt = new byte[8];
            using (RNGCryptoServiceProvider rngCsp = new RNGCryptoServiceProvider())
            {
                // Fill the array with a random value.
            //    rngCsp.GetBytes(salt);
            }

            Rfc2898DeriveBytes key = new Rfc2898DeriveBytes(password, salt, 1024);		//1024次迭代
            byte []pbkdf2 = key.GetBytes(16);
            
            //将盐和pbkdf2值拼接后返回
            byte []all = new byte[salt.Length + pbkdf2.Length];
            Array.Copy(salt, 0, all, 0, salt.Length);
            Array.Copy(pbkdf2, 0, all, salt.Length, pbkdf2.Length);
            return all;
	    }

	    public static bool Verify(String password, byte []pbkdf2)
        {
			byte[] salt = new byte[8];
			byte[] pb = new byte[pbkdf2.Length - 8];
	
	        Array.Copy(pbkdf2, 0, salt, 0, salt.Length);
            Array.Copy(pbkdf2, salt.Length, pb, 0, pb.Length);

            Rfc2898DeriveBytes key = new Rfc2898DeriveBytes(password, salt, 1024);		//1024次迭代
            byte[] pb2 = key.GetBytes(16);
            

            if (pb2.Length != pb.Length)
            {
                return false;
            }
            else
            {
                for (int i = 0; i < pb.Length; ++i)
                {
                    if (pb2[i] != pb[i])
                    {
                        return false;
                    }
                }
                return true;
            }
        }
    }
}
