using System;
using System.Collections.Generic;
using System.Text;
using System.IO;
using System.Security.Cryptography;


namespace Crypt
{
    public class AES256Demo
    {
        public static String Encrypt(String key, String text)
        {
            byte []cipherBytes = Encrypt(System.Text.Encoding.Default.GetBytes(key), System.Text.Encoding.Default.GetBytes(text), 256);
            String sk = System.Text.Encoding.Default.GetString(System.Text.Encoding.Default.GetBytes(key));
            return System.Convert.ToBase64String(cipherBytes);
        }

        public static String Decrypt(String key, String cipher)
        {
            byte[] plainBytes = Decrypt(System.Text.Encoding.Default.GetBytes(key), System.Convert.FromBase64String(cipher), 256);
            return System.Text.Encoding.Default.GetString(plainBytes);
        }

        public static String Encrypt128(String key, String text)
        {
            byte[] cipherBytes = Encrypt(System.Text.Encoding.Default.GetBytes(key), System.Text.Encoding.Default.GetBytes(text), 128);
            String sk = System.Text.Encoding.Default.GetString(System.Text.Encoding.Default.GetBytes(key));
            return System.Convert.ToBase64String(cipherBytes);
        }

        public static String Decrypt128(String key, String cipher)
        {
            byte[] plainBytes = Decrypt(System.Text.Encoding.Default.GetBytes(key), System.Convert.FromBase64String(cipher), 128);
            return System.Text.Encoding.Default.GetString(plainBytes);
        }

        public static byte[] Encrypt(byte[] key, byte[] plainText, int nBits)
        {
            // Check arguments.
            if (plainText == null || plainText.Length <= 0)
                throw new ArgumentNullException("plainText");

            byte[] aesKeyBytes = new byte[nBits/8];	//32 bytes for AES-256

            int len = key.Length > nBits/8 ? nBits/8 : key.Length;
            Array.Copy(key, 0, aesKeyBytes, 0, len);

            // Declare the streams used
            // to encrypt to an in memory
            // array of bytes.
            MemoryStream msEncrypt = null;
            CryptoStream csEncrypt = null;

            // Declare the Aes object
            // used to encrypt the data.
            Aes aesAlg = null;

            // Declare the bytes used to hold the
            // encrypted data.
            byte[] encrypted = null;
            byte[] IV = null;

            try
            {
                // Create an Aes object
                // with the specified key and IV.
                aesAlg = Aes.Create();
                aesAlg.Key = aesKeyBytes;
                aesAlg.GenerateIV();                //随机的初始化向量
                aesAlg.Mode = CipherMode.CBC;       //CBC模式
                aesAlg.Padding = PaddingMode.PKCS7; //PKCS7补码
                IV = new byte[aesAlg.IV.Length];
                aesAlg.IV.CopyTo(IV, 0);

                // Create a decrytor to perform the stream transform.
                ICryptoTransform encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV);

                // Create the streams used for encryption.
                msEncrypt = new MemoryStream();
                csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write);

                //Write all data to the stream.
                //swEncrypt.Write(plainText);

                csEncrypt.Write(plainText, 0, plainText.Length);
            }
            finally
            {
                // Clean things up.

                // Close the streams.
                if (csEncrypt != null)
                    csEncrypt.Close();
                if (msEncrypt != null)
                    msEncrypt.Close();

                // Clear the Aes object.
                if (aesAlg != null)
                    aesAlg.Clear();
            }

            byte[] cipher = msEncrypt.ToArray();

            encrypted = new byte[IV.Length + cipher.Length];

            IV.CopyTo(encrypted, 0);    //IV附在密文前端
            cipher.CopyTo(encrypted, IV.Length);
            // Return the encrypted bytes from the memory stream.

            return encrypted;
        }

        public static byte[] Decrypt(byte[] key, byte[] cipherText, int nBits)
        {
            // Check arguments.
            if (cipherText == null || cipherText.Length <= 0)
                throw new ArgumentNullException("cipherText");

            byte[] aesKeyBytes = new byte[nBits/8];	//32 bytes for AES-256

            int len = key.Length > nBits/8 ? nBits/8 : key.Length;
            Array.Copy(key, 0, aesKeyBytes, 0, len);

            // TDeclare the streams used
            // to decrypt to an in memory
            // array of bytes.
            MemoryStream msDecrypt = null;
            CryptoStream csDecrypt = null;
            StreamReader srDecrypt = null;

            // Declare the Aes object
            // used to decrypt the data.
            Aes aesAlg = null;

            // Declare the string used to hold
            // the decrypted text.
            byte []plainText = null;

            try
            {
                //Get IV and cipher
                byte[] cipher = new byte[cipherText.Length-16];
                byte[] IV = new byte[16];
                Array.Copy(cipherText, IV, IV.Length);
                Array.Copy(cipherText, IV.Length, cipher, 0, cipherText.Length - IV.Length);

                // Create an Aes object
                // with the specified key and IV.
                aesAlg = Aes.Create();
                aesAlg.Key = aesKeyBytes;
                aesAlg.IV = IV;

                // Create a decrytor to perform the stream transform.
                ICryptoTransform decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);

                // Create the streams used for decryption.
                msDecrypt = new MemoryStream(cipher);
                csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read);
                srDecrypt = new StreamReader(csDecrypt);

                // Read the decrypted bytes from the decrypting stream
                // and place them in a string.
                string ss = srDecrypt.ReadToEnd();
                plainText = System.Text.Encoding.Default.GetBytes(ss);
                
            }
            finally
            {
                // Clean things up.

                // Close the streams.
                if (srDecrypt != null)
                    srDecrypt.Close();
                if (csDecrypt != null)
                    csDecrypt.Close();
                if (msDecrypt != null)
                    msDecrypt.Close();

                // Clear the Aes object.
                if (aesAlg != null)
                    aesAlg.Clear();
            }

            return plainText;

        }

    }
}
