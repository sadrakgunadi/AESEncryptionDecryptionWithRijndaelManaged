using System;
using System.Collections.Generic;
using System.Text;
using System.Security.Cryptography;
using System.IO;

namespace AESAlgorithm
{
    class Program
    {
        static void Main(string[] args)
        {
            string key = string.Empty;
            string IV = string.Empty;
            string salt = string.Empty;

            using (RijndaelManaged rijndael = new RijndaelManaged())
            {
                rijndael.KeySize = 256;
                rijndael.Mode = CipherMode.CBC;
                rijndael.Padding = PaddingMode.PKCS7;

                rijndael.GenerateKey();

                key = Convert.ToBase64String(rijndael.Key);
                IV = Convert.ToBase64String(rijndael.IV);
                //salt = Convert.ToBase64String(GetSalt(32));
            }

            //Get Key and IV get from JAVA Application
            key = "cdzUhEbPUm0Ucq1NuESz2FvoqrzMmD+67ja5hdmKnLE=";
            IV = "HKn85+KzMBwjWomnZbkM/Q==";

            Console.WriteLine("\"Generated AES Random Key\"\r\n");

            Console.WriteLine("============================");
            Console.WriteLine("Random Key : " + key);
            Console.WriteLine("Random IV : " + IV);
            Console.WriteLine("============================\r\n");

            Console.WriteLine("Key Format : (using pipeline '|' delimiter) => Key + IV");
            string concatKey = key + "|" + IV;
            Console.WriteLine(concatKey);

            string plainText = "sadrak gunadi";
            string chiperText = Convert.ToBase64String(EncryptStringToBytes(plainText, Convert.FromBase64String(key), Convert.FromBase64String(IV)));
            string original = DecryptStringFromBytes(Convert.FromBase64String(chiperText), Convert.FromBase64String(key), Convert.FromBase64String(IV));

            Console.WriteLine("\r\nPlain Text : " + plainText);
            Console.WriteLine("Chiper Text : " + chiperText);
            Console.WriteLine("Original Text : " + original);

            Console.ReadKey();
        }

        private static byte[] GetSalt(int saltLengthLimit)
        {
            byte[] salt = new byte[saltLengthLimit];
            RNGCryptoServiceProvider random = new RNGCryptoServiceProvider();
            random.GetNonZeroBytes(salt);
            return salt;
        }

        static byte[] EncryptStringToBytes(string plainText, byte[] Key, byte[] IV)
        {
            if (plainText == null || plainText.Length <= 0)
                throw new ArgumentNullException("plainText");
            if (Key == null || Key.Length <= 0)
                throw new ArgumentNullException("Key");
            if (IV == null || IV.Length <= 0)
                throw new ArgumentNullException("IV");
            byte[] encrypted;

            using (RijndaelManaged rijAlg = new RijndaelManaged())
            {
                rijAlg.KeySize = 256;
                rijAlg.Mode = CipherMode.CBC;
                rijAlg.Padding = PaddingMode.PKCS7;

                rijAlg.Key = Key;
                rijAlg.IV = IV;

                ICryptoTransform encryptor = rijAlg.CreateEncryptor(rijAlg.Key, rijAlg.IV);

                using (MemoryStream msEncrypt = new MemoryStream())
                {
                    using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                    {
                        using (StreamWriter swEncrypt = new StreamWriter(csEncrypt))
                        {
                            swEncrypt.Write(plainText);
                        }
                        encrypted = msEncrypt.ToArray();
                    }
                }
            }

            return encrypted;

        }

        static string DecryptStringFromBytes(byte[] cipherText, byte[] Key, byte[] IV)
        {
            if (cipherText == null || cipherText.Length <= 0)
                throw new ArgumentNullException("cipherText");
            if (Key == null || Key.Length <= 0)
                throw new ArgumentNullException("Key");
            if (IV == null || IV.Length <= 0)
                throw new ArgumentNullException("IV");
            string plaintext = null;

            using (RijndaelManaged rijAlg = new RijndaelManaged())
            {
                rijAlg.KeySize = 256;
                rijAlg.Mode = CipherMode.CBC;
                rijAlg.Padding = PaddingMode.PKCS7;

                rijAlg.Key = Key;
                rijAlg.IV = IV;

                ICryptoTransform decryptor = rijAlg.CreateDecryptor(rijAlg.Key, rijAlg.IV);

                using (MemoryStream msDecrypt = new MemoryStream(cipherText))
                {
                    using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                    {
                        using (StreamReader srDecrypt = new StreamReader(csDecrypt))
                        {
                            plaintext = srDecrypt.ReadToEnd();
                        }
                    }
                }
            }

            return plaintext;

        }
    }
}
