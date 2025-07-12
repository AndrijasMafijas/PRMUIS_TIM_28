using System;
using System.Security.Cryptography;
using System.Text;

namespace GlavneMetode.RSA
{
    public class RSAEncryption
    {
        public static void GenerateKeys(out string publicKey, out string privateKey)
        {
            using (RSACryptoServiceProvider rsa = new RSACryptoServiceProvider(2048))
            {
                publicKey = rsa.ToXmlString(false);
                privateKey = rsa.ToXmlString(true);
            }
        }

        public static byte[] Encrypt(string message, string publicKey)
        {
            using (RSACryptoServiceProvider rsa = new RSACryptoServiceProvider(2048))
            {
                rsa.FromXmlString(publicKey);
                byte[] data = Encoding.UTF8.GetBytes(message);
                return rsa.Encrypt(data, false);
            }
        }

        public static string Decrypt(byte[] encryptedMessage, string privateKey)
        {
            using (RSACryptoServiceProvider rsa = new RSACryptoServiceProvider(2048))
            {
                rsa.FromXmlString(privateKey);
                byte[] decryptedData = rsa.Decrypt(encryptedMessage, false);
                return Encoding.UTF8.GetString(decryptedData);
            }
        }

        // Nova metoda: Šifrovanje simetričnog ključa RSA-om
        public static byte[] EncryptSymmetricKey(byte[] symmetricKey, string publicKey)
        {
            using (RSACryptoServiceProvider rsa = new RSACryptoServiceProvider(2048))
            {
                rsa.FromXmlString(publicKey);
                return rsa.Encrypt(symmetricKey, false);
            }
        }

        // Nova metoda: Dešifrovanje simetričnog ključa RSA-om
        public static byte[] DecryptSymmetricKey(byte[] encryptedSymmetricKey, string privateKey)
        {
            using (RSACryptoServiceProvider rsa = new RSACryptoServiceProvider(2048))
            {
                rsa.FromXmlString(privateKey);
                return rsa.Decrypt(encryptedSymmetricKey, false);
            }
        }

        // Pomoćna metoda za generisanje simetričnog ključa
        public static byte[] GenerateSymmetricKey(string algorithm)
        {
            if (algorithm == "AES")
            {
                using (AesCryptoServiceProvider aes = new AesCryptoServiceProvider())
                {
                    aes.KeySize = 256;
                    aes.GenerateKey();
                    return aes.Key;
                }
            }
            else if (algorithm == "3DES")
            {
                using (TripleDESCryptoServiceProvider tdes = new TripleDESCryptoServiceProvider())
                {
                    tdes.KeySize = 192;
                    tdes.GenerateKey();
                    return tdes.Key;
                }
            }
            else
            {
                throw new ArgumentException("Unknown algorithm. Use 'AES' or '3DES'.");
            }
        }
    }
}