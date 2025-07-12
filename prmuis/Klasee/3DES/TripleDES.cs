using GlavneMetode;
using System;
using System.Security.Cryptography;
using System.Text;

public class TripleDES
{
    // Statička metoda za šifrovanje poruke
    public static byte[] Encrypt3DES(string message, byte[] key)
    {
        if (key.Length != 24) // Proverava da li ključ ima 24 bajta, što je obavezno za TripleDES
        {
            throw new ArgumentException("Key must be 24 bytes long.");
        }

        try
        {
            using (TripleDESCryptoServiceProvider tdes = new TripleDESCryptoServiceProvider())
            {
                tdes.Mode = CipherMode.CBC; // Prelazak na CBC mod (sigurniji od ECB)
                tdes.Padding = PaddingMode.PKCS7;

                // Generišemo inicijalizacioni vektor (IV) za CBC mod
                tdes.GenerateIV();
                byte[] iv = tdes.IV;

                using (ICryptoTransform encryptor = tdes.CreateEncryptor(key, iv))
                {
                    byte[] messageBytes = Encoding.UTF8.GetBytes(message);
                    byte[] encryptedBytes = encryptor.TransformFinalBlock(messageBytes, 0, messageBytes.Length);

                    // Kombinujemo IV sa šifrovanom porukom kako bi ga server mogao koristiti za dešifrovanje
                    byte[] result = new byte[iv.Length + encryptedBytes.Length];
                    Buffer.BlockCopy(iv, 0, result, 0, iv.Length);
                    Buffer.BlockCopy(encryptedBytes, 0, result, iv.Length, encryptedBytes.Length);
                    TripleDESStats.TotalEncryptedBytes += result.Length;
                    return result;
                }
            }
        }
        catch (Exception ex)
        {
            throw new Exception("Encryption failed: " + ex.Message);
        }
    }

    // Statička metoda za dešifrovanje poruke
    public static string Decrypt3DES(byte[] encryptedMessage, byte[] key)
    {
        
        if (key.Length != 24) // Proverava da li ključ ima 24 bajta
        {
            throw new ArgumentException("Key must be 24 bytes long.");
        }
        
        try
        {
            using (TripleDESCryptoServiceProvider tdes = new TripleDESCryptoServiceProvider())
            {
                tdes.Mode = CipherMode.CBC;
                tdes.Padding = PaddingMode.PKCS7;

                // Ekstraktujemo IV iz prve 8 bajtova šifrovane poruke
                byte[] iv = new byte[tdes.BlockSize / 8];
                byte[] actualEncryptedMessage = new byte[encryptedMessage.Length - iv.Length];

                Buffer.BlockCopy(encryptedMessage, 0, iv, 0, iv.Length);
                Buffer.BlockCopy(encryptedMessage, iv.Length, actualEncryptedMessage, 0, actualEncryptedMessage.Length);

                using (ICryptoTransform decryptor = tdes.CreateDecryptor(key, iv))
                {
                    byte[] decryptedBytes = decryptor.TransformFinalBlock(actualEncryptedMessage, 0, actualEncryptedMessage.Length);
                    TripleDESStats.TotalDecryptedBytes += encryptedMessage.Length;
                    return Encoding.UTF8.GetString(decryptedBytes);
                }
            }
        }
        catch (Exception ex)
        {
            throw new Exception("Decryption failed: " + ex.Message);
        }
    }
}

