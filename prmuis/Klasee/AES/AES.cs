using GlavneMetode;
using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;


public class AES
{
    public static byte[] Encrypt(string message, byte[] key)
    {
        if (key.Length != 32) // 256-bit ključ
        {
            throw new ArgumentException("Key must be 32 bytes long (256 bits) for AES-256.");
        }
        try
        {
            using (AesCryptoServiceProvider aes = new AesCryptoServiceProvider())
            {
                aes.Mode = CipherMode.CBC;
                aes.Padding = PaddingMode.PKCS7;
                aes.KeySize = 256;
                aes.BlockSize = 128;
                aes.GenerateIV();
                byte[] iv = aes.IV;
                using (ICryptoTransform encryptor = aes.CreateEncryptor(key, iv))
                {
                    byte[] messageBytes = Encoding.UTF8.GetBytes(message);
                    byte[] encryptedBytes = encryptor.TransformFinalBlock(messageBytes, 0, messageBytes.Length);
                    byte[] result = new byte[iv.Length + encryptedBytes.Length];
                    Buffer.BlockCopy(iv, 0, result, 0, iv.Length);
                    Buffer.BlockCopy(encryptedBytes, 0, result, iv.Length, encryptedBytes.Length);
                    AESStats.TotalEncryptedBytes += result.Length;
                    return result;
                }
            }
        }
        catch (Exception ex)
        {
            throw new Exception("AES Encryption failed: " + ex.Message);
        }
    }

    public static string Decrypt(byte[] encryptedMessage, byte[] key)
    {
        if (key.Length != 32)
        {
            throw new ArgumentException("Key must be 32 bytes long (256 bits) for AES-256.");
        }
        try
        {
            using (AesCryptoServiceProvider aes = new AesCryptoServiceProvider())
            {
                aes.Mode = CipherMode.CBC;
                aes.Padding = PaddingMode.PKCS7;
                aes.KeySize = 256;
                aes.BlockSize = 128;
                byte[] iv = new byte[aes.BlockSize / 8];
                byte[] actualEncryptedMessage = new byte[encryptedMessage.Length - iv.Length];
                Buffer.BlockCopy(encryptedMessage, 0, iv, 0, iv.Length);
                Buffer.BlockCopy(encryptedMessage, iv.Length, actualEncryptedMessage, 0, actualEncryptedMessage.Length);
                using (ICryptoTransform decryptor = aes.CreateDecryptor(key, iv))
                {
                    byte[] decryptedBytes = decryptor.TransformFinalBlock(actualEncryptedMessage, 0, actualEncryptedMessage.Length);
                    AESStats.TotalDecryptedBytes += encryptedMessage.Length;
                    return Encoding.UTF8.GetString(decryptedBytes);
                }
            }
        }
        catch (Exception ex)
        {
            throw new Exception("AES Decryption failed: " + ex.Message);
        }
    }
}

