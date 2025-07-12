using System;
using System.Security.Cryptography;
using System.Text;

namespace GlavneMetode.Helpers
{
    public class SHAHelper
    {
        public static string Hash(string input)
        {
            try
            {
                using (SHA256 sha256 = SHA256.Create())
                {
                    byte[] bytes = Encoding.UTF8.GetBytes(input);
                    byte[] hash = sha256.ComputeHash(bytes);
                    StringBuilder sb = new StringBuilder();
                    foreach (byte b in hash)
                    {
                        sb.Append(b.ToString("x2"));
                    }
                    return sb.ToString();
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error computing SHA256 hash: {ex.Message}");
                return string.Empty;
            }
        }
    }
} 