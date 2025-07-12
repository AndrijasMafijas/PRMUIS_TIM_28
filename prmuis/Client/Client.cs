using System;
using System.Net;
using System.Net.Sockets;
using System.Text;
using GlavneMetode.Helpers;
using GlavneMetode.RSA;

namespace Client
{
    internal class Client
    {
        static void Main(string[] args)
        {
            byte[] buffer = new byte[4096];
            Console.WriteLine("[INFO] Unesite IP adresu servera:");
            string ipInput = Console.ReadLine();
            if (!IPAddress.TryParse(ipInput, out IPAddress ipAddress))
            {
                Console.WriteLine("[GRESKA] Neispravna IP adresa!");
                return;
            }

            Console.WriteLine("[INFO] Unesite port servera:");
            if (!int.TryParse(Console.ReadLine(), out int port) || port < 1 || port > 65535)
            {
                Console.WriteLine("[GRESKA] Port mora biti broj izmedju 1 i 65535!");
                return;
            }

            Console.WriteLine("[INFO] Odaberite protokol:\n1 - TCP\n2 - UDP");
            if (!int.TryParse(Console.ReadLine(), out int protokol) || (protokol != 1 && protokol != 2))
            {
                Console.WriteLine("[GRESKA] Protokol mora biti 1 ili 2!");
                return;
            }

            Console.WriteLine("[INFO] Odaberite sifrovanje:\n1 - 3DES\n2 - RSA");
            if (!int.TryParse(Console.ReadLine(), out int sifra) || (sifra != 1 && sifra != 2))
            {
                Console.WriteLine("[GRESKA] Sifrovanje mora biti 1 ili 2!");
                return;
            }

            byte[] keySymmetric = null;
            string serverPublicKey = null;
            string clientPrivateKey = null;

            // Pokretanje UDP klijenta za handshake
            UdpClient udpClient = new UdpClient(0);
            udpClient.Connect(ipAddress, 27015);

            // Slanje inicijalnog paketa sa protokolom, šifrom i portom
            string initMsg = protokol + " " + sifra + " " + port;
            byte[] initBytes = Encoding.UTF8.GetBytes(initMsg);
            udpClient.Send(initBytes, initBytes.Length);

            // Ako je 3DES: generiši simetrični ključ i pošalji ga direktno (nema RSA)
            if (sifra == 1)
            {
                keySymmetric = new byte[24];
                using (var rng = new System.Security.Cryptography.RNGCryptoServiceProvider())
                {
                    rng.GetBytes(keySymmetric);
                }
                Console.WriteLine("[INFO] Heš ključa: " + SHAHelper.Hash(Convert.ToBase64String(keySymmetric)));

                // Za 3DES nema RSA ključeva ni slanja javnog ključa
                // Dakle, direktno šalji simetrični ključ serveru (NE šifrovan RSA, po dogovoru)
                udpClient.Send(keySymmetric, keySymmetric.Length);
                Console.WriteLine("[INFO] Simetrični ključ poslat serveru (nešifrovano).");
            }
            else if (sifra == 2)
            {
                // RSA: primi serverov javni ključ
                IPEndPoint remoteEP = null;
                byte[] rsaResp = udpClient.Receive(ref remoteEP);
                serverPublicKey = Encoding.UTF8.GetString(rsaResp);
                Console.WriteLine("[INFO] Primljen javni RSA ključ servera.");

                // Generiši svoj RSA par ključeva
                RSAEncryption.GenerateKeys(out string clientPublicKey, out clientPrivateKey);

                // Pošalji svoj javni ključ serveru
                byte[] clientKeyBytes = Encoding.UTF8.GetBytes(clientPublicKey);
                udpClient.Send(clientKeyBytes, clientKeyBytes.Length);
                Console.WriteLine("[INFO] Poslat klijentov javni RSA ključ.");
            }

            if (protokol == 1) // TCP komunikacija
            {
                Socket tcpSocket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
                tcpSocket.Connect(ipAddress, port);
                Console.WriteLine("[INFO] TCP konekcija uspostavljena.");

                while (true)
                {
                    Console.Write("Unesite poruku: ");
                    string msg = Console.ReadLine();
                    if (string.IsNullOrWhiteSpace(msg)) continue;

                    string hash = SHAHelper.Hash(msg);
                    string combined = msg + "|" + hash;

                    byte[] encrypted;

                    if (sifra == 1)
                    {
                        encrypted = TripleDES.Encrypt3DES(combined, keySymmetric);
                    }
                    else if (sifra == 2)
                    {
                        encrypted = RSAEncryption.Encrypt(combined, serverPublicKey);
                    }
                    else
                    {
                        throw new Exception("Nepodržan algoritam");
                    }

                    tcpSocket.Send(encrypted);
                    if (msg.ToLower() == "kraj") break;

                    int len = tcpSocket.Receive(buffer);
                    byte[] receivedData = new byte[len];
                    Array.Copy(buffer, receivedData, len);

                    string response;

                    if (sifra == 1)
                    {
                        response = TripleDES.Decrypt3DES(receivedData, keySymmetric);
                    }
                    else if (sifra == 2)
                    {
                        try
                        {
                            response = RSAEncryption.Decrypt(receivedData, clientPrivateKey);
                        }
                        catch (Exception e)
                        {
                            Console.WriteLine("[GRESKA] RSA dekriptovanje odgovora neuspelo: " + e.Message);
                            response = "";
                        }
                    }
                    else
                    {
                        response = Encoding.UTF8.GetString(receivedData);
                    }

                    PrintResponse(response);
                }

                tcpSocket.Close();
            }
            else // UDP komunikacija
            {
                udpClient = new UdpClient();
                udpClient.Connect(ipAddress, port);
                IPEndPoint serverUdpEP = null;

                while (true)
                {
                    Console.Write("Unesite poruku: ");
                    string msg = Console.ReadLine();
                    if (string.IsNullOrWhiteSpace(msg)) continue;

                    string hash = SHAHelper.Hash(msg);
                    string combined = msg + "|" + hash;

                    byte[] encrypted;

                    if (sifra == 1)
                    {
                        encrypted = TripleDES.Encrypt3DES(combined, keySymmetric);
                    }
                    else if (sifra == 2)
                    {
                        encrypted = RSAEncryption.Encrypt(combined, serverPublicKey);
                    }
                    else
                    {
                        throw new Exception("Nepodržan algoritam");
                    }

                    udpClient.Send(encrypted, encrypted.Length);
                    if (msg.ToLower() == "kraj") break;

                    byte[] responseBytes = udpClient.Receive(ref serverUdpEP);

                    string response;

                    if (sifra == 1)
                    {
                        response = TripleDES.Decrypt3DES(responseBytes, keySymmetric);
                    }
                    else if (sifra == 2)
                    {
                        try
                        {
                            response = RSAEncryption.Decrypt(responseBytes, clientPrivateKey);
                        }
                        catch (Exception e)
                        {
                            Console.WriteLine("[GRESKA] RSA dekriptovanje odgovora neuspelo: " + e.Message);
                            response = "";
                        }
                    }
                    else
                    {
                        response = Encoding.UTF8.GetString(responseBytes);
                    }

                    PrintResponse(response);
                }

                udpClient.Close();
            }

            Console.WriteLine("[INFO] Klijent zavrsio.");
        }

        static void PrintResponse(string response)
        {
            string[] parts = response.Split('|');
            if (parts.Length == 2)
            {
                string text = parts[0];
                string hash = parts[1];
                if (SHAHelper.Hash(text) == hash)
                    Console.WriteLine("[INTEGRITET OK] Odgovor: " + text);
                else
                    Console.WriteLine("[INTEGRITET NIJE OK] Odgovor: " + text);
            }
            else
            {
                Console.WriteLine("Odgovor: " + response);
            }
        }
    }
}
