using GlavneMetode.RSA;
using System;
using System.Net;
using System.Net.Sockets;
using System.Text;
using GlavneMetode.Models;

namespace Server
{
    public class StartUdpRsa
    {
        public static void StartUDPServerRSA(int port, string serverPrivateKey)
        {
            Console.WriteLine($"[INFO] UDP Server sa RSA na portu {port}...");
            NacinKomunikacije udpServer = new NacinKomunikacije(2, "RSA", "", new IPEndPoint(IPAddress.Any, port));
            bool running = true;
            byte[] buffer = new byte[4096];
            while (running)
            {
                EndPoint clientEP = new IPEndPoint(IPAddress.Any, 0);
                int len = 0;
                try
                {
                    len = udpServer.Receive(buffer, ref clientEP);
                }
                catch (SocketException ex)
                {
                    Console.WriteLine("[GRESKA] Greška pri primanju UDP poruke: " + ex.Message);
                    continue;
                }
                byte[] data = new byte[len];
                Array.Copy(buffer, data, len);
                string clientId = ((IPEndPoint)clientEP).Address.ToString();
                if (!Server.udpClientKeys.ContainsKey(clientId))
                {
                    Console.WriteLine($"[GRESKA] Nepoznat klijent {clientId}, odbacujem poruku.");
                    continue;
                }
                string decryptedMsg;
                try
                {
                    decryptedMsg = RSAEncryption.Decrypt(data, serverPrivateKey);
                    RSAStats.TotalMessages++;
                }
                catch (Exception e)
                {
                    Console.WriteLine("[GRESKA] RSA dekriptovanje poruke neuspelo: " + e.Message);
                    continue;
                }
                Console.WriteLine($"[PRIMLJENO od {clientId}] {decryptedMsg}");
                if (decryptedMsg.Contains("kraj"))
                {
                    Console.WriteLine("[INFO] Primljena komanda 'kraj', server se zatvara...");
                    running = false;
                    break;
                }
                Console.Write("Unesite odgovor za UDP klijenta: ");
                string odgovor = Console.ReadLine();
                try
                {
                    string clientPublicKey = Server.udpClientKeys[clientId].clientPublicKey;
                    byte[] encryptedResponse = RSAEncryption.Encrypt(odgovor, clientPublicKey);
                    udpServer.SendTo(encryptedResponse, clientEP);
                }
                catch (Exception e)
                {
                    Console.WriteLine("[GRESKA] RSA šifrovanje odgovora neuspelo: " + e.Message);
                }
                if (odgovor.ToLower() == "kraj")
                {
                    Console.WriteLine("[INFO] Server se zatvara po komandi sa servera.");
                    running = false;
                    break;
                }
            }
            udpServer.Close();
            Console.WriteLine("[INFO] UDP Server zatvoren.");
        }
    }
}
