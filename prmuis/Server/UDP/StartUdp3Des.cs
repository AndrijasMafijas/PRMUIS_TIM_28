using GlavneMetode.Helpers;
using GlavneMetode.Models;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading.Tasks;

namespace Server
{
    public class StartUdp3Des
    {
        public static void StartUDPServer3DES(int port)
        {
            Console.WriteLine($"[INFO] UDP Server sa 3DES na portu {port}...");
            NacinKomunikacije udpServer = new NacinKomunikacije(2, "3DES", "", new IPEndPoint(IPAddress.Any, port));
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
                    Console.WriteLine($"[GRESKA] Nepoznat ili neautorizovan UDP klijent {clientId}, odbacujem poruku.");
                    continue;
                }
                string hashedAlgo = SHAHelper.Hash("3DES");
                if (!Server.komunikacijePoHesu.TryGetValue(hashedAlgo, out var komunikacija))
                {
                    Console.WriteLine("[GRESKA] Nema informacija o algoritmu 3DES (heš nije nađen).");
                    continue;
                }
                byte[] key3DES = Convert.FromBase64String(Server.udpClientKeys[clientId].clientPublicKey);
                string decryptedMsg;
                try
                {
                    decryptedMsg = TripleDES.Decrypt3DES(data, key3DES);
                }
                catch (Exception e)
                {
                    Console.WriteLine("[GRESKA] Ne mogu dekriptovati UDP poruku: " + e.Message);
                    continue;
                }
                Console.WriteLine($"[PRIMLJENO od {((IPEndPoint)clientEP).Address}:{((IPEndPoint)clientEP).Port}] {decryptedMsg}");
                if (decryptedMsg.Contains("kraj"))
                {
                    Console.WriteLine("[INFO] Primljena komanda 'kraj', server se zatvara...");
                    running = false;
                    break;
                }
                Console.Write("Unesite odgovor za UDP klijenta: ");
                string odgovor = Console.ReadLine();
                byte[] encryptedResponse;
                try
                {
                    encryptedResponse = TripleDES.Encrypt3DES(odgovor, key3DES);
                    udpServer.SendTo(encryptedResponse, clientEP);
                }
                catch (Exception e)
                {
                    Console.WriteLine("[GRESKA] Ne mogu poslati odgovor UDP klijentu: " + e.Message);
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
