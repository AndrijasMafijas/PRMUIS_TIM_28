using GlavneMetode;
using GlavneMetode.Helpers;
using GlavneMetode.Models;
using GlavneMetode.RSA;
using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading.Tasks;

namespace Server
{
    public class Server
    {
        public static Dictionary<string, (string clientPublicKey, string serverPublicKey, string serverPrivateKey)> udpClientKeys =
            new Dictionary<string, (string clientPublicKey, string serverPublicKey, string serverPrivateKey)>();

        public static Dictionary<string, NacinKomunikacije> komunikacijePoHesu =
            new Dictionary<string, NacinKomunikacije>();

        static void Main(string[] args)
        {
            byte[] buffer = new byte[4096];

            Console.WriteLine("[INFO] Čekam početni signal klijenta sa informacijama (UDP paket sa protokolom, algoritmom, portom i ključem)");

            // Zamena UdpClient sa NacinKomunikacije za handshake
            var handshakeKom = new NacinKomunikacije(2, "Handshake", "", new IPEndPoint(IPAddress.Any, 27015));
            EndPoint remoteEP = new IPEndPoint(IPAddress.Any, 0);

            int initLen = handshakeKom.Receive(buffer, ref remoteEP);
            string initMessage = Encoding.UTF8.GetString(buffer, 0, initLen);
            Console.WriteLine($"[INFO] Primljeno od {remoteEP}: {initMessage}");

            var parts = initMessage.Split(' ');
            if (parts.Length != 3)
            {
                Console.WriteLine("[GRESKA] Neispravan inicijalni paket (ocekujem 3 dela: protokol, algoritam, port)");
                return;
            }

            int protocol = int.Parse(parts[0]); // 1 = TCP, 2 = UDP
            int algorithm = int.Parse(parts[1]); // 1 = 3DES, 2 = RSA
            int clientPort = int.Parse(parts[2]);

            string encryptionAlgo = algorithm == 1 ? "3DES" : "RSA";
            string hashedAlgorithm = SHAHelper.Hash(encryptionAlgo);
            Console.WriteLine($"[INFO] Heš algoritma ({encryptionAlgo}): {hashedAlgorithm}");
            Console.WriteLine($"[INFO] Klijent je odabrao protokol {(protocol == 1 ? "TCP" : "UDP")} i algoritam {encryptionAlgo}");

            if (algorithm == 2) // RSA direktno za poruke
            {
                RSAEncryption.GenerateKeys(out string serverPublicKey, out string serverPrivateKey);
                byte[] serverKeyBytes = Encoding.UTF8.GetBytes(serverPublicKey);
                handshakeKom.SendTo(serverKeyBytes, remoteEP);
                Console.WriteLine("[INFO] Poslat javni RSA ključ klijentu.");

                int clientKeyLen = handshakeKom.Receive(buffer, ref remoteEP);
                string clientPublicKey = Encoding.UTF8.GetString(buffer, 0, clientKeyLen);
                Console.WriteLine("[INFO] Primljen klijentov javni RSA ključ.");

                string clientId = ((IPEndPoint)remoteEP).Address.ToString();
                udpClientKeys[clientId] = (clientPublicKey, serverPublicKey, serverPrivateKey);
                Console.WriteLine($"[INFO] Sačuvan serverov RSA par ključeva za UDP klijenta {clientId}");

                var komunikacija = new NacinKomunikacije(protocol, encryptionAlgo, "RSA_KEY", remoteEP)
                {
                    HesiraniNazivAlgoritma = hashedAlgorithm
                };
                komunikacijePoHesu[hashedAlgorithm] = komunikacija;

                if (protocol == 1)
                {
                    StartTcpRsa.StartTCPServerRSA(clientPort, serverPrivateKey);
                }
                else
                {
                    StartUdpRsa.StartUDPServerRSA(clientPort, serverPrivateKey);
                }

                PrikazStatistikeRada();
                handshakeKom.Close();
                return;
            }

            // === 3DES ===

            // Za 3DES ne šalji serverov javni RSA ključ, već samo primi simetrični ključ direktno
            int keyLen = handshakeKom.Receive(buffer, ref remoteEP);
            byte[] keyBytes = new byte[keyLen];
            Array.Copy(buffer, keyBytes, keyLen);
            Console.WriteLine("[INFO] Primljen simetrični 3DES ključ (nešifrovan).");

            string clientId3DES = ((IPEndPoint)remoteEP).Address.ToString();
            udpClientKeys[clientId3DES] = (Convert.ToBase64String(keyBytes), "", "");
            Console.WriteLine($"[INFO] Zapamćen 3DES ključ za UDP klijenta {clientId3DES}");

            var komunikacija3DES = new NacinKomunikacije(protocol, encryptionAlgo, Convert.ToBase64String(keyBytes), remoteEP)
            {
                HesiraniNazivAlgoritma = hashedAlgorithm
            };
            komunikacijePoHesu[hashedAlgorithm] = komunikacija3DES;

            if (protocol == 1)
            {
                StartTcp3Des.StartTCPServer3DES(clientPort, keyBytes);
            }
            else
            {
                StartUdp3Des.StartUDPServer3DES(clientPort);
            }

            PrikazStatistikeRada();
            handshakeKom.Close();
        }

        static void PrikazStatistikeRada()
        {
            Console.WriteLine("\n===== Statistika enkripcije i dekripcije =====");
            Console.WriteLine($"RSA - Broj RSA poruka: {RSAStats.TotalMessages}");
            Console.WriteLine($"3DES - Enkriptovano ukupno: {TripleDESStats.TotalEncryptedBytes} bajtova");
            Console.WriteLine($"3DES - Dekriptovano ukupno: {TripleDESStats.TotalDecryptedBytes} bajtova");
        }
    }
}
