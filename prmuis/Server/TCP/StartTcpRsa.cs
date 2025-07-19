using GlavneMetode.Models;
using GlavneMetode.RSA;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Text;

namespace Server
{
    public class StartTcpRsa
    {
        public static void StartTCPServerRSA(int port, string serverPrivateKey)
        {
            Console.WriteLine($"[INFO] TCP Server sa RSA na portu {port}...");

            NacinKomunikacije listener = new NacinKomunikacije(1, "RSA", "", new IPEndPoint(IPAddress.Any, port));
            //listener.clientSocket.Blocking = false;
            listener.Listen(10); // OVO JE KLJUČNO!
            Console.WriteLine($"[DEBUG] TCP server bindovan na: {listener.clientSocket.LocalEndPoint}");

            List<NacinKomunikacije> clients = new List<NacinKomunikacije>();
            Dictionary<NacinKomunikacije, string> clientPublicKeys = new Dictionary<NacinKomunikacije, string>();

            Console.WriteLine("[INFO] Server spreman, čeka nove klijente...");

            while (true)
            {
                List<NacinKomunikacije> allConnections = new List<NacinKomunikacije>(clients) { listener };
                List<Socket> socketList = allConnections.Select(c => c.clientSocket).ToList();
                Socket.Select(socketList, null, null, 1000000);
                List<NacinKomunikacije> zaUkloniti = new List<NacinKomunikacije>();

                // Prvo obradi nove konekcije
                if (socketList.Contains(listener.clientSocket))
                {
                    try
                    {
                        Socket newClientSocket = listener.Accept();
                        var newKom = new NacinKomunikacije(1, "RSA", "", newClientSocket.RemoteEndPoint);
                        newKom.clientSocket = newClientSocket;
                        clients.Add(newKom);
                        Console.WriteLine($"[INFO] Novi klijent povezan: {newClientSocket.RemoteEndPoint} (RSA)");

                        string clientId = ((IPEndPoint)newClientSocket.RemoteEndPoint).Address.ToString();
                        if (Server.udpClientKeys.TryGetValue(clientId, out var kljucevi))
                        {
                            string clientPublicKey = kljucevi.clientPublicKey;
                            if (!string.IsNullOrEmpty(clientPublicKey))
                            {
                                clientPublicKeys[newKom] = clientPublicKey;
                                Console.WriteLine($"[INFO] Javni ključ klijenta sačuvan za {newClientSocket.RemoteEndPoint}");
                            }
                            else
                            {
                                Console.WriteLine($"[WARN] Nema javnog ključa za klijenta {newClientSocket.RemoteEndPoint}");
                            }
                        }
                        else
                        {
                            Console.WriteLine($"[WARN] Nema podataka o klijentu {newClientSocket.RemoteEndPoint} u udpClientKeys.");
                        }
                    }
                    catch { }
                }

                // Zatim iteriraj kroz klijente i čitaj samo sa spremnih
                foreach (var komunikacija in clients.ToList())
                {
                    if (!socketList.Contains(komunikacija.clientSocket))
                        continue;
                    byte[] buffer = new byte[4096];
                    int received = 0;
                    try
                    {
                        received = komunikacija.Receive(buffer);
                    }
                    catch (SocketException)
                    {
                        Console.WriteLine($"[GRESKA] Socket greška kod {komunikacija.clientSocket.RemoteEndPoint}, uklanjam klijenta.");
                        zaUkloniti.Add(komunikacija);
                        continue;
                    }
                    if (received == 0)
                    {
                        Console.WriteLine($"[INFO] Klijent {komunikacija.clientSocket.RemoteEndPoint} je zatvorio konekciju.");
                        zaUkloniti.Add(komunikacija);
                        continue;
                    }
                    byte[] encryptedMsg = new byte[received];
                    Array.Copy(buffer, encryptedMsg, received);
                    string decryptedMsg;
                    try
                    {
                        decryptedMsg = RSAEncryption.Decrypt(encryptedMsg, serverPrivateKey);
                        RSAStats.TotalMessages++;
                    }
                    catch (Exception e)
                    {
                        Console.WriteLine($"[GRESKA] RSA dešifrovanje neuspešno za {komunikacija.clientSocket.RemoteEndPoint}: {e.Message}");
                        continue;
                    }
                    Console.WriteLine($"[PRIMLJENO od {komunikacija.clientSocket.RemoteEndPoint}] {decryptedMsg}");
                    if (decryptedMsg.Contains("kraj"))
                    {
                        Console.WriteLine($"[INFO] Klijent {komunikacija.clientSocket.RemoteEndPoint} se diskonektovao komandom 'kraj'.");
                        zaUkloniti.Add(komunikacija);
                        continue;
                    }
                    Console.Write($"[ODGOVOR za {komunikacija.clientSocket.RemoteEndPoint}]: ");
                    string odgovor = Console.ReadLine();
                    try
                    {
                        if (!clientPublicKeys.TryGetValue(komunikacija, out string clientPublicKey) || string.IsNullOrEmpty(clientPublicKey))
                        {
                            Console.WriteLine($"[WARN] Nema javnog ključa klijenta {komunikacija.clientSocket.RemoteEndPoint}, šaljem odgovor nešifrovano.");
                            byte[] plainBytes = Encoding.UTF8.GetBytes(odgovor);
                            komunikacija.Send(plainBytes);
                        }
                        else
                        {
                            byte[] encryptedResponse = RSAEncryption.Encrypt(odgovor, clientPublicKey);
                            komunikacija.Send(encryptedResponse);
                        }
                    }
                    catch (Exception e)
                    {
                        Console.WriteLine($"[GRESKA] Ne mogu poslati odgovor: {e.Message}");
                        zaUkloniti.Add(komunikacija);
                        continue;
                    }
                    if (odgovor.ToLower() == "kraj")
                    {
                        Console.WriteLine($"[INFO] Klijent {komunikacija.clientSocket.RemoteEndPoint} zatvoren komandom 'kraj' sa servera.");
                        zaUkloniti.Add(komunikacija);
                    }
                }
                foreach (var k in zaUkloniti)
                {
                    try { k.clientSocket.Shutdown(SocketShutdown.Both); } catch { }
                    k.Close();
                    clients.Remove(k);
                    clientPublicKeys.Remove(k);
                }
                if (clients.Count == 0)
                {
                    Console.WriteLine("[INFO] Nema više aktivnih RSA klijenata. Zatvaram TCP RSA server.");
                    try { listener.Close(); } catch { }
                    return;
                }
            }
        }
    }
}
