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
    public class StartTcp3Des
    {
        public static void StartTCPServer3DES(int port, byte[] firstClientKey)
        {
            Console.WriteLine($"[INFO] TCP Server sa 3DES na portu {port}...");

            NacinKomunikacije listener = null;
            try
            {
                listener = new NacinKomunikacije(1, "3DES", Convert.ToBase64String(firstClientKey), new IPEndPoint(IPAddress.Any, port));
                //listener.clientSocket.Blocking = false;
                listener.Listen(10);
                Console.WriteLine($"[DEBUG] TCP server bindovan na: {listener.clientSocket.LocalEndPoint}");
            }
            catch (Exception ex)
            {
                Console.WriteLine("[FATAL] Ne mogu da bindujem TCP server: " + ex.Message);
                return;
            }

            List<NacinKomunikacije> clients = new List<NacinKomunikacije>();
            Dictionary<NacinKomunikacije, byte[]> clientKeys = new Dictionary<NacinKomunikacije, byte[]>();
            Dictionary<NacinKomunikacije, NacinKomunikacije> clientInfo = new Dictionary<NacinKomunikacije, NacinKomunikacije>();

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
                        var newKom = new NacinKomunikacije(1, "3DES", listener.Kljuc, newClientSocket.RemoteEndPoint);
                        newKom.clientSocket = newClientSocket;
                        clients.Add(newKom);

                        string hashedAlgo = SHAHelper.Hash("3DES");
                        if (Server.komunikacijePoHesu.TryGetValue(hashedAlgo, out var komunikacijaInfo))
                        {
                            clientKeys[newKom] = Convert.FromBase64String(komunikacijaInfo.Kljuc);
                            clientInfo[newKom] = komunikacijaInfo;
                            Console.WriteLine($"[INFO] Novi klijent povezan: {newClientSocket.RemoteEndPoint}, koristi {komunikacijaInfo.Algoritam}");
                        }
                        else
                        {
                            Console.WriteLine("[GRESKA] Nema informacija o algoritmu 3DES (heš nije nađen).");
                            newKom.Close();
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
                        Console.WriteLine($"[GRESKA] Socket exception za klijenta {komunikacija.clientSocket.RemoteEndPoint}, uklanjam konekciju.");
                        zaUkloniti.Add(komunikacija);
                        continue;
                    }
                    if (received == 0)
                    {
                        Console.WriteLine($"[INFO] Klijent {komunikacija.clientSocket.RemoteEndPoint} je prekinuo vezu.");
                        zaUkloniti.Add(komunikacija);
                        continue;
                    }
                    byte[] encryptedData = new byte[received];
                    Array.Copy(buffer, encryptedData, received);
                    string decryptedMessage;
                    try
                    {
                        decryptedMessage = TripleDES.Decrypt3DES(encryptedData, clientKeys[komunikacija]);
                    }
                    catch (Exception e)
                    {
                        Console.WriteLine($"[GRESKA] Dekripcija neuspešna za {komunikacija.clientSocket.RemoteEndPoint}: {e.Message}");
                        continue;
                    }
                    Console.WriteLine($"[PRIMLJENO od {komunikacija.clientSocket.RemoteEndPoint}] {decryptedMessage} (Algoritam: {clientInfo[komunikacija].Algoritam})");
                    if (decryptedMessage.Contains("kraj"))
                    {
                        Console.WriteLine($"[INFO] Klijent {komunikacija.clientSocket.RemoteEndPoint} se diskonektovao komandom 'kraj'.");
                        zaUkloniti.Add(komunikacija);
                        continue;
                    }
                    Console.Write($"[ODGOVOR za {komunikacija.clientSocket.RemoteEndPoint}]: ");
                    string odgovor = Console.ReadLine();
                    byte[] encryptedResponse;
                    try
                    {
                        encryptedResponse = TripleDES.Encrypt3DES(odgovor, clientKeys[komunikacija]);
                        komunikacija.Send(encryptedResponse);
                    }
                    catch (Exception e)
                    {
                        Console.WriteLine($"[GRESKA] Slanje poruke neuspešno: {e.Message}");
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
                    clientKeys.Remove(k);
                    clientInfo.Remove(k);
                }
                if (clients.Count == 0)
                {
                    Console.WriteLine("[INFO] Nema više aktivnih klijenata. Zatvaram TCP server.");
                    try { listener.Close(); } catch { }
                    return;
                }
            }
        }
    }
}

