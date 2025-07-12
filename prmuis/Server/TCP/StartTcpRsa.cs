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

            Socket listener = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
            listener.Bind(new IPEndPoint(IPAddress.Any, port));
            listener.Listen(10);
            listener.Blocking = false;

            List<Socket> clients = new List<Socket>();

            // Mapiranje klijentskog soketa na njihov javni RSA ključ
            Dictionary<Socket, string> clientPublicKeys = new Dictionary<Socket, string>();

            Console.WriteLine("[INFO] Server spreman, čeka nove klijente...");

            while (true)
            {
                List<Socket> readList = new List<Socket>(clients) { listener };
                Socket.Select(readList, null, null, 1000000); // timeout = 1 sekunda

                List<Socket> zaUkloniti = new List<Socket>();

                foreach (Socket socket in readList)
                {
                    if (socket == listener)
                    {
                        try
                        {
                            Socket newClient = listener.Accept();
                            newClient.Blocking = false;
                            clients.Add(newClient);
                            Console.WriteLine($"[INFO] Novi klijent povezan: {newClient.RemoteEndPoint} (RSA)");

                            // Pretpostavljamo da je server već u globalnoj mapi udpClientKeys
                            // sačuvao javni ključ klijenta preko IP adrese
                            string clientId = ((IPEndPoint)newClient.RemoteEndPoint).Address.ToString();

                            if (Server.udpClientKeys.TryGetValue(clientId, out var kljucevi))
                            {
                                string clientPublicKey = kljucevi.clientPublicKey;
                                if (!string.IsNullOrEmpty(clientPublicKey))
                                {
                                    clientPublicKeys[newClient] = clientPublicKey;
                                    Console.WriteLine($"[INFO] Javni ključ klijenta sačuvan za {newClient.RemoteEndPoint}");
                                }
                                else
                                {
                                    Console.WriteLine($"[WARN] Nema javnog ključa za klijenta {newClient.RemoteEndPoint}");
                                }
                            }
                            else
                            {
                                Console.WriteLine($"[WARN] Nema podataka o klijentu {newClient.RemoteEndPoint} u udpClientKeys.");
                            }
                        }
                        catch { }
                    }
                    else
                    {
                        byte[] buffer = new byte[4096];
                        int received = 0;

                        try
                        {
                            received = socket.Receive(buffer);
                        }
                        catch (SocketException)
                        {
                            Console.WriteLine($"[GRESKA] Socket greška kod {socket.RemoteEndPoint}, uklanjam klijenta.");
                            zaUkloniti.Add(socket);
                            continue;
                        }

                        if (received == 0)
                        {
                            Console.WriteLine($"[INFO] Klijent {socket.RemoteEndPoint} je zatvorio konekciju.");
                            zaUkloniti.Add(socket);
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
                            Console.WriteLine($"[GRESKA] RSA dešifrovanje neuspešno za {socket.RemoteEndPoint}: {e.Message}");
                            continue;
                        }

                        Console.WriteLine($"[PRIMLJENO od {socket.RemoteEndPoint}] {decryptedMsg}");

                        if (decryptedMsg.Contains("kraj"))
                        {
                            Console.WriteLine($"[INFO] Klijent {socket.RemoteEndPoint} se diskonektovao komandom 'kraj'.");
                            zaUkloniti.Add(socket);
                            continue;
                        }

                        Console.Write($"[ODGOVOR za {socket.RemoteEndPoint}]: ");
                        string odgovor = Console.ReadLine();

                        try
                        {
                            if (!clientPublicKeys.TryGetValue(socket, out string clientPublicKey) || string.IsNullOrEmpty(clientPublicKey))
                            {
                                Console.WriteLine($"[WARN] Nema javnog ključa klijenta {socket.RemoteEndPoint}, šaljem odgovor nešifrovano.");
                                byte[] plainBytes = Encoding.UTF8.GetBytes(odgovor);
                                socket.Send(plainBytes);
                            }
                            else
                            {
                                byte[] encryptedResponse = RSAEncryption.Encrypt(odgovor, clientPublicKey);
                                socket.Send(encryptedResponse);
                            }
                        }
                        catch (Exception e)
                        {
                            Console.WriteLine($"[GRESKA] Ne mogu poslati odgovor: {e.Message}");
                            zaUkloniti.Add(socket);
                            continue;
                        }

                        if (odgovor.ToLower() == "kraj")
                        {
                            Console.WriteLine($"[INFO] Klijent {socket.RemoteEndPoint} zatvoren komandom 'kraj' sa servera.");
                            zaUkloniti.Add(socket);
                        }
                    }
                }

                foreach (var s in zaUkloniti)
                {
                    try { s.Shutdown(SocketShutdown.Both); } catch { }
                    s.Close();
                    clients.Remove(s);
                    clientPublicKeys.Remove(s);
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
