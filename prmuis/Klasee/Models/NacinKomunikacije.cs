using System;
using System.Net;
using System.Net.Sockets;
using System.Text;

namespace GlavneMetode.Models
{
    public class NacinKomunikacije
    {
        public Socket clientSocket { get; set; }
        public string Algoritam { get; set; }
        public string Kljuc { get; set; }
        public EndPoint senderEndPoint { get; set; }
        public string HesiraniNazivAlgoritma { get; set; }

        public NacinKomunikacije(int x, string algoritam, string kljuc, EndPoint recvEndPoint)
        {
            if (x == 1)
            {
                clientSocket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
                clientSocket.Bind(recvEndPoint);
            }
            else
            {
                clientSocket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
                clientSocket.Bind(recvEndPoint);
            }
            Algoritam = algoritam;
            Kljuc = kljuc;
            senderEndPoint = recvEndPoint;
        }

        public void Listen(int backlog = 5)
        {
            if (clientSocket.ProtocolType == ProtocolType.Tcp)
            {
                clientSocket.Listen(backlog);
            }
            else
            {
                throw new InvalidOperationException("Listen method is not supported for UDP sockets.");
            }
        }

        public Socket Accept()
        {
            if (clientSocket.ProtocolType == ProtocolType.Tcp)
            {
                return clientSocket.Accept();
            }
            throw new InvalidOperationException("Accept method is not supported for UDP sockets.");
        }

        public int Receive(byte[] buffer, ref EndPoint remoteEP)
        {
            if (clientSocket.ProtocolType == ProtocolType.Tcp)
            {
                int bytesReceived = clientSocket.Receive(buffer);

                // Ako je RSA, koristi se Base64, dekodiraj odmah ovde
                if (Algoritam == "RSA")
                {
                    string base64 = Encoding.UTF8.GetString(buffer, 0, bytesReceived);
                    byte[] decoded = Convert.FromBase64String(base64);
                    Buffer.BlockCopy(decoded, 0, buffer, 0, decoded.Length);
                    return decoded.Length;
                }

                return bytesReceived;
            }
            else
            {
                int bytesReceived = clientSocket.ReceiveFrom(buffer, ref remoteEP);

                // Ako je RSA, koristi se Base64, dekodiraj odmah ovde
                if (Algoritam == "RSA")
                {
                    string base64 = Encoding.UTF8.GetString(buffer, 0, bytesReceived);
                    byte[] decoded = Convert.FromBase64String(base64);
                    Buffer.BlockCopy(decoded, 0, buffer, 0, decoded.Length);
                    return decoded.Length;
                }

                return bytesReceived;
            }
        }

        public int Receive(byte[] buffer)
        {
            if (clientSocket.ProtocolType == ProtocolType.Tcp)
            {
                int bytesReceived = clientSocket.Receive(buffer);

                if (Algoritam == "RSA")
                {
                    string base64 = Encoding.UTF8.GetString(buffer, 0, bytesReceived);
                    byte[] decoded = Convert.FromBase64String(base64);
                    Buffer.BlockCopy(decoded, 0, buffer, 0, decoded.Length);
                    return decoded.Length;
                }

                return bytesReceived;
            }
            throw new InvalidOperationException("Use the overloaded Receive method for UDP.");
        }

        public int Send(byte[] buffer)
        {
            if (clientSocket.ProtocolType == ProtocolType.Tcp)
            {
                if (Algoritam == "RSA")
                {
                    string base64 = Convert.ToBase64String(buffer);
                    byte[] encoded = Encoding.UTF8.GetBytes(base64);
                    return clientSocket.Send(encoded);
                }

                return clientSocket.Send(buffer);
            }
            throw new InvalidOperationException("Send method is not supported for UDP sockets. Use SendTo instead.");
        }

        public int SendTo(byte[] buffer, EndPoint remoteEP)
        {
            if (clientSocket.SocketType == SocketType.Dgram)
            {
                if (Algoritam == "RSA")
                {
                    string base64 = Convert.ToBase64String(buffer);
                    byte[] encoded = Encoding.UTF8.GetBytes(base64);
                    return clientSocket.SendTo(encoded, remoteEP);
                }

                return clientSocket.SendTo(buffer, remoteEP);
            }
            throw new InvalidOperationException("SendTo method is not supported for TCP sockets.");
        }

        public void Close()
        {
            clientSocket.Close();
        }
    }
}