using System;
using System.IO;
using System.Security.Cryptography;

namespace PokusUPB
{
    class Program
    {  
        public static byte[] CreateKey(string password, int numBytes)
        {
            var salt = new byte[] { 1, 2, 23, 234, 37, 48, 134, 63, 248, 4 };

            const int Iterations = 9872;
            using (var rfc2898DeriveBytes = new Rfc2898DeriveBytes(password, salt, Iterations))
                return rfc2898DeriveBytes.GetBytes(numBytes);
        }

        static void EncryptFileAES(string sInputFile, string sOutputFile, string key, string IV) {
            RijndaelManaged Crypto = new RijndaelManaged();
            try
            {
                FileStream fsInput = new FileStream("tmpData",
                   FileMode.Open,
                   FileAccess.Read);

                FileStream fsEncrypted = new FileStream(sOutputFile,
                   FileMode.Create,
                   FileAccess.Write);
                Crypto.Key = CreateKey(key, 32);
                Crypto.IV = CreateKey(IV, 16);
                //Crypto.Padding = PaddingMode.Zeros;
                ICryptoTransform Encryptor = Crypto.CreateEncryptor(Crypto.Key, Crypto.IV);
                CryptoStream Crypto_Stream = new CryptoStream(fsEncrypted, Encryptor, CryptoStreamMode.Write);
                byte[] bytearrayinput = new byte[fsInput.Length];
                fsInput.Read(bytearrayinput, 0, bytearrayinput.Length);
                Crypto_Stream.Write(bytearrayinput, 0, bytearrayinput.Length);
                Crypto_Stream.Close();
                fsInput.Close();
                File.Delete("tmpData");
                fsEncrypted.Close();
            }
            catch (Exception ex)
            {
                Console.WriteLine("Something went wrong: {0}", ex.Message);
            }
        }

        static void DencryptFileAES(string sInputFile, string sOutputFile, string key, string IV)
        {
            RijndaelManaged Crypto = new RijndaelManaged();
            try {
                FileStream fsInput = new FileStream(sInputFile,
                   FileMode.Open,
                   FileAccess.Read);

                FileStream fsEncrypted = new FileStream(sOutputFile,
                   FileMode.Create,
                   FileAccess.Write);
                Crypto.Key = CreateKey(key, 32);
                Crypto.IV = CreateKey(IV, 16);
                //Crypto.Padding = PaddingMode.Zeros;
                ICryptoTransform Decryptor = Crypto.CreateDecryptor(Crypto.Key, Crypto.IV);
                CryptoStream Crypto_Stream = new CryptoStream(fsEncrypted, Decryptor, CryptoStreamMode.Write);
                byte[] bytearrayinput = new byte[fsInput.Length];
                fsInput.Read(bytearrayinput, 0, bytearrayinput.Length);
                Crypto_Stream.Write(bytearrayinput, 0, bytearrayinput.Length);
                Crypto_Stream.Close();
                fsInput.Close();
                fsEncrypted.Close();
            }
            catch (Exception ex)
            {
                Console.WriteLine("Something went wrong: {0}", ex.Message);
            }
        }

        public static void PrintByteArray(byte[] array)
        {
            int i;
            for (i = 0; i < array.Length; i++)
            {
                Console.Write(String.Format("{0:X2}", array[i]));
                if ((i % 4) == 3) Console.Write(" ");
            }
            Console.WriteLine();
        }

        static bool ByteArrayCompare(byte[] a1, byte[] a2)
        {
            if (a1.Length != a2.Length)
                return false;

            for (int i = 0; i < a1.Length; i++)
                if (a1[i] != a2[i])
                    return false;

            return true;
        }

        static void hashData(string sInputFile)
        {
            try
            {
                FileStream fsInput = new FileStream(sInputFile,
                   FileMode.Open,
                   FileAccess.Read);
                FileStream fsOutput = new FileStream("tmpData",
                   FileMode.Create,
                   FileAccess.Write);
                SHA256 mySHA256 = SHA256Managed.Create();
                byte[] hashValue;
                hashValue = mySHA256.ComputeHash(fsInput);

                fsInput.Position = 0;
                byte[] bytearrayinput = new byte[fsInput.Length];
                fsInput.Read(bytearrayinput, 0, bytearrayinput.Length);
                fsOutput.Write(bytearrayinput, 0, bytearrayinput.Length);
                fsOutput.Write(hashValue, 0, hashValue.Length);
                //PrintByteArray(hashValue);
                fsInput.Close();
                fsOutput.Close();
            }
            catch(Exception ex)
            {
                Console.WriteLine("Something went wrong: {0}", ex.Message);                
            }
        }

        static void integrityCheck(string sInputFile)
        {
            try {
                FileStream fsInput = new FileStream(sInputFile,
                   FileMode.Open,
                   FileAccess.ReadWrite);
                SHA256 mySHA256 = SHA256Managed.Create();
                byte[] hashValue;
                fsInput.Position = fsInput.Length - 32;
                byte[] controlHash = new byte[32];
                fsInput.Read(controlHash, 0, 32);
                Console.WriteLine("Control hash obtained from the file:");
                PrintByteArray(controlHash);

                fsInput.SetLength(fsInput.Length - 32);
                fsInput.Position = 0;
                byte[] bytearrayinput = new byte[fsInput.Length];
                fsInput.Read(bytearrayinput, 0, bytearrayinput.Length);
                hashValue = mySHA256.ComputeHash(bytearrayinput);
                Console.WriteLine("Hash computed from the decrypted file:");
                PrintByteArray(hashValue);
                if (ByteArrayCompare(hashValue, controlHash))
                    Console.WriteLine("File integrity is OK");
                else
                    Console.WriteLine("File is corrupted, integrity check failed");


                fsInput.Close();
            }
            catch (Exception ex)
            {
                Console.WriteLine("Something went wrong: {0}", ex.Message);
            }
        }

        static void Main()
        {
            string menu, key, IV;
            do
            {
                Console.WriteLine("Welcome to the program that will cipher and decipher your files!");
                Console.WriteLine("For ciphering press - 1");
                Console.WriteLine("For deciphering press - 2");
                Console.WriteLine("For checking file integrity press - 3");
                Console.WriteLine("For exit press - 0");
                menu = Console.ReadLine();
                switch (menu)
                {
                    case "0": break;
                    case "1":
                        Console.WriteLine("Enter phrase from which will key be derived:");
                        key = Console.ReadLine();
                        Console.WriteLine("Enter phrase from which will IV be derived:");
                        IV = Console.ReadLine();
                        hashData("MyData");
                        EncryptFileAES("MyData","Encrypted", key, IV);
                        break;
                    case "2":
                        Console.WriteLine("Enter phrase from which will key be derived:");
                        key = Console.ReadLine();
                        Console.WriteLine("Enter phrase from which will IV be derived:");
                        IV = Console.ReadLine();
                        DencryptFileAES("Encrypted", "Decrypted", key, IV);
                        integrityCheck("Decrypted");
                        break;
                    case "3":
                        integrityCheck("Decrypted");
                        break;
                    default:
                        Console.WriteLine("Bad input, press any key to continue");
                        Console.ReadKey();
                        break;
                }
                //Console.Clear();
            } while (menu != "0");
        }
    }
}
