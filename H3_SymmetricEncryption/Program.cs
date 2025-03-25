using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;

namespace H3_SymmetricEncryption
{
    public class Program
    {
        static void Main(string[] args)
        {
            Console.WriteLine("Choose an encryption algorithm:");
            Console.WriteLine("1: DES");
            Console.WriteLine("2: 3DES");
            Console.WriteLine("3: AES (Rijndael)");

            string choice = Console.ReadLine();
            SymmetricAlgorithm algorithm = choice switch
            {
                "1" => DES.Create(),
                "2" => TripleDES.Create(),
                "3" => Aes.Create(),
                _ => throw new Exception("Invalid choice")
            };

            Console.WriteLine($"You selected: {algorithm.GetType().Name}");

            byte[] key = new byte[algorithm.KeySize / 8];
            byte[] iv = new byte[algorithm.BlockSize / 8];

            RandomNumberGenerator.Fill(key);
            RandomNumberGenerator.Fill(iv);

            Console.Write("Enter a message to encrypt: ");
            string plaintext = Console.ReadLine();

            Stopwatch stopwatch = Stopwatch.StartNew();
            byte[] encrypted = Encrypt(plaintext, algorithm, key, iv);
            stopwatch.Stop();
            Console.WriteLine($"Encryption Time: {stopwatch.ElapsedMilliseconds} ms");

            stopwatch.Restart();
            string decrypted = Decrypt(encrypted, algorithm, key, iv);
            stopwatch.Stop();
            Console.WriteLine($"Decryption Time: {stopwatch.ElapsedMilliseconds} ms");

            Console.WriteLine("\n--- RESULTS ---");
            Console.WriteLine($"Plaintext (ASCII): {plaintext}");
            Console.WriteLine($"Plaintext (HEX): {ToHex(Encoding.ASCII.GetBytes(plaintext))}");
            Console.WriteLine($"Ciphertext (ASCII): {ToAscii(encrypted)}");
            Console.WriteLine($"Ciphertext (HEX): {ToHex(encrypted)}");
            Console.WriteLine($"Key (HEX): {ToHex(key)}");
            Console.WriteLine($"IV (HEX): {ToHex(iv)}");

        }

        static byte[] Encrypt(string plaintext, SymmetricAlgorithm algorithm, byte[] key, byte[] iv)
        {
            algorithm.Key = key;
            algorithm.IV = iv;

            using (ICryptoTransform encryptor = algorithm.CreateEncryptor())
            using (MemoryStream msEncrypt = new MemoryStream())
            using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
            using (StreamWriter swEncrypt = new StreamWriter(csEncrypt))
            {
                swEncrypt.Write(plaintext);
                swEncrypt.Close();
                return msEncrypt.ToArray();
            }
        }

        static string Decrypt(byte[] ciphertext, SymmetricAlgorithm algorithm, byte[] key, byte[] iv)
        {
            algorithm.Key = key;
            algorithm.IV = iv;

            using (ICryptoTransform decryptor = algorithm.CreateDecryptor())
            using (MemoryStream msDecrypt = new MemoryStream(ciphertext))
            using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
            using (StreamReader srDecrypt = new StreamReader(csDecrypt))
            {
                return srDecrypt.ReadToEnd();
            }
        }

        static string ToHex(byte[] data) => BitConverter.ToString(data).Replace("-", " ");

        static string ToAscii(byte[] data)
        {
            string asciiString = Encoding.ASCII.GetString(data);
            return asciiString.Replace("\r", "\\r").Replace("\n", "\\n");
        }

    }
}