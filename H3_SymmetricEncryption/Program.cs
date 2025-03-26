using H3_SymmetricEncryption.Algorithms;
using H3_SymmetricEncryption.Interfaces;
using H3_SymmetricEncryption.Services;
using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;

namespace H3_SymmetricEncryption
{
    public class Program
    {
        static void Main(string[] args)
        {
            // Display available algorithms
            Console.WriteLine("Choose an encryption algorithm:");
            Console.WriteLine("1: DES");
            Console.WriteLine("2: 3DES");
            Console.WriteLine("3: AES (Rijndael)");

            // Get the user's choice
            ConsoleKey choice = Console.ReadKey(intercept: true).Key;
            IEncryptionAlgorithm algorithm = choice switch
            {
                ConsoleKey.D1 => new DesEncryptionAlgorithm(),
                ConsoleKey.D2 => new TripleDesEncryptionAlgorithm(),
                ConsoleKey.D3 => new AesEncryptionAlgorithm(),
                _ => throw new Exception("Invalid choice")
            };

            Console.Clear();
            Console.WriteLine($"You selected: {algorithm.AlgorithmName}");
            Console.Write("Enter a message to encrypt: ");

            string plaintext = Console.ReadLine();

            // Process the encryption and the decryption and display results
            EncryptionService encryptionService = new EncryptionService(algorithm);
            encryptionService.ProcessEncryption(plaintext);
        }
    }
}