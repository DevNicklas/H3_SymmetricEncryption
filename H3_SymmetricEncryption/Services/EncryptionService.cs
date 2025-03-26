using H3_SymmetricEncryption.Interfaces;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace H3_SymmetricEncryption.Services
{
    /// <summary>
    /// Service class that handles encryption and decryption tasks.
    /// </summary>
    public class EncryptionService
    {
        private readonly IEncryptionAlgorithm _encryptionAlgorithm;

        /// <summary>
        /// Initializes a new instance of the EncryptionService class with the given encryption algorithm.
        /// </summary>
        /// <param name="encryptionAlgorithm">The encryption algorithm to use.</param>
        public EncryptionService(IEncryptionAlgorithm encryptionAlgorithm)
        {
            _encryptionAlgorithm = encryptionAlgorithm;
        }

        /// <summary>
        /// Encrypts and decrypts the given plaintext, and measures the time taken for both operations.
        /// Displays results in ASCII and HEX formats.
        /// </summary>
        /// <param name="plaintext">The plaintext to encrypt and decrypt.</param>
        public void ProcessEncryption(string plaintext)
        {
            byte[] key = _encryptionAlgorithm.GenerateKey();
            byte[] iv = _encryptionAlgorithm.GenerateIV();

            Console.Clear();
            Console.WriteLine($"Using algorithm: {_encryptionAlgorithm.AlgorithmName}");
            Console.WriteLine($"Key (HEX): {key}");
            Console.WriteLine($"IV (HEX): {iv}");

            Stopwatch stopwatch = Stopwatch.StartNew();
            byte[] encrypted = _encryptionAlgorithm.Encrypt(plaintext, key, iv);
            stopwatch.Stop();
            Console.WriteLine($"Encryption Time: {stopwatch.ElapsedMilliseconds} ms");

            stopwatch.Restart();
            string decrypted = _encryptionAlgorithm.Decrypt(encrypted, key, iv);
            stopwatch.Stop();
            Console.WriteLine($"Decryption Time: {stopwatch.ElapsedMilliseconds} ms");

            Console.WriteLine("\n--- RESULTS ---");
            Console.WriteLine($"Plaintext (ASCII): {plaintext}");
            Console.WriteLine($"Plaintext (HEX): {ToHex(Encoding.ASCII.GetBytes(plaintext))}");
            Console.WriteLine($"Ciphertext (ASCII): {ToAscii(encrypted)}");
            Console.WriteLine($"Ciphertext (HEX): {ToHex(encrypted)}");
        }

        /// <summary>
        /// Converts a byte array to a hexadecimal string representation.
        /// </summary>
        /// <param name="data">The byte array to convert.</param>
        /// <returns>The hexadecimal string representation of the byte array.</returns>
        private static string ToHex(byte[] data) => BitConverter.ToString(data).Replace("-", " ");

        /// <summary>
        /// Converts a byte array to an ASCII string representation, replacing special characters.
        /// </summary>
        /// <param name="data">The byte array to convert.</param>
        /// <returns>The ASCII string representation of the byte array.</returns>
        private static string ToAscii(byte[] data)
        {
            string asciiString = Encoding.ASCII.GetString(data);
            return asciiString.Replace("\r", "\\r").Replace("\n", "\\n");
        }
    }
}
