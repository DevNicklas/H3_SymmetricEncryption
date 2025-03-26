using H3_SymmetricEncryption.Interfaces;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace H3_SymmetricEncryption.Algorithms
{
    /// <summary>
    /// DES (Data Encryption Standard) encryption algorithm implementation.
    /// </summary>
    public class DesEncryptionAlgorithm : IEncryptionAlgorithm
    {
        private readonly DES _algorithm = DES.Create();

        /// <summary>
        /// The name of the encryption algorithm (DES).
        /// </summary>
        public string AlgorithmName => _algorithm.GetType().Name;

        /// <summary>
        /// Encrypts the given plaintext using the DES algorithm.
        /// </summary>
        public byte[] Encrypt(string plaintext, byte[] key, byte[] iv)
        {
            _algorithm.Key = key;
            _algorithm.IV = iv;
            using (ICryptoTransform encryptor = _algorithm.CreateEncryptor())
            using (MemoryStream msEncrypt = new MemoryStream())
            using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
            using (StreamWriter swEncrypt = new StreamWriter(csEncrypt))
            {
                swEncrypt.Write(plaintext);
                swEncrypt.Close();
                return msEncrypt.ToArray();
            }
        }

        /// <summary>
        /// Decrypts the given ciphertext using the DES algorithm.
        /// </summary>
        public string Decrypt(byte[] ciphertext, byte[] key, byte[] iv)
        {
            _algorithm.Key = key;
            _algorithm.IV = iv;
            using (ICryptoTransform decryptor = _algorithm.CreateDecryptor())
            using (MemoryStream msDecrypt = new MemoryStream(ciphertext))
            using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
            using (StreamReader srDecrypt = new StreamReader(csDecrypt))
            {
                return srDecrypt.ReadToEnd();
            }
        }

        /// <summary>
        /// Generates a secure encryption key for DES.
        /// </summary>
        public byte[] GenerateKey() => _algorithm.Key;

        /// <summary>
        /// Generates a secure initialization vector (IV) for DES.
        /// </summary>
        public byte[] GenerateIV() => _algorithm.IV;
    }
}
