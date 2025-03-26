using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace H3_SymmetricEncryption.Interfaces
{
    /// <summary>
    /// Interface defining the contract for symmetric encryption algorithms.
    /// </summary>
    public interface IEncryptionAlgorithm
    {
        byte[] Encrypt(string plaintext, byte[] key, byte[] iv);
        string Decrypt(byte[] ciphertext, byte[] key, byte[] iv);
        byte[] GenerateKey();
        byte[] GenerateIV();
        string AlgorithmName { get; }
    }
}
