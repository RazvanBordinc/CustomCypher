using System;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Collections.Generic;

namespace EncodingAlgorithm.Algorithm
{
    internal class CustomCypher
    {
        private byte[] _key1 = new byte[64];
        private byte[] _key2 = new byte[64];
        private byte[] _key3 = new byte[64];
        private byte[] _key4 = new byte[64];
        private const int BLOCK_SIZE = 64;

        private static byte[] GenerateRandomKey(int keySizeInBytes)
        {
            if (keySizeInBytes <= 0)
                throw new ArgumentOutOfRangeException(nameof(keySizeInBytes));
            byte[] key = new byte[keySizeInBytes];
            RandomNumberGenerator.Fill(key); // Generates crypto safe keys
            return key;
        }
        //Standard AES Substitution Box used to perform non-linear transformations -> AI GENERATED 
        private static readonly byte[] AES_SBOX = new byte[256] {
            0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5,
            0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
            0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0,
            0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
            0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC,
            0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
            0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A,
            0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
            0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0,
            0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
            0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B,
            0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
            0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85,
            0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
            0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5,
            0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
            0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17,
            0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
            0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88,
            0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
            0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C,
            0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
            0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9,
            0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
            0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6,
            0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
            0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E,
            0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
            0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94,
            0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
            0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68,
            0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16
        };

        private static readonly byte[] AES_INV_SBOX = new byte[256] {
            0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38,
            0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
            0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87,
            0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,
            0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D,
            0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
            0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2,
            0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25,
            0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16,
            0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92,
            0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA,
            0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,
            0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A,
            0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06,
            0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02,
            0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,
            0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA,
            0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,
            0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85,
            0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E,
            0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89,
            0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B,
            0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20,
            0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,
            0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31,
            0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F,
            0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D,
            0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF,
            0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0,
            0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,
            0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26,
            0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D
        };

        public string Decode(string ciphertext, string base64Key)
        {
            // Decode key
            byte[] allKeys = Convert.FromBase64String(base64Key);
            _key1 = allKeys.Take(64).ToArray();
            _key2 = allKeys.Skip(64).Take(64).ToArray();
            _key3 = allKeys.Skip(128).Take(64).ToArray();
            _key4 = allKeys.Skip(192).Take(64).ToArray();

            // Parse hex string to bytes
            byte[] cipherBytes = new byte[ciphertext.Length / 2];
            for (int i = 0; i < cipherBytes.Length; i++)
            {
                cipherBytes[i] = Convert.ToByte(ciphertext.Substring(i * 2, 2), 16);
            }

            // Get orders
            var (xOrder, calcOrder) = GenerateOrders();

            // Determine number of blocks and handle padding
            byte[] iv = _key1.Take(BLOCK_SIZE).ToArray(); // Use part of key1 as IV

            // Decrypt using CBC mode
            byte[] decrypted = DecryptCBC(cipherBytes, iv, xOrder, calcOrder);

            // Remove PKCS#7 padding
            int paddingLength = decrypted[decrypted.Length - 1];
            if (paddingLength > 0 && paddingLength <= BLOCK_SIZE)
            {
                decrypted = decrypted.Take(decrypted.Length - paddingLength).ToArray();
            }

            return Encoding.UTF8.GetString(decrypted);
        }

        private (int[] xOrder, int[] calcOrder) GenerateOrders()
        {
            int[] xOrder = _key2
                .Select((value, index) => new { value, index })
                .OrderByDescending(p => p.value)
                .Select(p => p.index)
                .ToArray(); // Generates order with 64 elements, each being distinct and in range 0-63

            int[] calcOrder = _key3
                  .Take(64)
                  .Select(p => p % 8)
                  .ToArray(); // Generates order with 8 elements in range 0-7 no distinct constraints
            return (xOrder, calcOrder);
        }

        private byte[] FeistelEncryptBlock(
           byte[] block,
           int rounds,
           int[] xOrder,
           int[] calcOrder
       )
        {
            if (block.Length != BLOCK_SIZE)throw new ArgumentException($"Block must be {BLOCK_SIZE} bytes");

            int half = block.Length / 2;
            byte[] L = block.Take(half).ToArray();  // Left half
            byte[] R = block.Skip(half).ToArray();  // Right half

            for (int round = 0; round < rounds; round++)
            {
                byte[] newR = new byte[half];
                for (int j = 0; j < half; j++)
                {
                    byte rByte = R[xOrder[j] < half ? xOrder[j] : xOrder[j] - half]; // xOrder=[ 0, 64 ]
                    byte f = SelOps(rByte, calcOrder[j], _key4);  
                    newR[j] = (byte)(L[j] ^ f);
                }

                L = R;
                R = newR;
            }

            return L.Concat(R).ToArray();
        }

        private byte[] FeistelDecryptBlock(
            byte[] block,
            int rounds,
            int[] xOrder,
            int[] calcOrder)
        {
            if (block.Length != BLOCK_SIZE)
                throw new ArgumentException($"Block must be {BLOCK_SIZE} bytes");

            int half = block.Length / 2;
            byte[] L = block.Take(half).ToArray();  // Left half
            byte[] R = block.Skip(half).ToArray();  // Right half

            for (int round = 0; round < rounds; round++)
            {
                byte[] newL = new byte[half];
                for (int j = 0; j < half; j++)
                {
                    int permIndex = xOrder[j];
                    byte lByte = L[permIndex < half ? permIndex : permIndex - half];

                    int op = calcOrder[j] & 7;

                    byte f = SelOps(lByte, op, _key4);

                    newL[j] = (byte)(R[j] ^ f);
                }

                R = L;
                L = newL;
            }

            return L.Concat(R).ToArray();
        }

        private byte SelOps(byte b, int op, byte[] k4)
        {
            // Operations performed considering the calcOrder
            switch (op & 7)
            {
                case 0: return (byte)(b ^ k4[0]);
                case 1: return (byte)(AES_SBOX[b] ^ k4[1]);
                case 2: return (byte)((b << (k4[2] & 7)) | (b >> (8 - (k4[2] & 7))));
                case 3: return (byte)((b + k4[0]) & 0xFF);
                case 4: return (byte)((b * 5) & 0xFF);
                case 5: return (byte)((b * 13) & 0xFF);
                case 6: return (byte)(b ^ ((byte)((b << 4) | (b >> 4))));
                case 7: return (byte)(AES_INV_SBOX[b] ^ k4[2]);
                default: return b;
            }
        }
        private byte[] EncryptCBC(byte[] plaintext, byte[] iv, int[] xOrder, int[] calcOrder)
        {
            int paddingLength = BLOCK_SIZE - (plaintext.Length % BLOCK_SIZE);    // 64 - length of token % 64 
            byte[] paddedPlaintext = new byte[plaintext.Length + paddingLength]; 
            Array.Copy(plaintext, paddedPlaintext, plaintext.Length);
            for (int i = plaintext.Length; i < paddedPlaintext.Length; i++)
            {
                paddedPlaintext[i] = (byte)paddingLength;
            }

            List<byte> ciphertext = new List<byte>();
            byte[] previousBlock = iv;

            for (int i = 0; i < paddedPlaintext.Length; i += BLOCK_SIZE)
            {
                byte[] block = new byte[BLOCK_SIZE];
                Array.Copy(paddedPlaintext, i, block, 0, BLOCK_SIZE);

                for (int j = 0; j < BLOCK_SIZE; j++)
                {
                    block[j] ^= previousBlock[j];
                }

                byte[] encryptedBlock = FeistelEncryptBlock(block, 16, xOrder, calcOrder); // 16 means rounds number basically how much it scrambles
                ciphertext.AddRange(encryptedBlock);

                previousBlock = encryptedBlock;
            }

            return ciphertext.ToArray();
        }

        private byte[] DecryptCBC(byte[] ciphertext, byte[] iv, int[] xOrder, int[] calcOrder)
        {
            if (ciphertext.Length % BLOCK_SIZE != 0)
            {
                throw new ArgumentException("Ciphertext length must be a multiple of block size");
            }

            List<byte> plaintext = new List<byte>();
            byte[] previousBlock = iv;

            // Process each block
            for (int i = 0; i < ciphertext.Length; i += BLOCK_SIZE)
            {
                byte[] encryptedBlock = new byte[BLOCK_SIZE];
                Array.Copy(ciphertext, i, encryptedBlock, 0, BLOCK_SIZE);

                // Decrypt the block
                byte[] decryptedBlock = FeistelDecryptBlock(encryptedBlock, 16, xOrder, calcOrder);

                // XOR with previous ciphertext block 
                for (int j = 0; j < BLOCK_SIZE; j++)
                {
                    decryptedBlock[j] ^= previousBlock[j];
                }

                plaintext.AddRange(decryptedBlock);

                // Set for next iteration
                previousBlock = encryptedBlock;
            }

            return plaintext.ToArray();
        }

        public (string key, string result) EncodeALG(string text)
        {
            // — Generate keys of 64 bytes
            _key1 = GenerateRandomKey(64);
            _key2 = GenerateRandomKey(64);
            _key3 = GenerateRandomKey(64);
            _key4 = GenerateRandomKey(64);

            // — Generate 2 orders, one distinct and one not
            var (xOrder, calcOrder) = GenerateOrders();

            // - Convert text to bytes
            byte[] token = Encoding.UTF8.GetBytes(text);

            // — Create block
            byte[] iv = _key1.Take(BLOCK_SIZE).ToArray();

            byte[] cipher = EncryptCBC(token, iv, xOrder, calcOrder);

            string result = string.Concat(cipher.Select(b => b.ToString("X2")));
            string key = Convert.ToBase64String(
                _key1.Concat(_key2).Concat(_key3).Concat(_key4).ToArray()
            );

            return (key, result);
        }
    }
}