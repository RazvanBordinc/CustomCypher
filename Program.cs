using EncodingAlgorithm.Algorithm;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.RegularExpressions;

namespace EncodingAlgorithm
{
    public class Program
    {
        public static void Main(string[] args)
        {
            string hello = "Testing crypting alg";
            CustomCypher customCypher = new CustomCypher();

            var (key, result) = customCypher.EncodeALG(hello);

            Console.WriteLine($"Result: {result}");
            Console.WriteLine($"\n\n`Key: {key}");
 
            Console.WriteLine("\n\n\n--- Decryption Test ---\n\n\n");
            string decrypted = customCypher.Decode(result, key);
            Console.WriteLine(decrypted);
 
        }
    }
}