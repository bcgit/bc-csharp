using Org.BouncyCastle.Utilities.IO.Compression;
using System.Collections.Generic;
using System.IO;

namespace Org.BouncyCastle.Pqc.Crypto.Picnic
{
    internal class LowmcConstantsL3
        : LowmcConstants
    {
        public LowmcConstantsL3()
        {
            _matrixToHex = new Dictionary<string, string>();
            using (var input = typeof(LowmcConstants).Assembly.GetManifestResourceStream(
                "Org.BouncyCastle.pqc.crypto.picnic.lowmcL3.bz2"))
            using (var sr = new StreamReader(Bzip2.DecompressInput(input)))
            {
                // load a properties file
                string line = sr.ReadLine();
                string matrix, hexString;

                while (line != null)
                {
                    string header = line;
                    if (header != "")
                    {
                        header = header.Replace(",", "");
                        int index = header.IndexOf('=');
                        matrix = header.Substring(0, index).Trim();
                        hexString = header.Substring(index + 1).Trim();
                        _matrixToHex.Add(matrix, hexString);
                    }

                    line = sr.ReadLine();
                }
            }

            // Parameters for security level L3
            // Block/key size: 192
            // Rounds: 30
            linearMatrices = ReadFromProperty(_matrixToHex["linearMatrices"], 138240);
            roundConstants = ReadFromProperty(_matrixToHex["roundConstants"], 720);
            keyMatrices = ReadFromProperty(_matrixToHex["keyMatrices"], 142848);
            _LMatrix = new KMatrices(30, 192, 6, linearMatrices);
            _KMatrix = new KMatrices(31, 192, 6, keyMatrices);
            RConstants = new KMatrices(30, 1, 6, roundConstants);

            // Parameters for security level L3, full s-box layer
            // Block/key size: 192
            // S-boxes: 64
            // Rounds: 4
            linearMatrices_full = ReadFromProperty(_matrixToHex["linearMatrices_full"], 18432);
            linearMatrices_inv = ReadFromProperty(_matrixToHex["linearMatrices_inv"], 18432);
            roundConstants_full = ReadFromProperty(_matrixToHex["roundConstants_full"], 96);
            keyMatrices_full = ReadFromProperty(_matrixToHex["keyMatrices_full"], 23040);
            keyMatrices_inv = ReadFromProperty(_matrixToHex["keyMatrices_inv"], 4608);
            LMatrix_full = new KMatrices(4, 192, 6, linearMatrices_full);
            LMatrix_inv = new KMatrices(4, 192, 6, linearMatrices_inv);
            KMatrix_full = new KMatrices(5, 192, 6, keyMatrices_full);
            KMatrix_inv = new KMatrices(1, 192, 6, keyMatrices_inv);
            RConstants_full = new KMatrices(4, 1, 6, roundConstants_full);
        }
    }
}