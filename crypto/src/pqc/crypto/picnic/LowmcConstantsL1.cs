using System.Collections.Generic;
using System.IO;

namespace Org.BouncyCastle.Pqc.Crypto.Picnic
{
    internal class LowmcConstantsL1
        : LowmcConstants
    {
        public LowmcConstantsL1()
        {
            _matrixToHex = new Dictionary<string, string>();
            Stream input = typeof(LowmcConstants).Assembly
                .GetManifestResourceStream("Org.BouncyCastle.pqc.crypto.picnic.lowmcL1.properties");
            
            using (StreamReader sr = new StreamReader(input))
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

            // Parameters for security level L1
            // Block/key size: 128
            // Rounds: 20
            linearMatrices = ReadFromProperty(_matrixToHex["linearMatrices"], 40960);
            roundConstants = ReadFromProperty(_matrixToHex["roundConstants"], 320);
            keyMatrices = ReadFromProperty(_matrixToHex["keyMatrices"], 43008);
            _LMatrix = new KMatrices(20, 128, 4, linearMatrices);
            _KMatrix = new KMatrices(21, 128, 4, keyMatrices);
            RConstants = new KMatrices(0, 1, 4, roundConstants);

            // Parameters for security level L1, full s-box layer
            // Block/key size: 129
            // Rounds: 4
            // Note that each 129-bit row of the matrix is zero padded to 160 bits (the next multiple of 32)
            linearMatrices_full = ReadFromProperty(_matrixToHex["linearMatrices_full"], 12800);
            keyMatrices_full = ReadFromProperty(_matrixToHex["keyMatrices_full"], 12900);
            keyMatrices_inv = ReadFromProperty(_matrixToHex["keyMatrices_inv"], 2850);
            linearMatrices_inv = ReadFromProperty(_matrixToHex["linearMatrices_inv"], 12800);
            roundConstants_full = ReadFromProperty(_matrixToHex["roundConstants_full"], 80);
            LMatrix_full = new KMatrices(4, 129, 5, linearMatrices_full);
            LMatrix_inv = new KMatrices(4, 129, 5, linearMatrices_inv);
            KMatrix_full = new KMatrices(5, 129, 5, keyMatrices_full);
            KMatrix_inv = new KMatrices(1, 129, 5, keyMatrices_inv);
            RConstants_full = new KMatrices(4, 1, 5, roundConstants_full);
        }
    }
}