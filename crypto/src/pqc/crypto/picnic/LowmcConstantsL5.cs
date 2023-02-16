using Org.BouncyCastle.Utilities.IO.Compression;
using System.Collections.Generic;
using System.IO;

namespace Org.BouncyCastle.Pqc.Crypto.Picnic
{

    internal class LowmcConstantsL5
        : LowmcConstants
    {
        public LowmcConstantsL5()
        {
            _matrixToHex = new Dictionary<string, string>();
            Stream input = typeof(LowmcConstants).Assembly
                .GetManifestResourceStream("Org.BouncyCastle.pqc.crypto.picnic.lowmcL5.bz2");
            input = Bzip2.DecompressInput(input);

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

            // Parameters for security level L5
            // Block/key size: 256
            // Rounds: 38
            linearMatrices = ReadFromProperty(_matrixToHex["linearMatrices"], 311296);
            roundConstants = ReadFromProperty(_matrixToHex["roundConstants"], 1216);
            keyMatrices = ReadFromProperty(_matrixToHex["keyMatrices"], 319488);
            _LMatrix = new KMatrices(38, 256, 8, linearMatrices);
            _KMatrix = new KMatrices(39, 256, 8, keyMatrices);
            RConstants = new KMatrices(38, 1, 8, roundConstants);

            // Parameters for security level L5, full nonlinear layer
            // Block/key size: 255
            // S-boxes: 85
            // Rounds: 4
            linearMatrices_full = ReadFromProperty(_matrixToHex["linearMatrices_full"], 32768);
            linearMatrices_inv = ReadFromProperty(_matrixToHex["linearMatrices_inv"], 32768);
            roundConstants_full = ReadFromProperty(_matrixToHex["roundConstants_full"], 128);
            keyMatrices_full = ReadFromProperty(_matrixToHex["keyMatrices_full"], 40960);
            keyMatrices_inv = ReadFromProperty(_matrixToHex["keyMatrices_inv"], 8160);
            LMatrix_full = new KMatrices(4, 255, 8, linearMatrices_full);
            LMatrix_inv = new KMatrices(4, 255, 8, linearMatrices_inv);
            KMatrix_full = new KMatrices(5, 255, 8, keyMatrices_full);
            KMatrix_inv = new KMatrices(1, 255, 8, keyMatrices_inv);
            RConstants_full = new KMatrices(4, 1, 8, roundConstants_full);

        }
    }
}