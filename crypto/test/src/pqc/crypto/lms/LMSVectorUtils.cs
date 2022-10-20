using System.IO;

using Org.BouncyCastle.Utilities.Encoders;

namespace Org.BouncyCastle.Pqc.Crypto.Lms
{
    public class LMSVectorUtils
    {
        public static byte[] ExtractPrefixedBytes(string vectorFromRFC)
        {
            MemoryStream bos = new MemoryStream();
            byte[] hexByte;
            foreach (string line in vectorFromRFC.Split('\n'))
            {
                int start = line.IndexOf('$');
                if (start > -1)
                {
                    ++start;
                    int end = line.IndexOf('#');
                    string hex;
                    if (end < 0)
                    {
                        hex = line.Substring(start).Trim();
                    }
                    else
                    {
                        hex = line.Substring(start, end - start).Trim();
                    }

                    hexByte = Hex.Decode(hex);
                    bos.Write(hexByte, 0, hexByte.Length);
                }
            }
            return bos.ToArray();
        }
    }
}
