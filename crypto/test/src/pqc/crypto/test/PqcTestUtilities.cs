using System.Collections.Generic;
using System.IO;

using Org.BouncyCastle.Utilities.Test;

namespace Org.BouncyCastle.Pqc.Crypto.Tests
{
    internal class PqcTestUtilities
    {
        internal delegate void RunTestVector(string name, Dictionary<string, string> data);

        internal static void RunTestVectors(string path1, string path2, bool sampleOnly, RunTestVector runTestVector)
        {
            var data = new Dictionary<string, string>();
            var sampler = sampleOnly ? new TestSampler() : null;
            using (var src = new StreamReader(SimpleTest.FindTestResource(path1, path2)))
            {
                string line;
                while ((line = src.ReadLine()) != null)
                {
                    line = line.Trim();
                    if (line.StartsWith("#"))
                        continue;

                    if (line.Length > 0)
                    {
                        int a = line.IndexOf('=');
                        if (a >= 0)
                        {
                            data[line.Substring(0, a).Trim()] = line.Substring(a + 1).Trim();
                        }
                        continue;
                    }

                    if (data.Count > 0)
                    {
                        runTestVector(path2, data);
                        data.Clear();
                    }
                }

                if (data.Count > 0)
                {
                    runTestVector(path2, data);
                    data.Clear();
                }
            }
        }
    }
}
