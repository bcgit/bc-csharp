using System.IO;
using System.Text;

using NUnit.Framework;

using Org.BouncyCastle.Bcpg;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.IO;

namespace Org.BouncyCastle.Bcpg.OpenPgp.Tests
{
    /// <summary>
    /// Regression test for ASCII-armor header injection via a bare carriage return. Armor header
    /// values were written verbatim, so a CR embedded in a value (e.g. a parsed User-ID re-armored
    /// as a Comment) survived into a single header line and could forge an armor boundary or an
    /// extra header for a reader that treats CR as end-of-line. Mirrors bc-java commit 02592d7173.
    /// </summary>
    [TestFixture]
    public class ArmoredOutputStreamInjectionTest
    {
        private static readonly string[] LineSeparators = new string[]{ "\r\n", "\r", "\n" };

        [Test]
        public void HeaderValueWithBareCarriageReturnCannotForgeArmorLine()
        {
            byte[] data = new byte[]{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9 };

            var bOut = new MemoryStream();
            using (var aOut = new ArmoredOutputStream(bOut, addVersionHeader: false))
            {
                // A Comment value carrying a bare CR followed by a forged header. Without the fix the
                // CR survives into one header line; a CR-as-EOL reader then sees "Injected: forged".
                aOut.SetHeader("Comment", "note\rInjected: forged");
                aOut.Write(data, 0, data.Length);
            }

            string armored = Encoding.ASCII.GetString(bOut.ToArray());

            // Re-split the way a lenient (CR-as-EOL) reader would: on CR, LF and CRLF. No physical
            // line may be the forged header -- the bare CR must have been neutralised by splitting.
            foreach (string line in armored.Split(LineSeparators, System.StringSplitOptions.None))
            {
                Assert.That(line.StartsWith("Injected:"), Is.False,
                    "armor header injection: a bare CR in a header value forged a line: " + line);
            }

            // The sanitized armor must still round-trip through the real reader.
            using (var aIn = new ArmoredInputStream(new MemoryStream(bOut.ToArray())))
            {
                byte[] recovered = Streams.ReadAll(aIn);
                Assert.That(Arrays.AreEqual(data, recovered), Is.True, "armored round-trip failed");
            }
        }
    }
}
