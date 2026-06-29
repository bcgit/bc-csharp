using System;
using System.Collections.Generic;
using System.IO;

using NUnit.Framework;

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
        public void All()
        {
            byte[] data = Strings.ToByteArray("the quick brown fox");

            // A Comment value carrying a bare CR followed by a forged armor tail. Splitting on CR turns
            // it into separate, well-formed "Comment:" headers, so the armor re-parses cleanly. Without
            // the fix the CR survives into one header line and BouncyCastle's own reader -- which treats
            // a lone CR as end-of-line -- rejects the armor as malformed (a round-trip denial of service).
            MemoryStream bOut = new MemoryStream();
            using (ArmoredOutputStream aOut = ArmoredOutputStream.Build()
                .AddComment("note\r-----END PGP MESSAGE-----")
                .Build(bOut))
            {
                aOut.Write(data, 0, data.Length);
            }

            byte[] recovered;
            using (ArmoredInputStream aIn = new ArmoredInputStream(new MemoryStream(bOut.ToArray(), false)))
            {
                recovered = Streams.ReadAll(aIn);
            }

            Assert.That(Arrays.AreEqual(data, recovered), "armored round-trip with an embedded CR in a comment failed");

            // A singleton header value containing a bare CR must be rejected, as one containing LF is.
            try
            {
                ArmoredOutputStream.Build()
                    .SetVersion("v\rInjected: forged")
                    .Build(new MemoryStream());
                Assert.Fail("CR in singleton armor header value accepted");
            }
            catch (ArgumentException)
            {
                // expected
            }

            // The deprecated setHeader(...) stores the value raw and emits it through the same
            // writeHeaderEntry chokepoint as the Builder. A LF in the value used to inject a second
            // parsed armor header; it must now be rejected when the header block is flushed on first
            // write. This is the path finding #25's proof exercised.
            try
            {
                ArmoredOutputStream injected = new ArmoredOutputStream(new MemoryStream());
#pragma warning disable CS0618 // Type or member is obsolete
                injected.SetHeader("Comment", "hello\nInjected: smuggled-header");
#pragma warning restore CS0618 // Type or member is obsolete
                injected.WriteByte(0x01);
                Assert.Fail("LF in deprecated setHeader value accepted");
            }
            catch (ArgumentException e)
            {
                Assert.NotNull(e.Message);
                Assert.AreEqual("armor header must not contain CR/LF", e.Message, "unexpected message: " + e.Message);
            }

            // The Hashtable constructor is the other raw, non-deprecated path through the chokepoint;
            // a bare CR in a value must be rejected there too.
            var rawHeaders = new Dictionary<string, string>(){
                { ArmoredOutputStream.HeaderComment, "hello\r-----END PGP MESSAGE-----" },
            };

            try
            {
                ArmoredOutputStream injected = new ArmoredOutputStream(new MemoryStream(), rawHeaders);
                injected.WriteByte(0x01);
                Assert.Fail("CR in Hashtable-constructor header value accepted");
            }
            catch (ArgumentException e)
            {
                Assert.NotNull(e.Message);
                Assert.AreEqual("armor header must not contain CR/LF", e.Message, "unexpected message: " + e.Message);
            }
        }
    }
}
