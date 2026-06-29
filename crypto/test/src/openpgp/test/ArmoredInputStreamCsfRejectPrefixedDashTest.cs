using System.IO;

using NUnit.Framework;

using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.IO;

namespace Org.BouncyCastle.Bcpg.OpenPgp.Tests
{
    /// <summary>
    /// Regression test for the cleartext signature framework (CSF) dash-escape handling of
    /// <see cref="ArmoredInputStream"/>.
    /// </summary>
    /// <remarks>
    /// A payload line beginning with a dash must be dash-escaped as "- " per RFC 4880 7.1; the stream previously
    /// dropped the two leading characters unconditionally, so a signature over "payload" also verified against a
    /// tampered "-Xpayload" line.
    /// </remarks>
    /// <seealso href="https://github.com/bcgit/bc-java/pull/2329"/>
    [TestFixture]
    public class ArmoredInputStreamCsfRejectPrefixedDashTest
    {
        private static readonly string MessageMismatch = "Exception message mismatch";
        private static readonly string RejectMessage =
            "Prefixed dash without trailing space encountered. CSF-signed message malformed.";

        // A cleartext-signed message whose payload line "-Xpayload" begins with a dash that is
        // neither a "-----" armor header nor a "- " dash-escape: malformed per RFC 4880 7.1.
        // The signature was created over "payload".
        private static readonly string Malformed =
            "-----BEGIN PGP SIGNED MESSAGE-----\n" +
            "Hash: SHA512\n" +
            "\n" +
            "-Xpayload\n" +
            "-----BEGIN PGP SIGNATURE-----\n" +
            "Version: PGPainless\n" +
            "\n" +
            "wnUEABYKACcFgmoz+AoJEF0ybVyS+fXHFqEE/9HfXX3exPsb+/QfXTJtXJL59ccA\n" +
            "AMmDAP4yxWVmaDycXXgNWuKtyHmWegY+TAQoS2FCrg0KZO/kuQEAnvg8YxQLcL7I\n" +
            "WbRs9RZtPLc+jgUKBbz/bode8TkqyQU=\n" +
            "=PIAb\n" +
            "-----END PGP SIGNATURE-----";

        [Test]
        public void RejectsMalformedWhenConfigured()
        {
            ArmoredInputStream aIn = ArmoredInputStream.Build()
                .SetRejectPrefixedDashesInCsfMessages(true)
                .Build(new MemoryStream(Strings.ToUtf8ByteArray(Malformed), false));

            try
            {
                Streams.Drain(aIn);
                Assert.Fail("Prefixed dash in CSF message MUST be rejected if configured to do so.");
            }
            catch (ArmoredInputException e)
            {
                Assert.AreEqual(RejectMessage, e.Message, MessageMismatch);
            }
        }

        [Test]
        public void RejectsMalformedByDefault()
        {
            // The default builder (no explicit configuration) must reject too: rejecting the
            // malformed message is the secure default.
            ArmoredInputStream aIn = ArmoredInputStream.Build()
                .Build(new MemoryStream(Strings.ToUtf8ByteArray(Malformed), false));

            try
            {
                Streams.Drain(aIn);
                Assert.Fail("Prefixed dash in CSF message MUST be rejected by default.");
            }
            catch (ArmoredInputException e)
            {
                Assert.AreEqual(RejectMessage, e.Message, MessageMismatch);
            }
        }

        [Test]
        public void SurfacesMalformedBytesWhenLenient()
        {
            ArmoredInputStream aIn = ArmoredInputStream.Build()
                .SetRejectPrefixedDashesInCsfMessages(false)
                .Build(new MemoryStream(Strings.ToUtf8ByteArray(Malformed), false));

            MemoryStream bOut = new MemoryStream();
            while (aIn.IsClearText())
            {
                bOut.WriteByte((byte)aIn.ReadByte());
            }

            string result = Strings.FromUtf8ByteArray(bOut.ToArray());

            // The leading dash is no longer silently dropped - the bytes are surfaced verbatim,
            // so a signature check over the recovered text fails instead of spuriously passing.
            Assert.That(result.StartsWith("-Xpayload"), "Malformed payload MUST be returned unaltered");
        }

        [Test]
        public void LenientStreamStillDetectsArmorBoundary()
        {
            // A malformed lone-dash line ("-") immediately before the signature boundary used to
            // corrupt the new-line tracking in lenient mode, so the stream never left the
            // clear-text section and consumed the whole signature block. Verify the look-ahead
            // byte is run through the new-line state machine.
            string trailingDash =
                "-----BEGIN PGP SIGNED MESSAGE-----\n" +
                "Hash: SHA512\n" +
                "\n" +
                "payload\n" +
                "-\n" +
                "-----BEGIN PGP SIGNATURE-----\n" +
                "Version: PGPainless\n" +
                "\n" +
                "wnUEABYKACcFgmoz+AoJEF0ybVyS+fXHFqEE/9HfXX3exPsb+/QfXTJtXJL59ccA\n" +
                "AMmDAP4yxWVmaDycXXgNWuKtyHmWegY+TAQoS2FCrg0KZO/kuQEAnvg8YxQLcL7I\n" +
                "WbRs9RZtPLc+jgUKBbz/bode8TkqyQU=\n" +
                "=PIAb\n" +
                "-----END PGP SIGNATURE-----";

            ArmoredInputStream aIn = ArmoredInputStream.Build()
                .SetRejectPrefixedDashesInCsfMessages(false)
                .Build(new MemoryStream(Strings.ToUtf8ByteArray(trailingDash), false));

            MemoryStream bOut = new MemoryStream();
            int count = 0;
            while (aIn.IsClearText() && count++ < 1000)
            {
                int ch = aIn.ReadByte();
                if (ch < 0)
                    break;

                bOut.WriteByte((byte)ch);
            }

            string result = Strings.FromUtf8ByteArray(bOut.ToArray());

            Assert.False(result.Contains("BEGIN PGP SIGNATURE"),
                "clear-text section must stop at the armor boundary, not consume the signature");
            Assert.True(result.StartsWith("payload\n-\n"),
                "malformed lone-dash payload must be surfaced verbatim");
        }
    }
}
