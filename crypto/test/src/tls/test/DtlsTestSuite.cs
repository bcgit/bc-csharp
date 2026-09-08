using System.Collections.Generic;

using NUnit.Framework;

namespace Org.BouncyCastle.Tls.Tests
{
    /// <summary>The <see cref="TlsTestSuite"/> cases, generated for the DTLS versions.</summary>
    public class DtlsTestSuite
    {
        public static IEnumerable<TestCaseData> Suite() =>
            TlsTestSuite.Generate(ProtocolVersion.DTLSv12.DownTo(ProtocolVersion.DTLSv10));
    }
}
