using System;

using Org.BouncyCastle.Asn1;

namespace Org.BouncyCastle.Asn1.X509.Qualified
{
    /// <summary>Object identifiers for the qualified certificate statements of RFC 3739.</summary>
    // TODO[api] Make static
    public sealed class Rfc3739QCObjectIdentifiers
    {
        private Rfc3739QCObjectIdentifiers()
        {
        }

        /// <summary>The object identifier <c>1.3.6.1.5.5.7.11</c>.</summary>
        //
        // base id
        //
        public static readonly DerObjectIdentifier IdQcs = X509ObjectIdentifiers.IdPkix.Branch("11");

        /// <summary>The object identifier <c>1.3.6.1.5.5.7.11.1</c>.</summary>
        public static readonly DerObjectIdentifier IdQcsPkixQCSyntaxV1 = IdQcs.Branch("1");
        /// <summary>The object identifier <c>1.3.6.1.5.5.7.11.2</c>.</summary>
        public static readonly DerObjectIdentifier IdQcsPkixQCSyntaxV2 = IdQcs.Branch("2");
    }
}
