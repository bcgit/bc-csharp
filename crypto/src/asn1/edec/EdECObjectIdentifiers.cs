using System;

namespace Org.BouncyCastle.Asn1.EdEC
{
    /**
     * Edwards Elliptic Curve Object Identifiers (RFC 8410)
     */
    // TODO[api] Make static
    public abstract class EdECObjectIdentifiers
    {
        /// <summary>The object identifier <c>1.3.101</c>.</summary>
        public static readonly DerObjectIdentifier id_edwards_curve_algs = new DerObjectIdentifier("1.3.101");

        /// <summary>The object identifier <c>1.3.101.110</c>.</summary>
        public static readonly DerObjectIdentifier id_X25519 = id_edwards_curve_algs.Branch("110");
        /// <summary>The object identifier <c>1.3.101.111</c>.</summary>
        public static readonly DerObjectIdentifier id_X448 = id_edwards_curve_algs.Branch("111");
        /// <summary>The object identifier <c>1.3.101.112</c>.</summary>
        public static readonly DerObjectIdentifier id_Ed25519 = id_edwards_curve_algs.Branch("112");
        /// <summary>The object identifier <c>1.3.101.113</c>.</summary>
        public static readonly DerObjectIdentifier id_Ed448 = id_edwards_curve_algs.Branch("113");
    }
}
