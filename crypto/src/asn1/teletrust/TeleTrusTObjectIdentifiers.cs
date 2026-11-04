using System;

namespace Org.BouncyCastle.Asn1.TeleTrust
{
    /// <summary>Object identifiers for TeleTrusT.</summary>
    // TODO[api] Make static
    public sealed class TeleTrusTObjectIdentifiers
    {
        private TeleTrusTObjectIdentifiers()
        {
        }


        /// <summary>The object identifier <c>1.3.36</c>.</summary>
        public static readonly DerObjectIdentifier TeleTrusT = new DerObjectIdentifier("1.3.36");

        /// <summary>The object identifier <c>1.3.36.3</c>.</summary>
        public static readonly DerObjectIdentifier algorithm = TeleTrusT.Branch("3");
        /// <summary>The object identifier <c>1.3.36.3</c>.</summary>
        [Obsolete("Use 'algorithm' instead")]
        public static readonly DerObjectIdentifier TeleTrusTAlgorithm = algorithm;

        /// <summary>The object identifier <c>1.3.36.3.1</c>.</summary>
        public static readonly DerObjectIdentifier encryptionAlgorithm = algorithm.Branch("1");
        /// <summary>The object identifier <c>1.3.36.3.2</c>.</summary>
        public static readonly DerObjectIdentifier hashAlgorithm = algorithm.Branch("2");
        /// <summary>The object identifier <c>1.3.36.3.3</c>.</summary>
        public static readonly DerObjectIdentifier signatureAlgorithm = algorithm.Branch("3");
        /// <summary>The object identifier <c>1.3.36.3.4</c>.</summary>
        public static readonly DerObjectIdentifier signatureScheme = algorithm.Branch("4");

        /// <summary>The object identifier <c>1.3.36.3.2.1</c>.</summary>
        public static readonly DerObjectIdentifier RipeMD160 = hashAlgorithm.Branch("1");
        /// <summary>The object identifier <c>1.3.36.3.2.2</c>.</summary>
        public static readonly DerObjectIdentifier RipeMD128 = hashAlgorithm.Branch("2");
        /// <summary>The object identifier <c>1.3.36.3.2.3</c>.</summary>
        public static readonly DerObjectIdentifier RipeMD256 = hashAlgorithm.Branch("3");

        /// <summary>The object identifier <c>1.3.36.3.3.1</c>.</summary>
        public static readonly DerObjectIdentifier rsaSignature = signatureAlgorithm.Branch("1");
        /// <summary>The object identifier <c>1.3.36.3.3.1</c>.</summary>
        [Obsolete("Use 'rsaSignature' instead")]
        public static readonly DerObjectIdentifier TeleTrusTRsaSignatureAlgorithm = rsaSignature;

        /// <summary>The object identifier <c>1.3.36.3.3.1.2</c>.</summary>
        public static readonly DerObjectIdentifier RsaSignatureWithRipeMD160 = rsaSignature.Branch("2");
        /// <summary>The object identifier <c>1.3.36.3.3.1.3</c>.</summary>
        public static readonly DerObjectIdentifier RsaSignatureWithRipeMD128 = rsaSignature.Branch("3");
        /// <summary>The object identifier <c>1.3.36.3.3.1.4</c>.</summary>
        public static readonly DerObjectIdentifier RsaSignatureWithRipeMD256 = rsaSignature.Branch("4");

        /// <summary>The object identifier <c>1.3.36.3.3.2</c>.</summary>
        public static readonly DerObjectIdentifier ECSign = signatureAlgorithm.Branch("2");

        /// <summary>The object identifier <c>1.3.36.3.3.2.1</c>.</summary>
        public static readonly DerObjectIdentifier ECSignWithSha1 = ECSign.Branch("1");
        /// <summary>The object identifier <c>1.3.36.3.3.2.2</c>.</summary>
        public static readonly DerObjectIdentifier ECSignWithRipeMD160 = ECSign.Branch("2");
        /// <summary>The object identifier <c>1.3.36.3.3.2.3</c>.</summary>
        public static readonly DerObjectIdentifier ECSignWithMD2 = ECSign.Branch("3");
        /// <summary>The object identifier <c>1.3.36.3.3.2.4</c>.</summary>
        public static readonly DerObjectIdentifier ECSignWithMD5 = ECSign.Branch("4");
        /// <summary>The object identifier <c>1.3.36.3.3.2.5</c>.</summary>
        public static readonly DerObjectIdentifier ttt_ecg = ECSign.Branch("5");

        /// <summary>The object identifier <c>1.3.36.3.3.2.8</c>.</summary>
        public static readonly DerObjectIdentifier ecStdCurvesAndGeneration = ECSign.Branch("8");
        /// <summary>The object identifier <c>1.3.36.3.3.2.8</c>.</summary>
        [Obsolete("Use 'ecStdCurvesAndGeneration' instead")]
        public static readonly DerObjectIdentifier EccBrainpool = ecStdCurvesAndGeneration;

        /// <summary>The object identifier <c>1.3.36.3.3.2.8.1</c>.</summary>
        public static readonly DerObjectIdentifier EllipticCurve = ecStdCurvesAndGeneration.Branch("1");

        /// <summary>The object identifier <c>1.3.36.3.3.2.8.1.1</c>.</summary>
        public static readonly DerObjectIdentifier VersionOne = EllipticCurve.Branch("1");

        /// <summary>The object identifier <c>1.3.36.3.3.2.8.1.1.1</c>.</summary>
        public static readonly DerObjectIdentifier BrainpoolP160R1 = VersionOne.Branch("1");
        /// <summary>The object identifier <c>1.3.36.3.3.2.8.1.1.2</c>.</summary>
        public static readonly DerObjectIdentifier BrainpoolP160T1 = VersionOne.Branch("2");
        /// <summary>The object identifier <c>1.3.36.3.3.2.8.1.1.3</c>.</summary>
        public static readonly DerObjectIdentifier BrainpoolP192R1 = VersionOne.Branch("3");
        /// <summary>The object identifier <c>1.3.36.3.3.2.8.1.1.4</c>.</summary>
        public static readonly DerObjectIdentifier BrainpoolP192T1 = VersionOne.Branch("4");
        /// <summary>The object identifier <c>1.3.36.3.3.2.8.1.1.5</c>.</summary>
        public static readonly DerObjectIdentifier BrainpoolP224R1 = VersionOne.Branch("5");
        /// <summary>The object identifier <c>1.3.36.3.3.2.8.1.1.6</c>.</summary>
        public static readonly DerObjectIdentifier BrainpoolP224T1 = VersionOne.Branch("6");
        /// <summary>The object identifier <c>1.3.36.3.3.2.8.1.1.7</c>.</summary>
        public static readonly DerObjectIdentifier BrainpoolP256R1 = VersionOne.Branch("7");
        /// <summary>The object identifier <c>1.3.36.3.3.2.8.1.1.8</c>.</summary>
        public static readonly DerObjectIdentifier BrainpoolP256T1 = VersionOne.Branch("8");
        /// <summary>The object identifier <c>1.3.36.3.3.2.8.1.1.9</c>.</summary>
        public static readonly DerObjectIdentifier BrainpoolP320R1 = VersionOne.Branch("9");
        /// <summary>The object identifier <c>1.3.36.3.3.2.8.1.1.10</c>.</summary>
        public static readonly DerObjectIdentifier BrainpoolP320T1 = VersionOne.Branch("10");
        /// <summary>The object identifier <c>1.3.36.3.3.2.8.1.1.11</c>.</summary>
        public static readonly DerObjectIdentifier BrainpoolP384R1 = VersionOne.Branch("11");
        /// <summary>The object identifier <c>1.3.36.3.3.2.8.1.1.12</c>.</summary>
        public static readonly DerObjectIdentifier BrainpoolP384T1 = VersionOne.Branch("12");
        /// <summary>The object identifier <c>1.3.36.3.3.2.8.1.1.13</c>.</summary>
        public static readonly DerObjectIdentifier BrainpoolP512R1 = VersionOne.Branch("13");
        /// <summary>The object identifier <c>1.3.36.3.3.2.8.1.1.14</c>.</summary>
        public static readonly DerObjectIdentifier BrainpoolP512T1 = VersionOne.Branch("14");
    }
}
