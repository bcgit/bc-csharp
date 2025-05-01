using System;

namespace Org.BouncyCastle.Asn1.TeleTrust
{
    // TODO[api] Make static
    public sealed class TeleTrusTObjectIdentifiers
    {
        private TeleTrusTObjectIdentifiers()
        {
        }


        public static readonly DerObjectIdentifier TeleTrusT = new DerObjectIdentifier("1.3.36");

        public static readonly DerObjectIdentifier algorithm = TeleTrusT.Branch("3");
        [Obsolete("Use 'algorithm' instead")]
        public static readonly DerObjectIdentifier TeleTrusTAlgorithm = algorithm;

        public static readonly DerObjectIdentifier encryptionAlgorithm = algorithm.Branch("1");
        public static readonly DerObjectIdentifier hashAlgorithm = algorithm.Branch("2");
        public static readonly DerObjectIdentifier signatureAlgorithm = algorithm.Branch("3");
        public static readonly DerObjectIdentifier signatureScheme = algorithm.Branch("4");

        public static readonly DerObjectIdentifier RipeMD160 = hashAlgorithm.Branch("1");
        public static readonly DerObjectIdentifier RipeMD128 = hashAlgorithm.Branch("2");
        public static readonly DerObjectIdentifier RipeMD256 = hashAlgorithm.Branch("3");

        public static readonly DerObjectIdentifier rsaSignature = signatureAlgorithm.Branch("1");
        [Obsolete("Use 'rsaSignature' instead")]
        public static readonly DerObjectIdentifier TeleTrusTRsaSignatureAlgorithm = rsaSignature;

        public static readonly DerObjectIdentifier RsaSignatureWithRipeMD160 = rsaSignature.Branch("2");
        public static readonly DerObjectIdentifier RsaSignatureWithRipeMD128 = rsaSignature.Branch("3");
        public static readonly DerObjectIdentifier RsaSignatureWithRipeMD256 = rsaSignature.Branch("4");

        public static readonly DerObjectIdentifier ECSign = signatureAlgorithm.Branch("2");

        public static readonly DerObjectIdentifier ECSignWithSha1 = ECSign.Branch("1");
        public static readonly DerObjectIdentifier ECSignWithRipeMD160 = ECSign.Branch("2");
        public static readonly DerObjectIdentifier ECSignWithMD2 = ECSign.Branch("3");
        public static readonly DerObjectIdentifier ECSignWithMD5 = ECSign.Branch("4");
        public static readonly DerObjectIdentifier ttt_ecg = ECSign.Branch("5");

        public static readonly DerObjectIdentifier ecStdCurvesAndGeneration = ECSign.Branch("8");
        [Obsolete("Use 'ecStdCurvesAndGeneration' instead")]
        public static readonly DerObjectIdentifier EccBrainpool = ecStdCurvesAndGeneration;

        public static readonly DerObjectIdentifier EllipticCurve = ecStdCurvesAndGeneration.Branch("1");

        public static readonly DerObjectIdentifier VersionOne = EllipticCurve.Branch("1");

        public static readonly DerObjectIdentifier BrainpoolP160R1 = VersionOne.Branch("1");
        public static readonly DerObjectIdentifier BrainpoolP160T1 = VersionOne.Branch("2");
        public static readonly DerObjectIdentifier BrainpoolP192R1 = VersionOne.Branch("3");
        public static readonly DerObjectIdentifier BrainpoolP192T1 = VersionOne.Branch("4");
        public static readonly DerObjectIdentifier BrainpoolP224R1 = VersionOne.Branch("5");
        public static readonly DerObjectIdentifier BrainpoolP224T1 = VersionOne.Branch("6");
        public static readonly DerObjectIdentifier BrainpoolP256R1 = VersionOne.Branch("7");
        public static readonly DerObjectIdentifier BrainpoolP256T1 = VersionOne.Branch("8");
        public static readonly DerObjectIdentifier BrainpoolP320R1 = VersionOne.Branch("9");
        public static readonly DerObjectIdentifier BrainpoolP320T1 = VersionOne.Branch("10");
        public static readonly DerObjectIdentifier BrainpoolP384R1 = VersionOne.Branch("11");
        public static readonly DerObjectIdentifier BrainpoolP384T1 = VersionOne.Branch("12");
        public static readonly DerObjectIdentifier BrainpoolP512R1 = VersionOne.Branch("13");
        public static readonly DerObjectIdentifier BrainpoolP512T1 = VersionOne.Branch("14");
    }
}
