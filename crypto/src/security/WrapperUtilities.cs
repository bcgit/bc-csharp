using System;
using System.Collections.Generic;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Kisa;
using Org.BouncyCastle.Asn1.Nist;
using Org.BouncyCastle.Asn1.Nsri;
using Org.BouncyCastle.Asn1.Ntt;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.Collections;

namespace Org.BouncyCastle.Security
{
    /// <remarks>
    ///  Utility class for creating IWrapper objects from their names/Oids
    /// </remarks>
    public static class WrapperUtilities
    {
        private enum WrapAlgorithm
        {
            AESRFC3211WRAP,
            AESWRAP,
            AESWRAPPAD,
            ARIARFC3211WRAP,
            ARIAWRAP,
            ARIAWRAPPAD,
            CAMELLIARFC3211WRAP,
            CAMELLIAWRAP,
            DESRFC3211WRAP,
            DESEDERFC3211WRAP,
            DESEDEWRAP,
            RC2WRAP,
            SEEDWRAP,
        };

        private static readonly IDictionary<string, string> Algorithms =
            new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

        static WrapperUtilities()
        {
            // Signal to obfuscation tools not to change enum constants
            Enums.GetArbitraryValue<WrapAlgorithm>().ToString();

            Algorithms["AESKW"] = "AESWRAP";
            Algorithms[NistObjectIdentifiers.IdAes128Wrap.Id] = "AESWRAP";
            Algorithms[NistObjectIdentifiers.IdAes192Wrap.Id] = "AESWRAP";
            Algorithms[NistObjectIdentifiers.IdAes256Wrap.Id] = "AESWRAP";

            Algorithms["AESKWP"] = "AESWRAPPAD";
            Algorithms[NistObjectIdentifiers.IdAes128WrapPad.Id] = "AESWRAPPAD";
            Algorithms[NistObjectIdentifiers.IdAes192WrapPad.Id] = "AESWRAPPAD";
            Algorithms[NistObjectIdentifiers.IdAes256WrapPad.Id] = "AESWRAPPAD";
            Algorithms["AESRFC5649WRAP"] = "AESWRAPPAD";

            Algorithms["ARIAKW"] = "ARIAWRAP";
            Algorithms[NsriObjectIdentifiers.id_aria128_kw.Id] = "ARIAWRAP";
            Algorithms[NsriObjectIdentifiers.id_aria192_kw.Id] = "ARIAWRAP";
            Algorithms[NsriObjectIdentifiers.id_aria256_kw.Id] = "ARIAWRAP";

            Algorithms["ARIAKWP"] = "ARIAWRAPPAD";
            Algorithms[NsriObjectIdentifiers.id_aria128_kwp.Id] = "ARIAWRAPPAD";
            Algorithms[NsriObjectIdentifiers.id_aria192_kwp.Id] = "ARIAWRAPPAD";
            Algorithms[NsriObjectIdentifiers.id_aria256_kwp.Id] = "ARIAWRAPPAD";

            Algorithms[NttObjectIdentifiers.IdCamellia128Wrap.Id] = "CAMELLIAWRAP";
            Algorithms[NttObjectIdentifiers.IdCamellia192Wrap.Id] = "CAMELLIAWRAP";
            Algorithms[NttObjectIdentifiers.IdCamellia256Wrap.Id] = "CAMELLIAWRAP";

            Algorithms["DESEDERFC3217WRAP"] = "DESEDEWRAP";
            Algorithms["TDEAWRAP"] = "DESEDEWRAP";
            Algorithms[PkcsObjectIdentifiers.IdAlgCms3DesWrap.Id] = "DESEDEWRAP";

            Algorithms[PkcsObjectIdentifiers.IdAlgCmsRC2Wrap.Id] = "RC2WRAP";

            Algorithms["SEEDKW"] = "SEEDWRAP";
            Algorithms[KisaObjectIdentifiers.IdNpkiAppCmsSeedWrap.Id] = "SEEDWRAP";
        }

        public static IWrapper GetWrapper(DerObjectIdentifier oid)
        {
            return GetWrapper(oid.Id);
        }

        public static IWrapper GetWrapper(string algorithm)
        {
            string mechanism = CollectionUtilities.GetValueOrKey(Algorithms, algorithm).ToUpperInvariant();

            if (Enums.TryGetEnumValue<WrapAlgorithm>(mechanism, out var wrapAlgorithm))
            {
                switch (wrapAlgorithm)
                {
                case WrapAlgorithm.AESRFC3211WRAP:
                    return new Rfc3211WrapEngine(AesUtilities.CreateEngine());
                case WrapAlgorithm.AESWRAP:
                    return new AesWrapEngine();
                case WrapAlgorithm.AESWRAPPAD:
                    return new AesWrapPadEngine();
                case WrapAlgorithm.ARIARFC3211WRAP:
                    return new Rfc3211WrapEngine(new AriaEngine());
                case WrapAlgorithm.ARIAWRAP:
                    return new AriaWrapEngine();
                case WrapAlgorithm.ARIAWRAPPAD:
                    return new AriaWrapPadEngine();
                case WrapAlgorithm.CAMELLIARFC3211WRAP:
                    return new Rfc3211WrapEngine(new CamelliaEngine());
                case WrapAlgorithm.CAMELLIAWRAP:
                    return new CamelliaWrapEngine();
                case WrapAlgorithm.DESRFC3211WRAP:
                    return new Rfc3211WrapEngine(new DesEngine());
                case WrapAlgorithm.DESEDERFC3211WRAP:
                    return new Rfc3211WrapEngine(new DesEdeEngine());
                case WrapAlgorithm.DESEDEWRAP:
                    return new DesEdeWrapEngine();
                case WrapAlgorithm.RC2WRAP:
                    return new RC2WrapEngine();
                case WrapAlgorithm.SEEDWRAP:
                    return new SeedWrapEngine();
                default:
                    throw new NotImplementedException();
                }
            }

            // Create an IBufferedCipher and use it as IWrapper (via BufferedCipherWrapper)
            IBufferedCipher blockCipher = CipherUtilities.GetCipher(algorithm);

            if (blockCipher != null)
                return new BufferedCipherWrapper(blockCipher);

            throw new SecurityUtilityException("Wrapper " + algorithm + " not recognised.");
        }

        public static string GetAlgorithmName(DerObjectIdentifier oid)
        {
            return CollectionUtilities.GetValueOrNull(Algorithms, oid.Id);
        }

        private class BufferedCipherWrapper
            : IWrapper
        {
            private readonly IBufferedCipher cipher;
            private bool forWrapping;

            public BufferedCipherWrapper(
                IBufferedCipher cipher)
            {
                this.cipher = cipher;
            }

            public string AlgorithmName
            {
                get { return cipher.AlgorithmName; }
            }

            public void Init(
                bool				forWrapping,
                ICipherParameters	parameters)
            {
                this.forWrapping = forWrapping;

                cipher.Init(forWrapping, parameters);
            }

            public byte[] Wrap(
                byte[]	input,
                int		inOff,
                int		length)
            {
                if (!forWrapping)
                    throw new InvalidOperationException("Not initialised for wrapping");

                return cipher.DoFinal(input, inOff, length);
            }

            public byte[] Unwrap(
                byte[]	input,
                int		inOff,
                int		length)
            {
                if (forWrapping)
                    throw new InvalidOperationException("Not initialised for unwrapping");

                return cipher.DoFinal(input, inOff, length);
            }
        }
    }
}
