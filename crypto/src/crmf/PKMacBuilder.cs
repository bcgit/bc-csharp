using System;
using System.IO;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Cmp;
using Org.BouncyCastle.Asn1.Iana;
using Org.BouncyCastle.Asn1.Oiw;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.IO;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Crmf
{
    internal sealed class PKMacFactory
        : IMacFactory
    {
        private readonly KeyParameter m_key;
        private readonly PbmParameter m_parameters;

        public PKMacFactory(byte[] key, PbmParameter parameters)
        {
            m_key = new KeyParameter(key);
            m_parameters = parameters;
        }

        public object AlgorithmDetails =>
            new AlgorithmIdentifier(CmpObjectIdentifiers.passwordBasedMac, m_parameters);

        public IStreamCalculator<IBlockResult> CreateCalculator()
        {
            IMac mac = MacUtilities.GetMac(m_parameters.Mac.Algorithm);
            mac.Init(m_key);
            return new DefaultMacCalculator(mac);
        }
    }

    public class PKMacBuilder
    {
        private AlgorithmIdentifier owf;
        private AlgorithmIdentifier mac;
        private IPKMacPrimitivesProvider provider;
        private SecureRandom random;
        private PbmParameter parameters;
        private int iterationCount;
        private int saltLength = 20;
        private int maxIterations;

        /// <summary>
        /// Default, IterationCount = 1000, OIW=IdSha1, Mac=HmacSHA1
        /// </summary>
        public PKMacBuilder()
            :   this(new AlgorithmIdentifier(OiwObjectIdentifiers.IdSha1), 1000,
                    new AlgorithmIdentifier(IanaObjectIdentifiers.HmacSha1, DerNull.Instance),
                    new DefaultPKMacPrimitivesProvider())
        {
        }

        /// <summary>
        /// Defaults with IPKMacPrimitivesProvider
        /// </summary>
        /// <param name="provider"></param>
        public PKMacBuilder(IPKMacPrimitivesProvider provider)
            :   this(new AlgorithmIdentifier(OiwObjectIdentifiers.IdSha1), 1000,
                    new AlgorithmIdentifier(IanaObjectIdentifiers.HmacSha1, DerNull.Instance), provider)
        {
        }

        /// <summary>
        /// Create.
        /// </summary>
        /// <param name="provider">The Mac provider</param>
        /// <param name="digestAlgorithmIdentifier">Digest Algorithm Id</param>
        /// <param name="macAlgorithmIdentifier">Mac Algorithm Id</param>
        public PKMacBuilder(IPKMacPrimitivesProvider provider, AlgorithmIdentifier digestAlgorithmIdentifier,
            AlgorithmIdentifier macAlgorithmIdentifier)
            : this(digestAlgorithmIdentifier, 1000, macAlgorithmIdentifier, provider)
        {
        }

        /// <summary>
        /// Create a PKMAC builder enforcing a ceiling on the maximum iteration count.
        /// </summary>
        /// <param name="provider">supporting calculator</param>
        /// <param name="maxIterations">max allowable value for iteration count.</param>
        public PKMacBuilder(IPKMacPrimitivesProvider provider, int maxIterations)
        {
            this.provider = provider;
            this.maxIterations = maxIterations;
        }

        private PKMacBuilder(AlgorithmIdentifier digestAlgorithmIdentifier, int iterationCount,
            AlgorithmIdentifier macAlgorithmIdentifier, IPKMacPrimitivesProvider provider)
        {
            this.iterationCount = iterationCount;
            this.mac = macAlgorithmIdentifier;
            this.owf = digestAlgorithmIdentifier;
            this.provider = provider;
        }

        /**
         * Set the salt length in octets.
         *
         * @param saltLength length in octets of the salt to be generated.
         * @return the generator
         */
        public PKMacBuilder SetSaltLength(int saltLength)
        {
            if (saltLength < 8)
                throw new ArgumentException("salt length must be at least 8 bytes");

            this.saltLength = saltLength;

            return this;
        }

        /// <summary>
        /// Set the iteration count.
        /// </summary>
        /// <param name="iterationCount">the iteration count.</param>
        /// <returns>this</returns>
        /// <exception cref="ArgumentException">if iteration count is less than 100</exception>
        public PKMacBuilder SetIterationCount(int iterationCount)
        {
            if (iterationCount < 100)
                throw new ArgumentException("iteration count must be at least 100");

            CheckIterationCountCeiling(iterationCount);

            this.iterationCount = iterationCount;

            return this;
        }

        /// <summary>
        /// The Secure random
        /// </summary>
        /// <param name="random">The random.</param>
        /// <returns>this</returns>
        public PKMacBuilder SetSecureRandom(SecureRandom random)
        {
            this.random = random;

            return this;
        }

        /// <summary>
        /// Set PbmParameters
        /// </summary>
        /// <param name="parameters">The parameters.</param>
        /// <returns>this</returns>
        public PKMacBuilder SetParameters(PbmParameter parameters)
        {
            CheckIterationCountCeiling(parameters.IterationCount.IntValueExact);

            this.parameters = parameters;

            return this;
        }

        public IMacFactory Get(AlgorithmIdentifier algorithm, char[] password)
        {
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            return Get(algorithm, password.AsSpan());
#else
            if (!CmpObjectIdentifiers.passwordBasedMac.Equals(algorithm.Algorithm))
                throw new ArgumentException("protection algorithm not mac based", nameof(algorithm));

            SetParameters(PbmParameter.GetInstance(algorithm.Parameters));

            return Build(password);
#endif
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public IMacFactory Get(AlgorithmIdentifier algorithm, ReadOnlySpan<char> password)
        {
            if (!CmpObjectIdentifiers.passwordBasedMac.Equals(algorithm.Algorithm))
                throw new ArgumentException("protection algorithm not mac based", nameof(algorithm));

            SetParameters(PbmParameter.GetInstance(algorithm.Parameters));

            return Build(password);
        }
#endif

        /// <summary>
        /// Build an IMacFactory.
        /// </summary>
        /// <param name="password">The password.</param>
        /// <returns>IMacFactory</returns>
        public IMacFactory Build(char[] password)
        {
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            return Build(password.AsSpan());
#else
            PbmParameter pbmParameter = parameters;
            if (pbmParameter == null)
            {
                pbmParameter = GenParameters();
            }

            return GenCalculator(pbmParameter, password);
#endif
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public IMacFactory Build(ReadOnlySpan<char> password)
        {
            PbmParameter pbmParameter = parameters;
            if (pbmParameter == null)
            {
                pbmParameter = GenParameters();
            }

            return GenCalculator(pbmParameter, password);
        }
#endif

        private void CheckIterationCountCeiling(int iterationCount)
        {
            if (maxIterations > 0 && iterationCount > maxIterations)
                throw new ArgumentException("iteration count exceeds limit (" + iterationCount + " > " + maxIterations + ")");
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        private IMacFactory GenCalculator(PbmParameter parameters, ReadOnlySpan<char> password)
        {
            return GenCalculator(parameters, Strings.ToUtf8ByteArray(password));
        }
#else
        private IMacFactory GenCalculator(PbmParameter parameters, char[] password)
        {
            return GenCalculator(parameters, Strings.ToUtf8ByteArray(password));
        }
#endif

        private IMacFactory GenCalculator(PbmParameter parameters, byte[] pw)
        {
            // From RFC 4211
            //
            //   1.  Generate a random salt value S
            //
            //   2.  Append the salt to the pw.  K = pw || salt.
            //
            //   3.  Hash the value of K.  K = HASH(K)
            //
            //   4.  Iter = Iter - 1.  If Iter is greater than zero.  Goto step 3.
            //
            //   5.  Compute an HMAC as documented in [HMAC].
            //
            //       MAC = HASH( K XOR opad, HASH( K XOR ipad, data) )
            //
            //       Where opad and ipad are defined in [HMAC].
            byte[] salt = parameters.Salt.GetOctets();
            byte[] K = new byte[pw.Length + salt.Length];

            Array.Copy(pw, 0, K, 0, pw.Length);
            Array.Copy(salt, 0, K, pw.Length, salt.Length);

            IDigest digest = provider.CreateDigest(parameters.Owf);

            int iter = parameters.IterationCount.IntValueExact;

            digest.BlockUpdate(K, 0, K.Length);

            K = new byte[digest.GetDigestSize()];

            digest.DoFinal(K, 0);

            while (--iter > 0)
            {
                digest.BlockUpdate(K, 0, K.Length);

                digest.DoFinal(K, 0);
            }

            byte[] key = K;

            return new PKMacFactory(key, parameters);
        }

        private PbmParameter GenParameters()
        {
            byte[] salt = SecureRandom.GetNextBytes(CryptoServicesRegistrar.GetSecureRandom(random), saltLength);

            return new PbmParameter(salt, owf, iterationCount, mac);
        }
    }
}
