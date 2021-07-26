using System;
using System.Collections;
using System.IO;

using Org.BouncyCastle.Tls.Crypto;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Tls
{
    public sealed class OfferedPsks
    {
        private readonly IList m_identities;
        private readonly IList m_binders;

        public OfferedPsks(IList identities)
            : this(identities, null)
        {
        }

        private OfferedPsks(IList identities, IList binders)
        {
            if (null == identities || identities.Count < 1)
                throw new ArgumentException("cannot be null or empty", "identities");
            if (null != binders && identities.Count != binders.Count)
                throw new ArgumentException("must be the same length as 'identities' (or null)", "binders");

            this.m_identities = identities;
            this.m_binders = binders;
        }

        public IList Binders
        {
            get { return m_binders; }
        }

        public IList Identities
        {
            get { return m_identities; }
        }

        /// <exception cref="IOException"/>
        public void Encode(Stream output)
        {
            // identities
            {
                int lengthOfIdentitiesList = 0;
                foreach (PskIdentity identity in m_identities)
                {
                    lengthOfIdentitiesList += identity.GetEncodedLength();
                }

                TlsUtilities.CheckUint16(lengthOfIdentitiesList);
                TlsUtilities.WriteUint16(lengthOfIdentitiesList, output);

                foreach (PskIdentity identity in m_identities)
                {
                    identity.Encode(output);
                }
            }

            // binders
            if (null != m_binders)
            {
                int lengthOfBindersList = 0;
                foreach (byte[] binder in m_binders)
                {
                    lengthOfBindersList += 1 + binder.Length;
                }

                TlsUtilities.CheckUint16(lengthOfBindersList);
                TlsUtilities.WriteUint16(lengthOfBindersList, output);

                foreach (byte[] binder in m_binders)
                {
                    TlsUtilities.WriteOpaque8(binder, output);
                }
            }
        }

        /// <exception cref="IOException"/>
        internal static void EncodeBinders(Stream output, TlsCrypto crypto, TlsHandshakeHash handshakeHash,
            TlsPsk[] psks, TlsSecret[] earlySecrets, int expectedLengthOfBindersList)
        {
            TlsUtilities.CheckUint16(expectedLengthOfBindersList);
            TlsUtilities.WriteUint16(expectedLengthOfBindersList, output);

            int lengthOfBindersList = 0;
            for (int i = 0; i < psks.Length; ++i)
            {
                TlsPsk psk = psks[i];
                TlsSecret earlySecret = earlySecrets[i];

                // TODO[tls13-psk] Handle resumption PSKs
                bool isExternalPsk = true;
                int pskCryptoHashAlgorithm = TlsCryptoUtilities.GetHashForPrf(psk.PrfAlgorithm);

                // TODO[tls13-psk] Cache the transcript hashes per algorithm to avoid duplicates for multiple PSKs
                TlsHash hash = crypto.CreateHash(pskCryptoHashAlgorithm);
                handshakeHash.CopyBufferTo(new TlsHashSink(hash));
                byte[] transcriptHash = hash.CalculateHash();

                byte[] binder = TlsUtilities.CalculatePskBinder(crypto, isExternalPsk, pskCryptoHashAlgorithm,
                    earlySecret, transcriptHash);

                lengthOfBindersList += 1 + binder.Length;
                TlsUtilities.WriteOpaque8(binder, output);
            }

            if (expectedLengthOfBindersList != lengthOfBindersList)
                throw new TlsFatalAlert(AlertDescription.internal_error);
        }

        /// <exception cref="IOException"/>
        internal static int GetLengthOfBindersList(TlsPsk[] psks)
        {
            int lengthOfBindersList = 0;
            for (int i = 0; i < psks.Length; ++i)
            {
                TlsPsk psk = psks[i];

                int prfAlgorithm = psk.PrfAlgorithm;
                int prfCryptoHashAlgorithm = TlsCryptoUtilities.GetHashForPrf(prfAlgorithm);

                lengthOfBindersList += 1 + TlsCryptoUtilities.GetHashOutputSize(prfCryptoHashAlgorithm);
            }
            TlsUtilities.CheckUint16(lengthOfBindersList);
            return lengthOfBindersList;
        }

        /// <exception cref="IOException"/>
        public static OfferedPsks Parse(Stream input)
        {
            IList identities = Platform.CreateArrayList();
            {
                int totalLengthIdentities = TlsUtilities.ReadUint16(input);
                if (totalLengthIdentities < 7)
                    throw new TlsFatalAlert(AlertDescription.decode_error);

                byte[] identitiesData = TlsUtilities.ReadFully(totalLengthIdentities, input);
                MemoryStream buf = new MemoryStream(identitiesData, false);
                do
                {
                    PskIdentity identity = PskIdentity.Parse(buf);
                    identities.Add(identity);
                }
                while (buf.Position < buf.Length);
            }

            IList binders = Platform.CreateArrayList();
            {
                int totalLengthBinders = TlsUtilities.ReadUint16(input);
                if (totalLengthBinders < 33)
                    throw new TlsFatalAlert(AlertDescription.decode_error);

                byte[] bindersData = TlsUtilities.ReadFully(totalLengthBinders, input);
                MemoryStream buf = new MemoryStream(bindersData, false);
                do
                {
                    byte[] binder = TlsUtilities.ReadOpaque8(input, 32);
                    binders.Add(binder);
                }
                while (buf.Position < buf.Length);
            }

            return new OfferedPsks(identities, binders);
        }
    }
}
