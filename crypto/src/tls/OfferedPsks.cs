using System;
using System.Collections;
using System.IO;

using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Tls
{
    public sealed class OfferedPsks
    {
        private readonly IList m_identities;
        private readonly IList m_binders;

        public OfferedPsks(IList identities, IList binders)
        {
            if (null == identities || identities.Count < 1)
                throw new ArgumentException("cannot be null or empty", "identities");
            if (null == binders || identities.Count != binders.Count)
                throw new ArgumentException("must be non-null and the same length as 'identities'", "binders");

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
                int totalLengthIdentities = 0;
                foreach (PskIdentity identity in m_identities)
                {
                    totalLengthIdentities += 2 + identity.Identity.Length + 4;
                }

                TlsUtilities.CheckUint16(totalLengthIdentities);
                TlsUtilities.WriteUint16(totalLengthIdentities, output);

                foreach (PskIdentity identity in m_identities)
                {
                    identity.Encode(output);
                }
            }

            // binders
            {
                int totalLengthBinders = 0;
                foreach (byte[] binder in m_binders)
                {
                    totalLengthBinders += 1 + binder.Length;
                }

                TlsUtilities.CheckUint16(totalLengthBinders);
                TlsUtilities.WriteUint16(totalLengthBinders, output);

                foreach (byte[] binder in m_binders)
                {
                    TlsUtilities.WriteOpaque8(binder, output);
                }
            }
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
