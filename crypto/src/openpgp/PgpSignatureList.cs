using System;

namespace Org.BouncyCastle.Bcpg.OpenPgp
{
    /// <remarks>A list of PGP signatures - normally in the signature block after literal data.</remarks>
    public class PgpSignatureList
        : PgpObject
    {
        private readonly PgpSignature[] sigs;

        /// <summary>Create a new <see cref="PgpSignatureList"/>.</summary>
        /// <param name="sigs">The sigs.</param>
        public PgpSignatureList(
            PgpSignature[] sigs)
        {
            this.sigs = (PgpSignature[]) sigs.Clone();
        }

        /// <summary>Create a new <see cref="PgpSignatureList"/>.</summary>
        /// <param name="sig">The signature.</param>
        public PgpSignatureList(
            PgpSignature sig)
        {
            this.sigs = new PgpSignature[]{ sig };
        }

        /// <summary>Gets the signature at the given index.</summary>
        /// <param name="index">The index.</param>
        public PgpSignature this[int index]
        {
            get { return sigs[index]; }
        }

        /// <summary>Gets the count.</summary>
        public int Count
        {
            get { return sigs.Length; }
        }

        /// <summary>Gets a value indicating whether this is empty.</summary>
        public bool IsEmpty
        {
            get { return (sigs.Length == 0); }
        }
    }
}
