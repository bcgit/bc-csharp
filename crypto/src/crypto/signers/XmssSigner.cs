using System;
using System.IO;

using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers.Xmss;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Crypto.Signers
{
    /// <summary>
    /// XMSS (RFC 8391) signer. The message is buffered through the streaming <see cref="ISigner"/> surface and
    /// signed or verified as a whole when the operation is finalised.
    /// </summary>
    /// <remarks>
    /// <para>
    /// XMSS is stateful: every signature spends one WOTS+ one-time key, which must never sign again (RFC 8391
    /// sec. 1.1). <see cref="GenerateSignature"/> advances the private key it was initialised with, in place, past the
    /// index it signed at. The caller must persist the advanced key - <see cref="GetUpdatedPrivateKey"/> hands it
    /// back - before the signature is released; a key restored from an encoding taken before a signature signs again
    /// at an index already used.
    /// </para>
    /// <para>
    /// Signing is serialised on this signer and on the private key, so several signers holding one key, or several
    /// threads sharing one signer, never sign at the same index. The message buffer is not a synchronisation point:
    /// threads sharing a signer must not interleave their messages.
    /// </para>
    /// </remarks>
    public sealed class XmssSigner
        : ISigner
    {
        private readonly MemoryStream m_buffer = new MemoryStream();

        private XmssPrivateKeyParameters m_privateKey;
        private XmssPublicKeyParameters m_publicKey;
        private XmssParameters m_parameters;

        private bool m_initSign;
        private bool m_hasGenerated;

        // what a collection that followed no signature handed back, so a second one can hand back the same object
        // rather than shard the single usage this signer kept for itself. Null once a signature has spent that usage,
        // and on every Init().
        private XmssPrivateKeyParameters m_collected;

        // whether that collection happened at all, which outlives the field above: that one is cleared when the
        // signature spends the usage this signer kept, and this is what still says the rest of the key is already in
        // the caller's hands. Cleared only by Init().
        private bool m_collectedRemainder;

        /// <inheritdoc/>
        public string AlgorithmName => "XMSS";

        /// <summary>
        /// Initialise for signing (<see cref="XmssPrivateKeyParameters"/>) or verification
        /// (<see cref="XmssPublicKeyParameters"/>), discarding any message buffered before.
        /// </summary>
        /// <remarks>
        /// <para>
        /// A <see cref="ParametersWithRandom"/> wrapper is accepted on either side and its random discarded: the
        /// randomizer r is derived from the key itself, r = PRF(SK_PRF, toByte(idx, 32)) (RFC 8391 sec. 4.1.9), so
        /// there is nothing for a random to drive.
        /// </para>
        /// <para>
        /// A verification init leaves the private key of an earlier signing init in place, so sign, then verify, then
        /// collect the advanced key with <see cref="GetUpdatedPrivateKey"/> remains a legitimate sequence; a signing
        /// init drops the public key of an earlier verification init.
        /// </para>
        /// </remarks>
        /// <exception cref="ArgumentNullException">If no key is given.</exception>
        /// <exception cref="InvalidCastException">If the key is not an XMSS key of the kind
        /// <paramref name="forSigning"/> asks for.</exception>
        public void Init(bool forSigning, ICipherParameters parameters)
        {
            parameters = ParameterUtilities.IgnoreRandom(parameters);

            // checked and cast before anything is assigned, so a refused key leaves the signer as it was
            if (parameters == null)
                throw new ArgumentNullException(nameof(parameters));

            XmssPrivateKeyParameters privateKey = forSigning ? (XmssPrivateKeyParameters)parameters : null;
            XmssPublicKeyParameters publicKey = forSigning ? null : (XmssPublicKeyParameters)parameters;

            // under the lock GenerateSignature() and GetUpdatedPrivateKey() take: this is the other place the private
            // key field is assigned, and an init landing part way through a signature would otherwise leave the two
            // disagreeing about which key is being spent
            lock (this)
            {
                if (forSigning)
                {
                    m_initSign = true;
                    m_hasGenerated = false;
                    m_collected = null;
                    m_collectedRemainder = false;
                    m_privateKey = privateKey;
                    // the public key from a previous verification init must not stay behind, or this signer would
                    // still verify against it
                    m_publicKey = null;
                    m_parameters = privateKey.Parameters;
                }
                else
                {
                    m_initSign = false;
                    m_publicKey = publicKey;
                    m_parameters = publicKey.Parameters;
                }

                // a message absorbed before this call belongs to the operation that has just ended: carrying it into
                // the new one would sign or verify bytes the caller never presented for it, and on the signing side
                // would spend a one-time key doing so
                Reset();
            }
        }

        /// <inheritdoc/>
        public void Update(byte input)
        {
            lock (m_buffer)
            {
                m_buffer.WriteByte(input);
            }
        }

        /// <inheritdoc/>
        public void BlockUpdate(byte[] input, int inOff, int inLen)
        {
            lock (m_buffer)
            {
                m_buffer.Write(input, inOff, inLen);
            }
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        /// <inheritdoc/>
        public void BlockUpdate(ReadOnlySpan<byte> input)
        {
            lock (m_buffer)
            {
                m_buffer.Write(input);
            }
        }
#endif

        /// <summary>The length in bytes of the signatures for the parameter set of the key last initialised with.
        /// </summary>
        /// <exception cref="InvalidOperationException">If the signer has not been initialised.</exception>
        public int GetMaxSignatureSize()
        {
            XmssParameters parameters = m_parameters;
            if (parameters == null)
                throw new InvalidOperationException("signer not initialized");

            return XmssSignature.EncodedSizeOf(parameters);
        }

        /// <summary>
        /// Sign the buffered message, and advance the private key past the one-time key the signature spent.
        /// </summary>
        /// <remarks>
        /// The buffered message is consumed whether or not a signature is produced. A signature that is refused
        /// before it is made - an exhausted key, a key without traversal state, a state that has already signed, a
        /// destroyed key - leaves the key where it was.
        /// </remarks>
        /// <exception cref="InvalidOperationException">If the signer is not initialised for signing, its key has
        /// already been handed back by <see cref="GetUpdatedPrivateKey"/>, or the key cannot sign.</exception>
        /// <exception cref="ExhaustedPrivateKeyException">If the key has no usages remaining.</exception>
        public byte[] GenerateSignature()
        {
            // on this signer's lock rather than on the key the field happens to hold: the field is reassigned by
            // GetUpdatedPrivateKey() and by Init(), so a lock taken on the object read out of it excludes nothing from
            // a call that has already read a different one. The key's own lock is still taken below, where it is what
            // excludes a second signer initialised on the same key.
            lock (this)
            {
                // consumed whether or not a signature is produced: a call that fails one of the checks below must
                // not leave bytes behind for the next one to sign
                byte[] message = TakeMessage();

                XmssPrivateKeyParameters privKey = m_privateKey;

                if (!m_initSign)
                    throw new InvalidOperationException("signer not initialized for signature generation");
                if (privKey == null)
                    throw new InvalidOperationException("signing key no longer usable");

                lock (privKey)
                {
                    if (privKey.GetUsagesRemaining() <= 0)
                        throw new ExhaustedPrivateKeyException("no usages of private key remaining");
                    if (!XmssEngine.HasTraversalState(privKey))
                        throw new InvalidOperationException("not initialized");

                    // whether a signature was made is what GetUpdatedPrivateKey() has to know, and the key answers
                    // it: the engine refuses a signature before it touches the key, and otherwise rolls it by exactly
                    // one in a finally, even when the signature failed part way through. This thread holds the key's
                    // lock across the call, so an index that has moved is one this signer moved. Once set the flag
                    // stays set until Init() clears it - a later refusal cannot unsay an earlier signature.
                    int indexBefore = privKey.Index;

                    try
                    {
                        return XmssEngine.GenerateSignature(privKey, message);
                    }
                    finally
                    {
                        if (privKey.Index != indexBefore)
                        {
                            m_hasGenerated = true;
                            m_collected = null;
                        }
                    }
                }
            }
        }

        /// <summary>
        /// The number of signatures the key this signer holds can still make; zero when it holds none - never
        /// initialised for signing, or its key already handed back by <see cref="GetUpdatedPrivateKey"/>.
        /// </summary>
        /// <remarks>
        /// A verification init leaves the private key in place (see <see cref="Init"/>), so a signer that has signed
        /// and then been initialised to verify goes on reporting that key's count. The answer is a count, not a
        /// reservation: the next signature made on the key, by this signer or another holding it, moves it.
        /// </remarks>
        public long GetUsagesRemaining()
        {
            XmssPrivateKeyParameters privKey = m_privateKey;

            return privKey == null ? 0L : privKey.GetUsagesRemaining();
        }

        /// <summary>Verify the buffered message against <paramref name="signature"/>.</summary>
        /// <remarks>
        /// The buffered message is consumed whatever the outcome. A signature that will not decode for the key's
        /// parameter set is reported as one that does not verify.
        /// </remarks>
        /// <exception cref="ArgumentNullException">If <paramref name="signature"/> is <c>null</c>.</exception>
        /// <exception cref="InvalidOperationException">If the signer is not initialised for verification.
        /// </exception>
        public bool VerifySignature(byte[] signature)
        {
            byte[] message = TakeMessage();

            XmssPublicKeyParameters publicKey = m_publicKey;

            // covers both a signer initialised for signing and one never initialised at all
            if (m_initSign || publicKey == null)
                throw new InvalidOperationException("signer not initialized for verification");

            return XmssEngine.VerifySignature(publicKey, message, signature);
        }

        /// <summary>Discard the buffered message.</summary>
        public void Reset()
        {
            lock (m_buffer)
            {
                ClearBuffer();
            }
        }

        /// <summary>The private key the caller must persist in place of the one it initialised this signer with.
        /// </summary>
        /// <remarks>
        /// <para>
        /// Having signed, the signer hands back the key it signed with, advanced past the index it spent, and keeps
        /// nothing: a further call returns <c>null</c>, and the signer cannot sign again until re-initialised.
        /// </para>
        /// <para>
        /// Before any signature, the signer keeps a single-use shard covering the key's current index for itself, and
        /// hands back the key moved on past it; a further call before a signature hands back that same key again
        /// rather than sharding the kept usage. After such a collection the shard's signature adds nothing to what the
        /// caller holds, so the collection after it returns <c>null</c>. A key with no usages left is handed back as
        /// it is.
        /// </para>
        /// </remarks>
        /// <returns>The <see cref="XmssPrivateKeyParameters"/> to persist, or <c>null</c> if there is none: the signer
        /// was never initialised for signing, or a previous call has already taken the key.</returns>
        public AsymmetricKeyParameter GetUpdatedPrivateKey()
        {
            // on this signer's lock, as GenerateSignature() is: this call replaces the field, so one running beside a
            // signature that had already read the old value would leave the key it hands back for storage sitting on
            // the very index that signature is about to spend
            lock (this)
            {
                XmssPrivateKeyParameters privKey = m_privateKey;

                // nothing to hand back: never initialised for signing, or a previous call has already taken the key
                if (privKey == null)
                    return null;

                lock (privKey)
                {
                    if (m_hasGenerated)
                    {
                        m_privateKey = null;

                        // the rest of this key is already with the caller: a collection made before the signature
                        // handed back everything but the one usage the signature has now spent, so what is left here
                        // is a spent shard that adds nothing to what was stored. Handing it over would let a caller
                        // that stores the latest collection overwrite the remainder with a key reporting nothing left.
                        if (m_collectedRemainder)
                            return null;
                    }
                    else if (m_collected != null)
                    {
                        // asked twice with no signature between: the key handed over the first time is still the
                        // whole of what this signer is not keeping, so hand back that same object rather than shard
                        // the single usage kept for signing
                        return m_collected;
                    }
                    else if (privKey.GetUsagesRemaining() > 0)
                    {
                        m_privateKey = privKey.GetNextKey();
                        m_collected = privKey;
                        m_collectedRemainder = true;
                    }
                    // else: a key with nothing left to spend has no next usage to leave behind; hand the spent key
                    // back so it can still be stored - and again on a second call, since nothing was consumed

                    return privKey;
                }
            }
        }

        private byte[] TakeMessage()
        {
            lock (m_buffer)
            {
                byte[] message = m_buffer.ToArray();
                ClearBuffer();
                return message;
            }
        }

        private void ClearBuffer()
        {
            Arrays.ZeroMemory(m_buffer.GetBuffer(), 0, (int)m_buffer.Length);
            m_buffer.SetLength(0);
        }
    }
}
