using System.IO;

namespace Org.BouncyCastle.Crypto.Tls
{
    public class NewSessionTicket
    {
        protected long ticketLifetimeHint;
        protected byte[] ticket;

        public NewSessionTicket(long ticketLifetimeHint, byte[] ticket)
        {
            this.ticketLifetimeHint = ticketLifetimeHint;
            this.ticket = ticket;
        }

        public long TicketLifetimeHint
        {
            get
            {
                return ticketLifetimeHint;
            }
        }

        public byte[] Ticket
        {
            get
            {
                return ticket;
            }
        }

        /**
         * Encode this {@link NewSessionTicket} to an {@link Stream}.
         *
         * @param output the {@link Stream} to encode to.
         * @throws IOException
         */
        public void Encode(Stream output)
        {
            TlsUtilities.WriteUint32(ticketLifetimeHint, output);
            TlsUtilities.WriteOpaque16(ticket, output);
        }

        /**
         * Parse a {@link NewSessionTicket} from an {@link InputStream}.
         *
         * @param input the {@link InputStream} to parse from.
         * @return a {@link NewSessionTicket} object.
         * @throws IOException
         */
        public static NewSessionTicket Parse(Stream input)
        {
            long ticketLifetimeHint = TlsUtilities.ReadUint32(input);
            byte[] ticket = TlsUtilities.ReadOpaque16(input);
            return new NewSessionTicket(ticketLifetimeHint, ticket);
        }
    }
}