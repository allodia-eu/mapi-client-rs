//! What the command line looks like: the arguments, and the subcommands they belong to.
//!
//! Its own file rather than part of `main`, because this is the half that grows with every
//! operation and the process around it is not — and because a subcommand's `--help` text is the
//! only documentation most people will read, so it deserves the room to say what the operation
//! costs and what it will not undo.

use clap::{Parser, Subcommand};

use crate::scenario;
use crate::settings::Connection;

#[derive(Debug, Parser)]
#[command(
    name = "mapi-cli",
    version,
    about = "Diagnostic client for MAPI over HTTP, and the fixture capture tool.",
    long_about = None,
)]
pub(crate) struct Cli {
    #[command(flatten)]
    pub(crate) connection: Connection,

    #[command(subcommand)]
    pub(crate) command: Command,
}

#[derive(Debug, Subcommand)]
pub(crate) enum Command {
    /// Ask the endpoint whether it is there, without establishing anything.
    ///
    /// The cheapest check that the URL is right, that the credentials work and that whatever
    /// answers speaks MAPI/HTTP. [MS-OXCMAPIHTTP] §2.2.6
    Ping,

    /// Establish a Session Context and report what the server said about the mailbox.
    Connect,

    /// Walk a folder's hierarchy table.
    Folders {
        /// Which folder to list the children of. One of the thirteen a logon names, or a folder id
        /// as `0x...`. Defaults to the IPM subtree, which is the user-visible root.
        #[arg(long, value_name = "FOLDER", default_value = "ipm-subtree")]
        folder: String,

        /// Rows per round trip.
        #[arg(long, value_name = "ROWS", default_value_t = 50)]
        page_size: u16,

        /// List every folder below this one rather than its immediate children.
        ///
        /// Sets the `Depth` bit of `TableFlags`, so the whole tree arrives in one table.
        /// [MS-OXCFOLD] §2.2.1.13.1
        #[arg(long)]
        recursive: bool,

        /// Show only folders of this container class, and its refinements.
        ///
        /// `IPF.Appointment` lists the calendars; `IPF.Contact` lists the contact folders, its
        /// `IPF.Contact.MOC.QuickContacts` kind included. [MS-OXCFOLD] §2.2.2.2.2.3
        #[arg(long, value_name = "CLASS")]
        class: Option<String>,
    },

    /// Find the folders a logon does not name: Calendar, Contacts, Drafts and the rest.
    ///
    /// Two round trips: the entry ids come from binary properties on the Inbox, and only the
    /// server can turn a long-term entry id into an id `RopOpenFolder` takes.
    /// [MS-OXOSFLD] §2.2.3
    Special {
        /// Also open each one and report what it is: name, class, item count, and whether it is a
        /// search folder rather than a real one.
        #[arg(long)]
        details: bool,
    },

    /// Resolve the calendar and contact properties to the ids this mailbox uses for them.
    ///
    /// Named properties have no fixed id: each store allocates one from `0x8000` upwards the first
    /// time it needs the property, so the numbers this prints are meaningful only in the mailbox
    /// that answered. Run it against two mailboxes to see that. [MS-OXCPRPT] §3.1.2
    Named {
        /// Ask the store back what each resolved id is called, and fail if any disagrees.
        ///
        /// `RopGetNamesFromPropertyIds`, which is the only check on the response ordering that
        /// does not come from the same answer being checked. [MS-OXCROPS] §2.2.8.2
        #[arg(long)]
        verify: bool,

        /// Also ask what an id is called *here*, written as `0x8186`. Repeatable.
        ///
        /// Point it at an id another mailbox reported to see what the cross-store mistake actually
        /// costs: the same number is a different property, or none at all.
        #[arg(long = "id", value_name = "ID")]
        ids: Vec<String>,
    },

    /// Read a folder's contents table.
    Messages {
        /// Which folder to read. One of the thirteen a logon names, or a folder id as `0x...`.
        #[arg(long, value_name = "FOLDER", default_value = "inbox")]
        folder: String,

        /// Rows per round trip.
        #[arg(long, value_name = "ROWS", default_value_t = 50)]
        page_size: u16,

        /// How many rows to print. The rest are still read.
        #[arg(long, value_name = "ROWS", default_value_t = 20)]
        limit: usize,

        /// Order by delivery time, newest first, on the server.
        ///
        /// `RopSortTable`. The sort key has to be among the columns read, which
        /// [MS-OXCTABL] §2.2.2.3 requires and this client checks before sending.
        #[arg(long)]
        newest_first: bool,

        /// Show only messages whose subject contains this, matched by the server.
        ///
        /// `RopRestrict` with a content restriction, paired with an existence test because
        /// [MS-OXCDATA] §2.12.9.1 leaves the result on an item with no subject undefined.
        #[arg(long, value_name = "TEXT")]
        subject: Option<String>,
    },

    /// List a calendar's events, with real start times, end times and locations.
    ///
    /// Every one of those is a named property with no fixed id, so this resolves them against the
    /// store first and builds its column set from the answer. [MS-OXOCAL] §2.2.1
    Events {
        /// Which folder to read, as `0x...`. Defaults to the Calendar the entry-id chain finds.
        #[arg(long, value_name = "FOLDER")]
        folder: Option<String>,

        /// How many events to print. The rest are still read.
        #[arg(long, value_name = "ROWS", default_value_t = 20)]
        limit: usize,
    },

    /// List a contacts folder, with the email addresses that make it worth listing.
    ///
    /// `PidLidEmail1EmailAddress` is a named property, so this costs the same lookup `events` does.
    /// [MS-OXOCNTC] §2.2.1.2
    Contacts {
        /// Which folder to read, as `0x...`. Defaults to the Contacts folder.
        #[arg(long, value_name = "FOLDER")]
        folder: Option<String>,

        /// How many contacts to print. The rest are still read.
        #[arg(long, value_name = "ROWS", default_value_t = 20)]
        limit: usize,
    },

    /// Open one message: its properties, its recipients, its body and its attachments.
    ///
    /// The body is read with `RopOpenStream`, which is the only reading that works for a message of
    /// any size — a property fetch answers anything past the response buffer with an error rather
    /// than with the value. [MS-OXCPRPT] §2.2.3.2
    Message {
        /// Which folder it lives in. `RopOpenMessage` needs both ids.
        #[arg(long, value_name = "FOLDER", default_value = "inbox")]
        folder: String,

        /// The message id, as `0x...`. `mapi-cli messages` prints these.
        #[arg(long, value_name = "ID")]
        id: String,

        /// Also stream the plain-text and HTML bodies, and report how long each is.
        #[arg(long)]
        body: bool,
    },

    /// Write a message into Drafts, with recipients and an attachment.
    ///
    /// The recipients are addressed one-off — an SMTP address and nothing looked up — because the
    /// address book is NSPI, a separate endpoint this workspace does not implement.
    /// [MS-OXCDATA] §2.2.5.1
    Draft {
        /// The subject.
        #[arg(long, value_name = "TEXT", default_value = "Drafted by mapi-cli")]
        subject: String,

        /// The plain-text body.
        #[arg(long, value_name = "TEXT", default_value = "")]
        body: String,

        /// An SMTP address to address it to. Repeatable.
        #[arg(long = "to", value_name = "ADDRESS")]
        to: Vec<String>,

        /// A file to attach. Its bytes go through `RopWriteStream`, 16 KiB at a time.
        #[arg(long, value_name = "FILE")]
        attach: Option<std::path::PathBuf>,
    },

    /// Create a contact in the Contacts folder.
    ///
    /// Half of what makes a contact a contact is named properties, and one of those is a one-off
    /// entry id — without it a client shows the address and will not send to it.
    /// [MS-OXOCNTC] §2.2.1.2
    Contact {
        /// The display name. Split on its last space into a given name and a surname.
        #[arg(long, value_name = "NAME")]
        name: String,

        /// The SMTP address.
        #[arg(long, value_name = "ADDRESS")]
        email: String,

        /// The company name.
        #[arg(long, value_name = "NAME")]
        company: Option<String>,

        /// The business telephone number.
        #[arg(long, value_name = "NUMBER")]
        phone: Option<String>,
    },

    /// Create a single-instance appointment in the Calendar.
    ///
    /// Both instants are UTC and the `Z` is required: [MS-OXOCAL] §2.2.1.5 specifies the start in
    /// UTC, and this tool will not guess a time zone.
    Event {
        /// The subject.
        #[arg(long, value_name = "TEXT")]
        subject: String,

        /// When it starts, as `2026-09-10T09:00:00Z`.
        #[arg(long, value_name = "INSTANT")]
        start: String,

        /// When it ends, as `2026-09-10T10:00:00Z`.
        #[arg(long, value_name = "INSTANT")]
        end: String,

        /// Where it is.
        #[arg(long, value_name = "TEXT")]
        location: Option<String>,
    },

    /// Write a message and hand it to the transport.
    ///
    /// **This sends real mail**, to whatever address is given. There is no dry run: the response
    /// says the server accepted the message, and a bad address comes back as a non-delivery report
    /// in this mailbox rather than as an error here. [MS-OXCROPS] §2.2.7.1
    Send {
        /// The subject.
        #[arg(long, value_name = "TEXT", default_value = "Sent by mapi-cli")]
        subject: String,

        /// The plain-text body.
        #[arg(long, value_name = "TEXT", default_value = "")]
        body: String,

        /// An SMTP address to send it to. Repeatable, and required — a message with no recipients
        /// is refused by the server rather than by this tool, which is a worse place to find out.
        #[arg(long = "to", value_name = "ADDRESS", required = true)]
        to: Vec<String>,

        /// A file to attach. Its bytes go through `RopWriteStream`, 16 KiB at a time.
        #[arg(long, value_name = "FILE")]
        attach: Option<std::path::PathBuf>,

        /// Do not name Sent Items as the folder to file the sent message in.
        ///
        /// `PidTagSentMailSvrEID` is what says where it goes, and **without it the message stays
        /// in Drafts** — measured on Exchange Server SE `15.02.2562.045`, where the property moves
        /// the message rather than copying it. [MS-OXOMSG] §2.2.3.10
        #[arg(long)]
        no_copy: bool,

        /// Keep nothing: send it and remove it.
        ///
        /// `PidTagDeleteAfterSubmit`, which on Exchange Server SE `15.02.2562.045` **also
        /// suppresses the Sent Items copy** — so this is one option rather than two, and the two
        /// are refused together. [MS-OXOMSG] §2.2.3.8
        #[arg(long, conflicts_with = "no_copy")]
        discard: bool,
    },

    /// Hand a message that is already in the mailbox to the transport.
    ///
    /// The other half of `send`, for a draft written earlier — by `mapi-cli draft`, by Outlook, or
    /// by anything else. **This sends real mail** to whatever recipients the draft already carries.
    /// [MS-OXCROPS] §2.2.7.1
    Submit {
        /// Which folder it is in.
        #[arg(long, value_name = "FOLDER", default_value = "drafts")]
        folder: String,

        /// The message id, as `0x...`.
        #[arg(long, value_name = "ID")]
        id: String,
    },

    /// Move or copy messages between two folders.
    ///
    /// *Archiving*, as far as MAPI has such an operation. Both folders are opened in the same ROP
    /// buffer as the move, so it is one round trip. [MS-OXCROPS] §2.2.4.6
    Move {
        /// Which folder they are in now. One of the thirteen a logon names, a special-folder name,
        /// or a folder id as `0x...`.
        #[arg(long = "from", value_name = "FOLDER", default_value = "inbox")]
        from: String,

        /// Where they are going.
        #[arg(long = "to", value_name = "FOLDER")]
        to: String,

        /// A message id, as `0x...`. Repeatable.
        #[arg(long = "id", value_name = "ID", required = true)]
        ids: Vec<String>,

        /// Copy rather than move, leaving the originals where they are.
        #[arg(long)]
        copy: bool,
    },

    /// Mark messages read or unread.
    ///
    /// One of the two things "flag a message" means in MAPI — this one is the `mfRead` bit of
    /// `PidTagMessageFlags`, and `mapi-cli flag` is the other. [MS-OXCROPS] §2.2.6.10
    Mark {
        /// Which folder they are in.
        #[arg(long, value_name = "FOLDER", default_value = "inbox")]
        folder: String,

        /// A message id, as `0x...`. Repeatable.
        #[arg(long = "id", value_name = "ID", required = true)]
        ids: Vec<String>,

        /// Mark them unread rather than read.
        #[arg(long)]
        unread: bool,

        /// Send the sender the read receipt they asked for.
        ///
        /// Off by default, and deliberately: marking a message read is the same ROP as sending the
        /// receipt, and telling somebody the user has read a message the user has not looked at is
        /// not a thing to do by accident. [MS-OXCMSG] §2.2.3.10.1
        #[arg(long, conflicts_with = "unread")]
        receipt: bool,
    },

    /// Report what state a message is in: read or not, sent or not, flagged or not.
    ///
    /// The read-only counterpart of `mark` and `flag`, and the way to check either did what it
    /// said. Most of what it asks for comes back absent on an ordinary message, which is the
    /// answer: [MS-OXOFLAG] §2.2.1.1 has the flag properties exist only on a flagged one.
    State {
        /// Which folder it is in.
        #[arg(long, value_name = "FOLDER", default_value = "inbox")]
        folder: String,

        /// The message id, as `0x...`.
        #[arg(long, value_name = "ID")]
        id: String,
    },

    /// Set or clear a message's follow-up flag.
    ///
    /// The other thing "flag a message" means: a set of ordinary properties rather than a ROP, and
    /// half of them named. [MS-OXOFLAG] §3.1.4.1
    Flag {
        /// Which folder it is in.
        #[arg(long, value_name = "FOLDER", default_value = "inbox")]
        folder: String,

        /// The message id, as `0x...`.
        #[arg(long, value_name = "ID")]
        id: String,

        /// The text that goes with the flag. [MS-OXOFLAG] §2.2.1.9
        #[arg(long, value_name = "TEXT", default_value = "Follow up")]
        text: String,

        /// The flag's colour: purple, orange, green, yellow, blue or red.
        ///
        /// Without one the flag has no colour, which [MS-OXOFLAG] §3.1.4.1.2 calls a basic flag.
        #[arg(long, value_name = "COLOUR")]
        colour: Option<String>,

        /// Mark the flag complete rather than outstanding.
        #[arg(long, conflicts_with = "clear")]
        complete: bool,

        /// Take the flag off entirely.
        ///
        /// A delete rather than a write of zero: [MS-OXOFLAG] §2.2.1.1 has `PidTagFlagStatus`
        /// present only on a flagged message.
        #[arg(long)]
        clear: bool,
    },

    /// Delete messages from a folder, by id.
    ///
    /// A soft delete: the server keeps a back-up copy. `RopDeleteMessages` succeeds whether or not
    /// it deleted anything, so this reports what the `PartialCompletion` flag said.
    /// [MS-OXCROPS] §2.2.4.11
    Delete {
        /// Which folder they are in. One of the thirteen a logon names, or a folder id as `0x...`.
        #[arg(long, value_name = "FOLDER", default_value = "drafts")]
        folder: String,

        /// A message id, as `0x...`. Repeatable.
        #[arg(long = "id", value_name = "ID", required = true)]
        ids: Vec<String>,
    },

    /// Dump the Store object's properties: display name, owner, size and quotas.
    ///
    /// With no `--tag`, this asks for everything the object holds, which is the only way to see
    /// what a deployment actually carries as against what [MS-OXCSTOR] §2.2.2.1 documents.
    Properties {
        /// A property tag to read, written id-first as `0x3001001F`. Repeatable. Without any,
        /// every property the Store object has is read.
        #[arg(long, value_name = "TAG")]
        tag: Vec<String>,
    },

    /// Locate a mailbox with Autodiscover.
    ///
    /// Needs no endpoint and no distinguished name — finding those is what it does.
    Discover {
        /// The email address to look up.
        address: String,
    },

    /// Drive a scenario against the live server and write it out as fixtures.
    Capture(scenario::CaptureArguments),
}
