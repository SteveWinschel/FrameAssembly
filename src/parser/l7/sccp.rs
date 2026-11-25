//! Cisco Skinny Client Control Protocol (SCCP) Layer 7 VoIP signaling field parser.
//!
//! This module implements the `winnow` parser combinator for Cisco Skinny (`sccp`) IP phone
//! call-control signaling messages over TCP port 2000 in FrameAssembly `.frasm` specifications.
//! It recognizes the `sccp` protocol keyword, message type shorthands (`register`, `registerack`,
//! `keepalive`, `keepaliveack`, `offhook`, `onhook`, `keypadbutton`, `callstate`, `starttone`,
//! `stoptone`, `openreceivechannel`, `openreceivechannelack`), explicit `msgtype`, `version`,
//! `devicename`, `line`, `callid`, `state`, `button`, `tone`, `addr`, and `mediaport`.

use winnow::ModalResult as PResult;
use winnow::combinator::{alt, cut_err};
use winnow::prelude::*;

use crate::ast::*;
use crate::lexer::Token;
use crate::parser::{
    ParsedField, Stream, parse_any_str, parse_ip, parse_u32, tag,
};

/// Parses a Cisco Skinny (SCCP) protocol declaration or signaling message field.
pub(crate) fn parse_sccp_field<'i, 'a>(input: &mut Stream<'i, 'a>) -> PResult<ParsedField<'a>> {
    alt((
        alt((
            tag(Token::Sccp).map(|(_, s)| ParsedField::Protocol(Protocol::Sccp, (s.start, s.len()))),
            tag(Token::Register)
                .map(|(_, s)| ParsedField::L7StringField("MSG_TYPE", "REGISTER", (s.start, s.len()))),
            tag(Token::RegisterAck).map(|(_, s)| {
                ParsedField::L7StringField("MSG_TYPE", "REGISTERACK", (s.start, s.len()))
            }),
            tag(Token::Keepalive).map(|(_, s)| {
                ParsedField::L7StringField("MSG_TYPE", "KEEPALIVE", (s.start, s.len()))
            }),
            tag(Token::KeepaliveAck).map(|(_, s)| {
                ParsedField::L7StringField("MSG_TYPE", "KEEPALIVEACK", (s.start, s.len()))
            }),
            tag(Token::OffHook)
                .map(|(_, s)| ParsedField::L7StringField("MSG_TYPE", "OFFHOOK", (s.start, s.len()))),
            tag(Token::OnHook)
                .map(|(_, s)| ParsedField::L7StringField("MSG_TYPE", "ONHOOK", (s.start, s.len()))),
            tag(Token::KeypadButton).map(|(_, s)| {
                ParsedField::L7StringField("MSG_TYPE", "KEYPADBUTTON", (s.start, s.len()))
            }),
        )),
        alt((
            tag(Token::CallState).map(|(_, s)| {
                ParsedField::L7StringField("MSG_TYPE", "CALLSTATE", (s.start, s.len()))
            }),
            tag(Token::StartTone).map(|(_, s)| {
                ParsedField::L7StringField("MSG_TYPE", "STARTTONE", (s.start, s.len()))
            }),
            tag(Token::StopTone).map(|(_, s)| {
                ParsedField::L7StringField("MSG_TYPE", "STOPTONE", (s.start, s.len()))
            }),
            tag(Token::OpenReceiveChannel).map(|(_, s)| {
                ParsedField::L7StringField("MSG_TYPE", "OPENRECEIVECHANNEL", (s.start, s.len()))
            }),
            tag(Token::OpenReceiveChannelAck).map(|(_, s)| {
                ParsedField::L7StringField("MSG_TYPE", "OPENRECEIVECHANNELACK", (s.start, s.len()))
            }),
            (tag(Token::MsgType), cut_err(parse_any_str)).map(|((_, s), v)| {
                ParsedField::L7StringField("MSG_TYPE", v, (s.start, s.end - s.start))
            }),
            (tag(Token::Version), cut_err(parse_u32)).map(|((_, s), v)| {
                ParsedField::L7U32Field("VERSION", v, (s.start, s.end - s.start))
            }),
            (tag(Token::DeviceName), cut_err(parse_any_str)).map(|((_, s), v)| {
                ParsedField::L7StringField("DEVICE_NAME", v, (s.start, s.end - s.start))
            }),
        )),
        alt((
            (tag(Token::Line), cut_err(parse_u32))
                .map(|((_, s), v)| ParsedField::L7U32Field("LINE", v, (s.start, s.end - s.start))),
            (tag(Token::CallId), cut_err(parse_u32)).map(|((_, s), v)| {
                ParsedField::L7U32Field("CALL_ID", v, (s.start, s.end - s.start))
            }),
            (tag(Token::State), cut_err(parse_u32)).map(|((_, s), v)| {
                ParsedField::L7U32Field("STATE", v, (s.start, s.end - s.start))
            }),
            (tag(Token::Button), cut_err(parse_u32)).map(|((_, s), v)| {
                ParsedField::L7U32Field("BUTTON", v, (s.start, s.end - s.start))
            }),
            (tag(Token::Tone), cut_err(parse_u32))
                .map(|((_, s), v)| ParsedField::L7U32Field("TONE", v, (s.start, s.end - s.start))),
            (tag(Token::Addr), cut_err(parse_ip))
                .map(|((_, s), v)| ParsedField::L7IpField("ADDR", v, (s.start, s.end - s.start))),
            (tag(Token::MediaPort), cut_err(parse_u32)).map(|((_, s), v)| {
                ParsedField::L7U32Field("MEDIA_PORT", v, (s.start, s.end - s.start))
            }),
        )),
    ))
    .parse_next(input)
}
