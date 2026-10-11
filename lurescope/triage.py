"""Safe, local triage of RFC 5322 email messages.

The parser never opens attachments, follows links, resolves DNS, or executes active
content. Model evidence and deterministic email-context evidence remain separate so
callers can understand exactly why a message was routed for review.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import asdict, dataclass, field
from email import policy
from email.message import EmailMessage, Message
from email.parser import BytesParser
from email.utils import getaddresses
from html.parser import HTMLParser
from pathlib import Path
from typing import Iterator, List, Optional, Sequence
from urllib.parse import urlsplit

from . import service
from .local_io import read_regular_file

MAX_EMAIL_BYTES = 5 * 1024 * 1024
MAX_SCORE_TEXT = 20_000
_URL = re.compile(r"https?://[^\s<>\"']+", re.IGNORECASE)
_DANGEROUS_EXTENSIONS = {
    ".bat", ".cmd", ".com", ".exe", ".hta", ".iso", ".jar", ".js",
    ".lnk", ".msi", ".ps1", ".scr", ".vbe", ".vbs", ".wsf",
}
_ARCHIVE_EXTENSIONS = {".7z", ".gz", ".img", ".rar", ".tar", ".zip"}
_QR_LANGUAGE = re.compile(
    r"\b(?:qr|quick response)\s*code\b|\bscan\s+(?:(?:this|the|a)\s+)?code\b",
    re.IGNORECASE,
)


class EmailTooLarge(ValueError):
    """Raised before parsing an email beyond the documented local safety limit."""


class _HTMLText(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.parts: List[str] = []
        self.urls: List[str] = []
        self.hidden = 0
        self.inline_images = 0
        self.visible_text_length = 0

    def handle_starttag(self, tag: str, attrs) -> None:
        if tag in {"script", "style", "head"}:
            self.hidden += 1
        elif tag in {"br", "p", "div", "li", "tr"}:
            self.parts.append("\n")
        if tag == "a":
            href = dict(attrs).get("href", "")
            if href.casefold().startswith(("http://", "https://")):
                self.urls.append(href)
        elif tag == "img" and not self.hidden:
            self.inline_images += 1
            alt = str(dict(attrs).get("alt", "")).strip()
            if alt:
                self.parts.append(f" {alt} ")

    def handle_endtag(self, tag: str) -> None:
        if tag in {"script", "style", "head"} and self.hidden:
            self.hidden -= 1
        elif tag in {"p", "div", "li", "tr"}:
            self.parts.append("\n")

    def handle_data(self, data: str) -> None:
        if not self.hidden:
            self.parts.append(data)
            self.visible_text_length += len(data.strip())

    def text(self) -> str:
        return re.sub(r"\n{3,}", "\n\n", "".join(self.parts)).strip()


@dataclass(frozen=True)
class Evidence:
    code: str
    severity: str
    title: str
    detail: str


@dataclass
class ParsedEmail:
    subject: str
    from_address: Optional[str]
    reply_to: Optional[str]
    to: List[str]
    message_id: Optional[str]
    body: str
    urls: List[str]
    attachments: List[str]
    authentication_results: List[str]
    inline_image_count: int
    html_visible_text_length: int
    inspection_gaps: List[str] = field(default_factory=list)


@dataclass
class EmailTriageResult:
    schema_version: int
    risk_tier: str
    recommended_action: str
    detector: str
    content_probability: float
    content_label: str
    threshold: float
    threshold_source: str
    policy_id: Optional[str]
    subject: str
    from_address: Optional[str]
    reply_to: Optional[str]
    recipients: List[str]
    message_id: Optional[str]
    signals: List[str]
    evidence: List[Evidence] = field(default_factory=list)
    urls: List[str] = field(default_factory=list)
    attachments: List[str] = field(default_factory=list)

    def as_dict(self) -> dict:
        return asdict(self)


def _addresses(value: Optional[str]) -> List[str]:
    if not value:
        return []
    return [address.casefold() for _, address in getaddresses([value]) if address]


def _domain(address: Optional[str]) -> Optional[str]:
    if not address or "@" not in address:
        return None
    return address.rsplit("@", 1)[1].rstrip(">").casefold()


def _part_text(part: Message, gaps: set[str]) -> str:
    encoding = str(part.get("Content-Transfer-Encoding", "")).strip().casefold()
    if encoding not in {"", "7bit", "8bit", "binary", "base64", "quoted-printable"}:
        gaps.add("body_decoding_uncertain")
        return ""
    if encoding == "quoted-printable":
        payload = part.get_payload()
        if isinstance(payload, str) and re.search(r"=(?![0-9a-fA-F]{2}|\r?\n)", payload):
            gaps.add("body_decoding_uncertain")
            return ""
    try:
        content = part.get_content(errors="strict")
    except (LookupError, UnicodeError):
        # Do not guess a charset or insert replacement text into the assessment.
        # Other readable body parts can still be assessed, with a review cue.
        gaps.add("body_decoding_uncertain")
        return ""
    return content if isinstance(content, str) else ""


def _is_body_boundary(part: Message) -> bool:
    return (
        part.get_content_disposition() == "attachment"
        or part.get_filename() is not None
        or part.get_content_maintype() == "message"
    )


def _outer_parts(message: Message) -> Iterator[Message]:
    """Visit outer-message parts, never descendants of attached/embedded mail.

    BytesParser already builds the MIME tree. This only controls subsequent
    extraction; it is not a bound on the parser's memory or recursion.
    """
    pending = [message]
    while pending:
        part = pending.pop()
        yield part
        if not _is_body_boundary(part) and part.is_multipart():
            pending.extend(reversed(part.get_payload()))


def _extract_body(message: EmailMessage, gaps: set[str]) -> tuple[str, List[str], int, int]:
    plain: List[str] = []
    html: List[str] = []
    html_urls: List[str] = []
    inline_images = 0
    html_visible_text_length = 0
    for part in _outer_parts(message):
        if _is_body_boundary(part):
            if (part.get_content_maintype() == "message" and part.get_filename() is None
                    and part.get_content_disposition() != "attachment"):
                gaps.add("uninspected_body_part")
            continue
        content_type = part.get_content_type()
        if part.is_multipart():
            if content_type not in {
                "multipart/mixed", "multipart/alternative", "multipart/related",
            }:
                gaps.add("uninspected_body_part")
            continue
        if content_type == "text/plain":
            plain.append(_part_text(part, gaps))
        elif content_type == "text/html":
            parser = _HTMLText()
            parser.feed(_part_text(part, gaps))
            html.append(parser.text())
            html_urls.extend(parser.urls)
            inline_images += parser.inline_images
            html_visible_text_length += parser.visible_text_length
        else:
            gaps.add("uninspected_body_part")
    chosen = plain if any(item.strip() for item in plain) else html
    body = "\n\n".join(item.strip() for item in chosen if item.strip()).strip()
    if chosen is plain and any(item.strip() for item in html):
        html_body = "\n\n".join(item.strip() for item in html if item.strip())
        if " ".join(body.split()) != " ".join(html_body.split()):
            gaps.add("html_body_differs")
    return body, html_urls, inline_images, html_visible_text_length


def parse_email(raw: bytes, max_bytes: int = MAX_EMAIL_BYTES) -> ParsedEmail:
    """Parse an email without dereferencing or decoding attachment payloads."""
    if len(raw) > max_bytes:
        raise EmailTooLarge(f"email is {len(raw)} bytes; limit is {max_bytes}")
    message = BytesParser(policy=policy.default).parsebytes(raw)
    from_addresses = _addresses(str(message.get("From", "")))
    reply_addresses = _addresses(str(message.get("Reply-To", "")))
    recipients = _addresses(str(message.get("To", ""))) + _addresses(str(message.get("Cc", "")))
    attachments: List[str] = []
    for part in _outer_parts(message):
        filename = part.get_filename()
        if filename:
            attachments.append(str(filename))
    gaps: set[str] = set()
    body, html_urls, inline_images, html_visible_text_length = _extract_body(message, gaps)
    # Decoding can add defects, so inspect after body extraction. Descendants of
    # attachments remain outside this boundary; their contents are not audited.
    for part in _outer_parts(message):
        if part.defects:
            gaps.add("mime_parse_defect")
        for name in ("Content-Type", "Content-Transfer-Encoding", "Content-Disposition"):
            values = part.get_all(name, [])
            if len(values) > 1:
                gaps.add("ambiguous_email_headers")
            if any(getattr(value, "defects", ()) for value in values):
                gaps.add("mime_parse_defect")
    for name in ("Subject", "From", "Reply-To", "To", "Cc", "Message-ID"):
        values = message.get_all(name, [])
        if len(values) > 1:
            gaps.add("ambiguous_email_headers")
        if any(getattr(value, "defects", ()) for value in values):
            gaps.add("mime_parse_defect")
    if not body:
        gaps.add("no_readable_body")
    urls = sorted({
        item.rstrip(".,);]") for item in [*_URL.findall(body), *html_urls]
    })
    return ParsedEmail(
        subject=str(message.get("Subject", "")).strip(),
        from_address=from_addresses[0] if from_addresses else None,
        reply_to=reply_addresses[0] if reply_addresses else None,
        to=recipients,
        message_id=str(message.get("Message-ID", "")).strip() or None,
        body=body,
        urls=urls,
        attachments=attachments,
        authentication_results=[
            str(value) for value in message.get_all("Authentication-Results", [])
        ],
        inline_image_count=inline_images,
        html_visible_text_length=html_visible_text_length,
        inspection_gaps=sorted(gaps),
    )


def _context_evidence(email: ParsedEmail) -> List[Evidence]:
    evidence: List[Evidence] = []
    gap_details = {
        "uninspected_body_part": "An inline body format or embedded message was not inspected.",
        "body_decoding_uncertain": (
            "Body decoding was unsupported or malformed; unreadable parts were omitted."
        ),
        "mime_parse_defect": (
            "The email parser reported a defect; interpretation may differ between clients."
        ),
        "ambiguous_email_headers": (
            "Repeated singleton headers make the message interpretation ambiguous."
        ),
        "no_readable_body": (
            "No readable body was extracted; any content score concerns the subject only."
        ),
        "html_body_differs": (
            "Extracted HTML text differs from the plain text selected for scoring."
        ),
    }
    for code in email.inspection_gaps:
        evidence.append(Evidence(
            code, "medium", "Email inspection is incomplete",
            gap_details[code] + " Review the original in a controlled workflow; "
            "this is not a fraud finding.",
        ))
    from_domain, reply_domain = _domain(email.from_address), _domain(email.reply_to)
    if from_domain and reply_domain and from_domain != reply_domain:
        evidence.append(Evidence(
            "reply_to_domain_mismatch", "medium", "Reply-To domain differs",
            f"From uses {from_domain}; replies go to {reply_domain}.",
        ))
    domains = set()
    malformed_urls = 0
    for url in email.urls:
        try:
            domain = urlsplit(url).hostname
        except ValueError:
            domain = None
        if domain:
            domains.add(domain)
        else:
            malformed_urls += 1
    if malformed_urls:
        evidence.append(Evidence(
            "malformed_url", "medium", "Malformed link requires review",
            f"{malformed_urls} extracted link(s) could not be parsed for domain checks; "
            "inspect them without opening them. No link was fetched.",
        ))
    for domain in sorted(domains):
        normalized = domain.casefold()
        if normalized.startswith("xn--") or ".xn--" in normalized:
            evidence.append(Evidence(
                "punycode_url", "medium", "Punycode link domain",
                f"The message contains an internationalized domain encoding: {domain}.",
            ))
        try:
            ipaddress.ip_address(normalized.strip("[]"))
        except ValueError:
            pass
        else:
            evidence.append(Evidence(
                "ip_literal_url", "medium", "Link uses an IP address",
                f"The message links directly to {domain} instead of a named domain.",
            ))
    auth = " ".join(email.authentication_results).casefold()
    failed = sorted({
        name for name in ("spf", "dkim", "dmarc")
        if re.search(rf"\b{name}=fail\b", auth)
    })
    if failed:
        evidence.append(Evidence(
            "email_authentication_failed", "medium",
            "Header reports email authentication failure",
            f"Authentication-Results reports failure for {', '.join(failed)}; "
            "verify that the header came from a trusted gateway.",
        ))
    visual_language = "\n".join((email.subject, email.body))
    if email.inline_image_count and _QR_LANGUAGE.search(visual_language):
        evidence.append(Evidence(
            "qr_lure_cue", "medium", "QR-code lure cue",
            "The HTML combines an inline image with instructions to scan a code; "
            "image bytes were not decoded.",
        ))
    elif email.inline_image_count and email.html_visible_text_length < 8:
        evidence.append(Evidence(
            "image_dominant_html", "medium", "Image-dominant HTML body",
            "The HTML has an inline image but almost no visible text; image bytes "
            "were not decoded.",
        ))
    for filename in email.attachments:
        suffix = Path(filename.casefold()).suffix
        if suffix in _DANGEROUS_EXTENSIONS:
            evidence.append(Evidence(
                "executable_attachment", "high", "Executable attachment",
                f"Attachment {filename!r} has a high-risk executable extension.",
            ))
        elif suffix in _ARCHIVE_EXTENSIONS:
            evidence.append(Evidence(
                "archive_attachment", "medium", "Archive or disk-image attachment",
                f"Attachment {filename!r} requires controlled inspection.",
            ))
    return evidence


def triage_email(
    raw: bytes,
    detector_name: str = service.DEFAULT_DETECTOR,
    threshold: Optional[float] = None,
    engine: Optional[str] = None,
    model: Optional[str] = None,
) -> EmailTriageResult:
    parsed = parse_email(raw)
    score_text = "\n\n".join(item for item in (parsed.subject, parsed.body) if item).strip()
    if not score_text:
        raise ValueError("email has no subject or readable text body")
    if len(score_text) > MAX_SCORE_TEXT:
        raise ValueError("email text exceeds the scoring limit; manual review is required")
    scored = service.score(
        score_text, detector_name=detector_name,
        threshold=threshold, engine=engine, model=model,
    )
    evidence = _context_evidence(parsed)
    severities = {item.severity for item in evidence}
    if scored.label == "fraud" or "high" in severities:
        risk = "high"
        action = "Quarantine and send for analyst review; do not open links or attachments."
    elif evidence or scored.fraud_probability >= scored.threshold * 0.6:
        risk = "review"
        action = "Hold for review and verify the sender through a trusted channel."
    else:
        risk = "low"
        action = "No strong signal found; continue normal email-security controls."
    return EmailTriageResult(
        schema_version=1,
        risk_tier=risk,
        recommended_action=action,
        detector=scored.detector,
        content_probability=scored.fraud_probability,
        content_label=scored.label,
        threshold=scored.threshold,
        threshold_source=scored.threshold_source,
        policy_id=scored.policy_id,
        subject=parsed.subject,
        from_address=parsed.from_address,
        reply_to=parsed.reply_to,
        recipients=parsed.to,
        message_id=parsed.message_id,
        signals=scored.signals,
        evidence=evidence,
        urls=parsed.urls,
        attachments=parsed.attachments,
    )


def triage_files(paths: Sequence[Path], **kwargs) -> List[EmailTriageResult]:
    """Triage bounded regular files; callers must trust their parent directories.

    This convenience helper is sequential, not an atomic batch: earlier files
    may already have been assessed when a later file is rejected.
    """
    return [
        triage_email(
            read_regular_file(path, maximum=MAX_EMAIL_BYTES, label="email"), **kwargs
        )
        for path in paths
    ]
