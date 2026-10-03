"""Streamlit review queue: the finding, its evidence and the screenshot behind it.

Run with: make dashboard  (streamlit run src/lookalike_hunter/dashboard/app.py)

Each finding can be confirmed or corrected; the answer is written to the
evaluation dataset as a human label (see eval/feedback.py).

Deliberately thin. The querying lives in `data.py` where it is tested; this file
only arranges what comes back.

Every string shown here came from a hostile page or from a model that read one,
so it is rendered with ``st.text``, which parses neither Markdown nor HTML.
Escaping HTML is not enough on its own: ``st.write`` and ``st.caption`` render
Markdown, so ``[Verify](https://evil)`` would become a live link and
``![](https://tracker/x)`` would have the analyst's browser fetch a URL the
attacker controls, telling them someone is looking. Only the label badge, whose
values come from a fixed set, goes through HTML.
"""

from __future__ import annotations

from pathlib import Path

import streamlit as st

from lookalike_hunter.classify.schema import Label
from lookalike_hunter.config import load_settings
from lookalike_hunter.dashboard.data import (
    Finding,
    defang,
    label_counts,
    load_findings,
    plain,
)
from lookalike_hunter.eval.feedback import (
    HUMAN,
    REVIEWABLE_LABELS,
    ExistingLabel,
    current_labels,
    record_label,
)

_NONE = ExistingLabel(None, None, None)

LABEL_COLOURS = {
    "phishing": "#b3261e",
    "parked": "#6c757d",
    "legitimate": "#1e7d32",
    "unreachable": "#8a6d00",
    "unknown": "#3b4a5a",
}


def render_review(finding: Finding, existing: ExistingLabel | None, dataset_path: Path) -> None:
    """Confirm or correct the model; the answer becomes a human label in the benchmark."""
    if existing is not None and existing.expected:
        by = "you" if existing.labelled_by == HUMAN else plain(existing.labelled_by or "?", 20)
        st.text(f"labelled {plain(existing.expected, 20)} by {by} on {existing.labelled_at}")
    options = [str(label) for label in REVIEWABLE_LABELS]
    # Start from the current label, else the model's answer, so confirming is one click.
    start = existing.expected if existing and existing.expected in options else finding.label
    choice = st.selectbox(
        "What this site really is",
        options,
        index=options.index(start) if start in options else options.index("unknown"),
        key=f"review-{finding.fqdn}",
    )
    if st.button("Save label", key=f"save-{finding.fqdn}"):
        record_label(
            dataset_path,
            finding.fqdn,
            Label(choice),
            brand=finding.brand,
            suggestion=finding.label if finding.label in LABEL_COLOURS else None,
        )
        st.rerun()


def render_finding(
    finding: Finding, captures_dir: Path, existing: ExistingLabel | None, dataset_path: Path
) -> None:
    # The label is matched against the fixed set rather than escaped: a value
    # outside it (a tampered row) is shown as plain text instead of as a badge.
    colour = LABEL_COLOURS.get(finding.label)
    if colour is not None:
        st.markdown(
            f"<span style='background:{colour};color:#fff;padding:2px 8px;"
            f"border-radius:4px'>{finding.label}</span> "
            f"confidence {finding.confidence:.2f} · score {finding.score:.2f}",
            unsafe_allow_html=True,
        )
    else:
        st.text(f"label: {plain(finding.label, 40)}")
    st.text(plain(finding.fqdn, 253))

    left, right = st.columns([2, 3])
    with left:
        if finding.brand:
            st.text(f"impersonates: {plain(finding.brand, 60)}")
        if finding.final_url:
            # Defanged on purpose: a clickable link here defeats the container.
            st.text(f"final URL: {defang(finding.final_url)}")
        st.text(f"model: {plain(finding.model or 'n/a', 60)}")
        st.text(f"classified: {finding.classified_at:%Y-%m-%d %H:%M}")
        st.text("notified" if finding.alerted_at else "not notified")
        if finding.evidence:
            st.text(plain(finding.evidence, 1000))
        render_review(finding, existing, dataset_path)
    with right:
        shot = finding.screenshot_file(captures_dir)
        if shot is not None:
            st.image(str(shot), width="stretch")
        else:
            st.info("No screenshot: the capture failed or the file is gone.")
    st.divider()


def main() -> None:
    st.set_page_config(page_title="Lookalike Hunter", layout="wide")
    settings = load_settings()

    st.title("Lookalike Hunter")
    st.caption(
        "Brand-impersonating domains from Certificate Transparency, triaged by a "
        "vision-language model. Links are defanged; screenshots were taken in an "
        "isolated container."
    )

    # Only labels from the fixed set: these strings reach widgets that render Markdown.
    counts = {
        label: count
        for label, count in label_counts(settings.db_path).items()
        if label in LABEL_COLOURS
    }
    if counts:
        for column, (label, count) in zip(st.columns(len(counts)), counts.items(), strict=True):
            column.metric(label, count)

    with st.sidebar:
        st.header("Filter")
        chosen = st.multiselect("Labels", list(LABEL_COLOURS), default=["phishing"])
        min_confidence = st.slider("Minimum confidence", 0.0, 1.0, 0.0, 0.05)
        limit = st.number_input("Maximum findings", 10, 500, 100, step=10)
        unreviewed = st.checkbox("Only findings I have not labelled", value=False)

    labels = current_labels(settings.dataset_path)
    findings = load_findings(
        settings.db_path,
        labels=tuple(chosen),
        min_confidence=min_confidence,
        limit=int(limit),
    )
    if unreviewed:
        findings = [f for f in findings if labels.get(f.fqdn, _NONE).labelled_by != HUMAN]
    reviewed = sum(1 for label in labels.values() if label.labelled_by == HUMAN)
    st.write(f"{len(findings)} finding(s) · {reviewed} site(s) labelled by you so far")
    for finding in findings:
        render_finding(
            finding,
            settings.capture.output_dir,
            labels.get(finding.fqdn),
            settings.dataset_path,
        )


if __name__ == "__main__":
    main()
