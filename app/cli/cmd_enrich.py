"""Enrichment command."""
import logging

from app.enrichment.runner import default_providers
from app.pipeline import run_enrichment_cycle

log = logging.getLogger(__name__)


def register(sub):
    pe = sub.add_parser("enrich", help="Run enrichment providers over stored entities.")
    pe.add_argument("--type", help="Restrict to one entity type (cve, domain, ip, url, md5, sha1, sha256).")
    pe.add_argument("--value", help="Enrich a single entity value (requires --type).")
    pe.add_argument("--limit", type=int, help="Cap the number of entities processed.")
    pe.add_argument("--force", action="store_true", help="Bypass cache freshness check.")
    pe.set_defaults(func=cmd_enrich)


def cmd_enrich(args):
    providers = default_providers()
    configured = [p for p in providers if p.is_configured()]
    skipped = [p.name for p in providers if not p.is_configured()]
    if skipped:
        log.info("Skipping unconfigured providers: %s", ", ".join(skipped))
    if not configured:
        print("No enrichment providers are configured.")
        return

    totals = run_enrichment_cycle(
        entity_type=args.type, entity_value=args.value, limit=args.limit, force=args.force
    )
    if totals["targets"] == 0:
        print("No entities to enrich.")
        return
    print(
        "Enrichment done. "
        f"targets={totals['targets']} hits={totals['hits']} cached={totals['cached']} "
        f"errors={totals['errors']} skipped={totals['skipped']}"
    )
