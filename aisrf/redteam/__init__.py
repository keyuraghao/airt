"""AISRF red-team engine: attack corpus, mutators, evaluators, campaign runner and API.

The engine drives probes from the YAML corpus through the same interception pipeline as any
other request (aisrf.gateway.pipeline.submit), scores each response with the evaluators and
aggregates the results into a campaign summary.
"""

from .corpus import Probe, get_probe, get_probes, list_categories, load_corpus

__all__ = ["Probe", "get_probe", "get_probes", "list_categories", "load_corpus"]
