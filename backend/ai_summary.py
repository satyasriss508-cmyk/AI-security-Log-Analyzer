"""Optional AI summary using the Anthropic API. Falls back to rule-based text."""
import json, os
from analyzer import rule_based_summary


def summarize(result: dict) -> dict:
    key = os.getenv("ANTHROPIC_API_KEY")
    if not key or not result["incidents"]:
        return {"text": rule_based_summary(result), "source": "rule-based"}
    try:
        import anthropic
        client = anthropic.Anthropic(api_key=key.strip())
        payload = json.dumps({"stats": result["stats"], "incidents": result["incidents"][:15]})
        msg = client.messages.create(
            model=os.getenv("ANTHROPIC_MODEL", "claude-sonnet-5-5"), max_tokens=700,
            system="You are a SOC analyst. Given detected security incidents from logs, write a concise incident "
                   "summary (max 150 words) followed by 3-5 prioritized recommended actions. Plain text, no markdown.",
            messages=[{"role": "user", "content": payload}])
        return {"text": msg.content[0].text, "source": "claude"}
    except Exception as e:  # never break analysis because of the AI call
        detail = getattr(e, "message", None) or str(e)
        return {"text": rule_based_summary(result) + f" (AI summary unavailable: {type(e).__name__}: {detail[:200]})",
                "source": "rule-based"}
