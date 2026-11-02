"""Model adapters. The model is a dependency: keep it behind an interface."""
from __future__ import annotations
from pathlib import Path


class Model:
    def complete(self, system: str, user: str) -> str:
        raise NotImplementedError


class FixtureModel(Model):
    """Deterministic. Returns `first` on attempt 0, `repair` on attempt >= 1.

    A fixture is not a model. It exists so the suite runs with no API key and
    so the repair loop can be tested against known inputs.
    """

    def __init__(self, first: str = "{}", repair: str | None = None):
        self.first, self.repair, self.calls = first, repair, 0

    def complete(self, system: str, user: str) -> str:
        out = self.first if self.calls == 0 else (self.repair or self.first)
        self.calls += 1
        return out


class AnthropicModel(Model):
    def __init__(self, model: str, api_key: str | None = None, max_tokens: int = 1400):
        try:
            import anthropic  # noqa: F401
        except ImportError as exc:  # pragma: no cover
            raise SystemExit("pip install anthropic") from exc
        import anthropic
        self.client = anthropic.Anthropic(api_key=api_key)
        self.model, self.max_tokens = model, max_tokens

    def complete(self, system: str, user: str) -> str:
        msg = self.client.messages.create(
            model=self.model, max_tokens=self.max_tokens,
            system=system, messages=[{"role": "user", "content": user}],
        )
        return "".join(b.text for b in msg.content if b.type == "text").strip()


class OpenAIModel(Model):
    def __init__(self, model: str, api_key: str | None = None, max_tokens: int = 1400):
        try:
            from openai import OpenAI
        except ImportError as exc:  # pragma: no cover
            raise SystemExit("pip install openai") from exc
        self.client, self.model, self.max_tokens = OpenAI(api_key=api_key), model, max_tokens

    def complete(self, system: str, user: str) -> str:
        r = self.client.chat.completions.create(
            model=self.model, max_tokens=self.max_tokens,
            messages=[{"role": "system", "content": system},
                      {"role": "user", "content": user}],
        )
        return (r.choices[0].message.content or "").strip()


def load_prompt(path: str | Path = "prompt/critic.v1.0.md") -> str:
    return Path(path).read_text(encoding="utf-8")
